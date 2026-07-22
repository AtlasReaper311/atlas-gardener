"""Short-lived, repository-restricted GitHub App authentication for the controller."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from atlas_gardener.errors import GardenerError, SafetyRefusal

API_VERSION = "2022-11-28"
MAX_RESPONSE_BYTES = 1_048_576
EXPECTED_PERMISSIONS = {
    "metadata": "read",
    "contents": "write",
    "pull_requests": "write",
}


class AppTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        bearer: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...


class RestAppTransport:
    """Minimal GitHub App transport restricted to installation lookup, mint and revoke."""

    def __init__(self, api_base: str = "https://api.github.com") -> None:
        self.api_base = api_base.rstrip("/")

    @staticmethod
    def _allowed(method: str, path: str) -> bool:
        if method == "GET" and path.startswith("/repos/AtlasReaper311/") and path.endswith("/installation"):
            name = path.removeprefix("/repos/AtlasReaper311/").removesuffix("/installation")
            return bool(name) and all(character.isalnum() or character in "._-" for character in name)
        if method == "POST" and path.startswith("/app/installations/") and path.endswith("/access_tokens"):
            value = path.removeprefix("/app/installations/").removesuffix("/access_tokens")
            return value.isdigit()
        if method == "DELETE" and path == "/installation/token":
            return True
        return False

    def request(
        self,
        method: str,
        path: str,
        *,
        bearer: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        method = method.upper()
        if not self._allowed(method, path):
            raise GardenerError(f"GitHub App token broker refused endpoint: {method} {path}")
        if not bearer or any(character.isspace() for character in bearer):
            raise SafetyRefusal("GitHub App bearer credential is unavailable")
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {bearer}",
            "User-Agent": "AtlasReaper311/atlas-gardener",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.api_base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raise GardenerError(f"GitHub App token broker returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise GardenerError("GitHub App token broker was unavailable") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise GardenerError("GitHub App token broker response exceeded the bound")
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise GardenerError("GitHub App token broker returned invalid JSON") from error
        if not isinstance(value, dict):
            raise GardenerError("GitHub App token broker returned a non-object")
        return value


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_app_jwt(app_id: str, private_key_path: Path, *, now: int | None = None) -> str:
    if not app_id.isdigit():
        raise SafetyRefusal("GitHub App ID must contain digits only")
    private_key_path = private_key_path.resolve(strict=True)
    if not private_key_path.is_file():
        raise SafetyRefusal("GitHub App private key is unavailable")
    issued = int(now if now is not None else time.time())
    header = _base64url(b'{"alg":"RS256","typ":"JWT"}')
    payload = _base64url(
        json.dumps(
            {"iat": issued - 60, "exp": issued + 540, "iss": app_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    unsigned = f"{header}.{payload}".encode("ascii")
    with tempfile.TemporaryDirectory(prefix="atlas-gardener-jwt-") as directory:
        root = Path(directory)
        unsigned_path = root / "unsigned"
        signature_path = root / "signature"
        unsigned_path.write_bytes(unsigned)
        completed = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key_path),
                "-out",
                str(signature_path),
                str(unsigned_path),
            ],
            check=False,
            capture_output=True,
            timeout=20,
        )
        if completed.returncode != 0:
            raise SafetyRefusal("GitHub App private key could not sign a JWT")
        signature = _base64url(signature_path.read_bytes())
    return f"{header}.{payload}.{signature}"


class InstallationToken:
    """One token with explicit revocation and no printable credential representation."""

    def __init__(self, token: str, repository: str, transport: AppTransport) -> None:
        if len(token) < 20 or any(character.isspace() for character in token):
            raise SafetyRefusal("GitHub returned an invalid installation token")
        self._token = token
        self.repository = repository
        self.transport = transport
        self.revoked = False

    @property
    def value(self) -> str:
        if self.revoked:
            raise SafetyRefusal("installation token has already been revoked")
        return self._token

    def revoke(self) -> None:
        if self.revoked:
            return
        self.transport.request("DELETE", "/installation/token", bearer=self._token)
        self._token = ""
        self.revoked = True

    def __enter__(self) -> "InstallationToken":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.revoke()

    def __repr__(self) -> str:
        return f"InstallationToken(repository={self.repository!r}, revoked={self.revoked!r})"


def mint_repository_token(
    *,
    app_id: str,
    private_key_path: Path,
    repository: str,
    transport: AppTransport | None = None,
    now: int | None = None,
) -> InstallationToken:
    owner, separator, name = repository.partition("/")
    if separator != "/" or owner != "AtlasReaper311" or not name or not all(
        character.isalnum() or character in "._-" for character in name
    ):
        raise SafetyRefusal("installation token target is not an Atlas repository")
    client = transport or RestAppTransport()
    jwt = build_app_jwt(app_id, private_key_path, now=now)
    installation = client.request(
        "GET",
        f"/repos/{repository}/installation",
        bearer=jwt,
    )
    installation_id = installation.get("id")
    if not isinstance(installation_id, int) or installation_id <= 0:
        raise SafetyRefusal("GitHub App installation is unavailable for the target repository")
    response = client.request(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        bearer=jwt,
        payload={
            "repositories": [name],
            "permissions": EXPECTED_PERMISSIONS,
        },
    )
    if response.get("permissions") != EXPECTED_PERMISSIONS:
        raise SafetyRefusal("minted installation token permission boundary changed")
    repositories = response.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise SafetyRefusal("minted installation token is not repository-restricted")
    if repositories[0].get("full_name") != repository:
        raise SafetyRefusal("minted installation token targets the wrong repository")
    token = response.get("token")
    if not isinstance(token, str):
        raise SafetyRefusal("GitHub did not return an installation token")
    return InstallationToken(token, repository, client)


def private_key_from_environment(directory: Path) -> Path:
    value = os.environ.get("ATLAS_GARDENER_APP_PRIVATE_KEY", "")
    if not value.strip():
        raise SafetyRefusal("ATLAS_GARDENER_APP_PRIVATE_KEY is not set")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "github-app-private-key.pem"
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return path
