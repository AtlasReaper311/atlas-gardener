from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.github_app_auth import (
    EXPECTED_PERMISSIONS,
    InstallationToken,
    RestAppTransport,
    build_app_jwt,
    mint_repository_token,
)


class FakeTransport:
    def __init__(self, token: str = "ghs_" + "x" * 40) -> None:
        self.token = token
        self.calls: list[tuple[str, str, str, dict | None]] = []
        self.revoked = False
        self.permissions = dict(EXPECTED_PERMISSIONS)
        self.repositories = [{"full_name": "AtlasReaper311/atlas-dora"}]

    def request(self, method, path, *, bearer, payload=None):
        self.calls.append((method, path, bearer, payload))
        if method == "GET" and path.endswith("/installation"):
            return {"id": 123}
        if method == "POST" and path.endswith("/access_tokens"):
            return {
                "token": self.token,
                "permissions": self.permissions,
                "repositories": self.repositories,
            }
        if method == "DELETE" and path == "/installation/token":
            self.revoked = True
            return {}
        return {}


class GitHubAppAuthTests(unittest.TestCase):
    def test_endpoint_allowlist_is_exact(self) -> None:
        self.assertTrue(
            RestAppTransport._allowed(
                "GET", "/repos/AtlasReaper311/atlas-dora/installation"
            )
        )
        self.assertTrue(
            RestAppTransport._allowed(
                "POST", "/app/installations/123/access_tokens"
            )
        )
        self.assertTrue(RestAppTransport._allowed("DELETE", "/installation/token"))
        for method, path in (
            ("GET", "/repos/Other/example/installation"),
            ("POST", "/repos/AtlasReaper311/atlas-dora/pulls"),
            ("PUT", "/repos/AtlasReaper311/atlas-dora/actions/permissions"),
            ("DELETE", "/repos/AtlasReaper311/atlas-dora/git/refs/heads/main"),
        ):
            self.assertFalse(RestAppTransport._allowed(method, path))

    def test_mints_classic_and_stateless_tokens_without_parsing_format(self) -> None:
        for value in (
            "ghs_" + "a" * 40,
            "ghs_" + "b" * 20 + "." + "c" * 30 + "." + "d" * 30,
        ):
            transport = FakeTransport(value)
            with mock.patch(
                "atlas_gardener.github_app_auth.build_app_jwt",
                return_value="app-jwt-that-is-long-enough",
            ):
                token = mint_repository_token(
                    app_id="123",
                    private_key_path=Path("unused.pem"),
                    repository="AtlasReaper311/atlas-dora",
                    transport=transport,
                )
            self.assertEqual(value, token.value)
            self.assertNotIn(value, repr(token))
            mint_call = next(call for call in transport.calls if call[0] == "POST")
            self.assertEqual(
                {
                    "repositories": ["atlas-dora"],
                    "permissions": EXPECTED_PERMISSIONS,
                },
                mint_call[3],
            )
            token.revoke()
            self.assertTrue(transport.revoked)
            self.assertTrue(token.revoked)
            with self.assertRaisesRegex(SafetyRefusal, "already been revoked"):
                _ = token.value

    def test_permission_expansion_and_wrong_repository_fail_closed(self) -> None:
        transport = FakeTransport()
        transport.permissions["actions"] = "read"
        with mock.patch(
            "atlas_gardener.github_app_auth.build_app_jwt",
            return_value="app-jwt-that-is-long-enough",
        ):
            with self.assertRaisesRegex(SafetyRefusal, "permission boundary"):
                mint_repository_token(
                    app_id="123",
                    private_key_path=Path("unused.pem"),
                    repository="AtlasReaper311/atlas-dora",
                    transport=transport,
                )

        transport = FakeTransport()
        transport.repositories = [{"full_name": "AtlasReaper311/status"}]
        with mock.patch(
            "atlas_gardener.github_app_auth.build_app_jwt",
            return_value="app-jwt-that-is-long-enough",
        ):
            with self.assertRaisesRegex(SafetyRefusal, "wrong repository"):
                mint_repository_token(
                    app_id="123",
                    private_key_path=Path("unused.pem"),
                    repository="AtlasReaper311/atlas-dora",
                    transport=transport,
                )

    def test_missing_and_malformed_key_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.pem"
            with self.assertRaises((FileNotFoundError, SafetyRefusal)):
                build_app_jwt("123", missing, now=1000)
            malformed = root / "malformed.pem"
            malformed.write_text("not a key\n", encoding="utf-8")
            with self.assertRaisesRegex(SafetyRefusal, "could not sign"):
                build_app_jwt("123", malformed, now=1000)

    def test_token_context_revokes_after_failure(self) -> None:
        transport = FakeTransport()
        token = InstallationToken(transport.token, "AtlasReaper311/atlas-dora", transport)
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with token:
                raise RuntimeError("boom")
        self.assertTrue(transport.revoked)
        self.assertTrue(token.revoked)


if __name__ == "__main__":
    unittest.main()
