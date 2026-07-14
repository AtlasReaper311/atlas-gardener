"""Strict, dependency-free validation for the Phase 1 JSON contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from atlas_gardener.errors import ContractError
from atlas_gardener.models import LoadedFinding

FINDING_SCHEMA = "finding.schema.json"
PROPOSAL_SCHEMA = "remediation-proposal.schema.json"
FINGERPRINT_RULES = "fingerprint-rules.json"


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation required by Phase 1."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_value(value: Any, *, prefix: str = "sha256:") -> str:
    """Hash a canonical JSON value with the requested contract prefix."""

    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}{digest}"


def read_json(path: Path) -> Any:
    """Read one UTF-8 JSON file with a bounded, useful error."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(
            f"cannot read valid UTF-8 JSON from {path}: {error}"
        ) from error


def write_json(path: Path, value: Any) -> None:
    """Write deterministic UTF-8 JSON with a final newline."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def resolve_contracts_root(
    explicit: Path | None = None,
    *,
    estate_root: Path | None = None,
    repository: Path | None = None,
) -> Path:
    """Resolve the checked-out Phase 1 v1 contract directory without network use."""

    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    configured = os.environ.get("ATLAS_GARDENER_CONTRACTS")
    if configured:
        candidates.append(Path(configured))
    if estate_root is not None:
        candidates.append(estate_root / "atlas-infra" / "contracts" / "v1")
    if repository is not None:
        candidates.append(repository.parent / "atlas-infra" / "contracts" / "v1")
    candidates.append(Path.cwd().parent / "atlas-infra" / "contracts" / "v1")
    candidates.append(
        Path(__file__).resolve().parents[3] / "atlas-infra" / "contracts" / "v1"
    )

    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if all((resolved / name).is_file() for name in _required_contract_files()):
            return resolved
    searched = ", ".join(str(path.expanduser()) for path in candidates)
    raise ContractError(f"Phase 1 contracts/v1 not found; searched: {searched}")


def _required_contract_files() -> tuple[str, ...]:
    return FINDING_SCHEMA, PROPOSAL_SCHEMA, FINGERPRINT_RULES


class SchemaValidator:
    """Validate the closed subset used by Finding and RemediationProposal v1."""

    def validate(self, instance: Any, schema: dict[str, Any]) -> None:
        errors: list[str] = []
        self._validate(instance, schema, "$", errors)
        if errors:
            raise ContractError("schema validation failed: " + "; ".join(errors))

    def _validate(
        self,
        instance: Any,
        schema: dict[str, Any],
        path: str,
        errors: list[str],
    ) -> None:
        expected_type = schema.get("type")
        if expected_type is not None and not _matches_type(instance, expected_type):
            errors.append(f"{path} must be {expected_type}")
            return

        if "const" in schema and instance != schema["const"]:
            errors.append(f"{path} must equal {schema['const']!r}")
        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{path} is not an allowed value")

        if isinstance(instance, dict):
            required = schema.get("required", [])
            for name in required:
                if name not in instance:
                    errors.append(f"{path}.{name} is required")
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                for name in instance:
                    if name not in properties:
                        errors.append(f"{path}.{name} is not declared")
            for name, value in instance.items():
                child_schema = properties.get(name)
                if isinstance(child_schema, dict):
                    self._validate(value, child_schema, f"{path}.{name}", errors)

        if isinstance(instance, list):
            if len(instance) < schema.get("minItems", 0):
                errors.append(f"{path} has too few items")
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                errors.append(f"{path} has too many items")
            if schema.get("uniqueItems"):
                canonical = [canonical_json(item) for item in instance]
                if len(canonical) != len(set(canonical)):
                    errors.append(f"{path} items must be unique")
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                for index, value in enumerate(instance):
                    self._validate(value, item_schema, f"{path}[{index}]", errors)

        if isinstance(instance, str):
            if len(instance) < schema.get("minLength", 0):
                errors.append(f"{path} is too short")
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                errors.append(f"{path} is too long")
            pattern = schema.get("pattern")
            if pattern is not None and re.search(pattern, instance) is None:
                errors.append(f"{path} does not match its required pattern")
            if schema.get("format") == "date-time" and not _is_datetime(instance):
                errors.append(f"{path} must be an RFC 3339 timestamp with timezone")
            if schema.get("format") == "uri" and not _is_absolute_uri(instance):
                errors.append(f"{path} must be an absolute URI")


def _matches_type(value: Any, expected: str) -> bool:
    mapping = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
        "integer": int,
        "number": (int, float),
        "null": type(None),
    }
    target = mapping.get(expected)
    if target is None:
        return False
    if expected in {"integer", "number"} and isinstance(value, bool):
        return False
    return isinstance(value, target)


def _is_datetime(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _is_absolute_uri(value: str) -> bool:
    parsed = urlsplit(value)
    return bool(parsed.scheme and parsed.netloc)


def _select_path(value: dict[str, Any], dotted_path: str) -> Any:
    current: Any = value
    for component in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(component)
    return current


def selected_fields_digest(
    value: dict[str, Any],
    rule: dict[str, Any],
) -> str:
    """Apply the canonical Phase 1 selected-fields fingerprint rule."""

    selected: dict[str, Any] = {}
    sort_arrays = set(rule.get("sort_arrays", []))
    for field in rule["fields"]:
        field_value = _select_path(value, field)
        if field in sort_arrays and isinstance(field_value, list):
            field_value = sorted(field_value, key=canonical_json)
        selected[field] = field_value
    return sha256_value(selected, prefix=rule["prefix"])


class ContractSet:
    """Loaded Phase 1 schemas and canonical fingerprint rules."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.finding_schema = _require_object(
            read_json(self.root / FINDING_SCHEMA), FINDING_SCHEMA
        )
        self.proposal_schema = _require_object(
            read_json(self.root / PROPOSAL_SCHEMA), PROPOSAL_SCHEMA
        )
        rules = _require_object(
            read_json(self.root / FINGERPRINT_RULES), FINGERPRINT_RULES
        )
        self.fingerprint_rules = rules
        self.rules = _require_object(rules.get("rules"), f"{FINGERPRINT_RULES}.rules")
        self.validator = SchemaValidator()

    def validate_finding(self, finding: Any) -> dict[str, Any]:
        if not isinstance(finding, dict):
            raise ContractError("Finding JSON root must be an object")
        self.validator.validate(finding, self.finding_schema)
        expected = selected_fields_digest(finding, self.rules["finding"])
        if finding["fingerprint"] != expected:
            raise ContractError(
                "Finding fingerprint does not match the Phase 1 canonical selected fields"
            )
        return finding

    def validate_proposal(self, proposal: Any) -> dict[str, Any]:
        if not isinstance(proposal, dict):
            raise ContractError("RemediationProposal JSON root must be an object")
        self.validator.validate(proposal, self.proposal_schema)
        expected = selected_fields_digest(proposal, self.rules["remediation-proposal"])
        if proposal["proposal_id"] != expected:
            raise ContractError(
                "proposal_id does not match the Phase 1 canonical selected fields"
            )
        return proposal

    def proposal_id(self, proposal: dict[str, Any]) -> str:
        return selected_fields_digest(proposal, self.rules["remediation-proposal"])


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must contain a JSON object")
    return value


def load_findings(path: Path, contracts: ContractSet) -> list[LoadedFinding]:
    """Load, validate, fingerprint-deduplicate, and deterministically order Findings."""

    if path.is_file():
        paths = [path]
    elif path.is_dir():
        paths = sorted(
            candidate for candidate in path.rglob("*.json") if candidate.is_file()
        )
    else:
        raise ContractError(f"Finding path does not exist: {path}")
    if not paths:
        raise ContractError(f"Finding directory contains no JSON files: {path}")

    validated: list[LoadedFinding] = []
    for candidate in paths:
        validated.append(
            LoadedFinding(candidate, contracts.validate_finding(read_json(candidate)))
        )

    by_fingerprint: dict[str, LoadedFinding] = {}
    for loaded in sorted(
        validated,
        key=lambda item: (
            item.value["fingerprint"],
            canonical_json(item.value),
            str(item.path),
        ),
    ):
        by_fingerprint.setdefault(loaded.value["fingerprint"], loaded)
    return [by_fingerprint[key] for key in sorted(by_fingerprint)]
