"""Typed, user-facing Atlas Gardener failures."""


class GardenerError(Exception):
    """Base class for an expected fail-closed refusal."""


class ContractError(GardenerError):
    """Raised when a Finding or proposal violates a v1 contract."""


class SafetyRefusal(GardenerError):
    """Raised when a requested proposal or apply violates safety policy."""
