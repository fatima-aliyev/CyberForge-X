"""Custom exception hierarchy for CyberForge-X.

All recoverable module failures use a subclass of :class:`CyberForgeError` so the
orchestrator can isolate a failing module without aborting the whole assessment.
"""

from __future__ import annotations


class CyberForgeError(Exception):
    """Base class for all CyberForge-X errors."""


class ConfigurationError(CyberForgeError):
    """Raised when configuration or scope data is invalid."""


class AuthorizationError(CyberForgeError):
    """Raised when the authorization/disclaimer gate is not satisfied."""


class ScopeViolation(CyberForgeError):
    """Raised when a target falls outside the signed engagement scope."""

    def __init__(self, target: str, reason: str = "target is outside the authorized scope") -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation for {target!r}: {reason}")


class PolicyViolation(CyberForgeError):
    """Raised when an operation violates the non-destructive safety policy."""


class RequestBudgetExceeded(CyberForgeError):
    """Raised when the global request budget is exhausted."""


class RateLimitError(CyberForgeError):
    """Raised for invalid rate-limit configuration."""


class ModuleError(CyberForgeError):
    """A non-fatal failure inside an assessment module."""

    def __init__(self, module: str, message: str) -> None:
        self.module = module
        self.message = message
        super().__init__(f"[{module}] {message}")


class TargetUnreachable(ModuleError):
    """The target could not be reached during a module run."""


class OptionalDependencyError(ModuleError):
    """A requested integration requires an optional dependency."""


class LockoutDetected(CyberForgeError):
    """A credential test aborted because account-lockout signals were observed."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Credential test aborted for {target}: {reason}")


class SpecParseError(ModuleError):
    """An API specification could not be parsed safely."""


class OOBError(CyberForgeError):
    """Out-of-band listener failure."""
