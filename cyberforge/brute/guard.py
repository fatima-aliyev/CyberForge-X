"""Credential-testing limits, lockout detection, and authorization checks."""

from __future__ import annotations

import dataclasses
import time

from cyberforge.core.context import ModuleContext

LOCKOUT_WORDS = (
    "too many attempts",
    "too many failed",
    "temporarily locked",
    "account locked",
    "account is locked",
    "account disabled",
    "try again later",
    "rate limit exceeded",
    "slow down",
)
LOCKOUT_STATUSES = {423, 429}


@dataclasses.dataclass
class AttemptBudget:
    max_attempts: int
    used: int = 0

    def consume(self) -> bool:
        if self.used >= self.max_attempts:
            return False
        self.used += 1
        return True

    @property
    def remaining(self) -> int:
        return max(0, self.max_attempts - self.used)


class CredentialGuard:
    def __init__(self, ctx: ModuleContext, budget: AttemptBudget) -> None:
        self.ctx = ctx
        self.budget = budget
        self.delay = max(0.2, float(ctx.config.brute_delay))

    def authorized(self) -> tuple[bool, str]:
        if not self.ctx.config.allow_credential_attacks:
            return False, "credential testing requires --allow-credential-attacks"
        if not self.ctx.scope.config.allow_credential_attacks:
            return False, "scope does not set allow_credential_attacks: true"
        if not self.ctx.config.have_authorization:
            return False, "authorization flag was not recorded"
        return True, ""

    def sleep(self) -> None:
        if self.delay > 0:
            time.sleep(self.delay)

    def is_lockout(self, status: int | None, text: str = "", message: str = "") -> bool:
        if status in LOCKOUT_STATUSES:
            return True
        haystack = f"{text}\n{message}".lower()
        return any(word in haystack for word in LOCKOUT_WORDS)
