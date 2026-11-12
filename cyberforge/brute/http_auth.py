"""HTTP Basic and Digest credential checks."""

from __future__ import annotations

import shlex
from urllib.parse import urlsplit

from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from cyberforge.brute.base import CredentialHit, credential_hit
from cyberforge.brute.guard import AttemptBudget, CredentialGuard
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.session import HttpResult

LOGIN_HINTS = ("login", "signin", "sign-in", "logon")


class HTTPAuthTester:
    def __init__(self, ctx: ModuleContext, guard: CredentialGuard, budget: AttemptBudget, digest: bool = False) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.session = ctx.session
        self.guard = guard
        self.budget = budget
        self.digest = digest

    def test(self, target: str, users: list[str], passwords: list[str]) -> list[CredentialHit]:
        url = target if "://" in target else f"http://{target}"
        if urlsplit(url).scheme not in {"http", "https"}:
            return []
        protocol = "HTTP Digest" if self.digest else "HTTP Basic"
        for username in users:
            for password in passwords:
                if not self.budget.consume():
                    self.log.info("Credential attempt budget exhausted")
                    return []
                auth = (
                    HTTPDigestAuth(username, password)
                    if self.digest
                    else HTTPBasicAuth(username, password)
                )
                try:
                    result = self.session.get(url, auth=auth, headers={"Accept": "*/*"})
                except RequestBudgetExceeded:
                    self.log.warning("request budget exhausted during HTTP authentication testing")
                    return []
                except (ScopeViolation, PolicyViolation):
                    return []
                finally:
                    self.guard.sleep()
                if result.status is None:
                    continue
                if self.guard.is_lockout(result.status, result.text):
                    self.log.warning("Possible lockout/rate limit at %s; stopping this target", target)
                    return []
                if _success(result, self.digest):
                    self.log.warning("Valid HTTP credentials found for %s (username %s)", target, username)
                    return [
                        credential_hit(
                            protocol=protocol,
                            target=url,
                            username=username,
                            password=password,
                            request=self._reproduction(url, username),
                            notes=(
                                f"HTTP {result.status}; final URL {result.url}; "
                                f"{'Digest' if self.digest else 'Basic'} challenge accepted."
                            ),
                        )
                    ]
        return []

    @staticmethod
    def _reproduction(url: str, username: str) -> str:
        return f"curl -i -sS -u {shlex.quote(username)}:'<password>' {shlex.quote(url)}"


def _success(result: HttpResult, digest: bool) -> bool:
    if result.status not in {200, 201, 202, 203, 204, 206}:
        return False
    text = (result.text or "").lower()
    path = urlsplit(result.url).path.lower()
    if any(hint in path for hint in LOGIN_HINTS) and "<input" in text and "password" in text:
        return False
    if "invalid credentials" in text or "authentication failed" in text:
        return False
    return not (digest and result.header("WWW-Authenticate").lower().startswith("digest"))
