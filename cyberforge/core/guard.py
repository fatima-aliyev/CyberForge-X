"""Authorization gate and non-destructive request policy."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from cyberforge.core.exceptions import AuthorizationError, PolicyViolation
from cyberforge.core.logging import get_logger
from cyberforge.core.scope import Scope
from cyberforge.core.utils import utc_now_iso

DISCLAIMER = """\
CYBERFORGE-X AUTHORIZED-USE NOTICE
==================================
CyberForge-X performs active security testing: port/service discovery, web
parameter probing, API authorization checks, JWT analysis, and (only when
explicitly enabled) bounded credential testing.

You MUST have explicit, written authorization from the system owner before
running this tool. You are responsible for complying with all applicable laws,
contracts, and rules of engagement.

By continuing you confirm that:
  1. You are authorized to test every target in the supplied scope file.
  2. The scope file accurately reflects the signed engagement.
  3. You accept responsibility for all activity performed by this tool.
  4. You will not use this tool for denial-of-service, data destruction,
     data exfiltration, persistence, or any other destructive activity.

CyberForge-X deliberately blocks DELETE requests, disables destructive tests,
caps request volume, and enforces the scope on every outbound request.
"""


@dataclass
class RequestPolicy:
    allow_post: bool = True
    allow_put: bool = False
    allow_patch: bool = False
    allow_delete: bool = False
    allow_trace: bool = False

    def allowed_methods(self) -> set[str]:
        methods = {"GET", "HEAD", "OPTIONS"}
        if self.allow_post:
            methods.add("POST")
        if self.allow_put:
            methods.add("PUT")
        if self.allow_patch:
            methods.add("PATCH")
        if self.allow_delete:
            methods.add("DELETE")
        if self.allow_trace:
            methods.add("TRACE")
        return methods

    def check(self, method: str) -> None:
        upper = method.upper()
        if upper not in self.allowed_methods():
            if upper == "DELETE":
                raise PolicyViolation("DELETE requests are permanently blocked by policy")
            raise PolicyViolation(
                f"HTTP method {upper} is blocked; enable only the specific test flag required"
            )

    def describe(self) -> dict[str, Any]:
        return {
            "allowed_methods": sorted(self.allowed_methods()),
            "delete_blocked": "DELETE" not in self.allowed_methods(),
        }


class AuthorizationGate:
    """Two-key authorization: explicit flag + exact engagement name + disclaimer."""

    @staticmethod
    def enforce(
        scope: Scope,
        engagement_confirmation: str,
        have_authorization: bool,
        accept_disclaimer: bool,
        interactive: bool | None = None,
        console: Console | None = None,
    ) -> dict[str, Any]:
        console = console or Console(highlight=False)
        logger = get_logger("authorization")
        if interactive is None:
            interactive = sys.stdin.isatty()

        if engagement_confirmation.strip() != scope.config.engagement.strip():
            raise AuthorizationError(
                "authorization confirmation does not match scope.engagement; "
                "pass --authorization with the exact engagement name"
            )
        if not have_authorization:
            raise AuthorizationError(
                "explicit authorization flag missing; pass --i-have-authorization only when "
                "written authorization is on file"
            )

        console.print(DISCLAIMER, style="yellow")
        if not accept_disclaimer:
            if not interactive:
                raise AuthorizationError(
                    "non-interactive run requires --accept-disclaimer after reviewing the notice"
                )
            answer = console.input("[bold]Type [cyan]I AGREE[/cyan] to continue:[/bold] ").strip()
            if answer != "I AGREE":
                raise AuthorizationError("disclaimer was not accepted")

        if not scope.config.authorization_ref:
            logger.warning(
                "scope has no authorization_ref; production engagements should record a "
                "signed SOW/ticket reference"
            )

        audit = scope.audit_metadata()
        audit.update(
            {
                "gate": "passed",
                "gate_timestamp": utc_now_iso(),
                "disclaimer_accepted": True,
                "authorization_flag": True,
            }
        )
        logger.info(
            "Authorization gate passed for engagement %r (authorized by %s)",
            scope.config.engagement,
            scope.config.authorized_by,
        )
        return audit
