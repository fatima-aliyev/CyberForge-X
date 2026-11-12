"""SMB password authentication checks (optional impacket dependency)."""

from __future__ import annotations

import contextlib

from cyberforge.brute.base import CredentialHit, credential_hit
from cyberforge.brute.guard import AttemptBudget, CredentialGuard
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import ScopeViolation
from cyberforge.core.utils import split_host_port


class SMBTester:
    def __init__(self, ctx: ModuleContext, guard: CredentialGuard, budget: AttemptBudget) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.guard = guard
        self.budget = budget

    def test(self, target: str, users: list[str], passwords: list[str]) -> list[CredentialHit]:
        try:
            from impacket.smbconnection import SessionError, SMBConnection
        except ImportError:
            self.ctx.bundle.add_error(
                "brute",
                "impacket is required for SMB credential testing (install requirements-optional.txt)",
            )
            self.log.warning("impacket is not installed; SMB credential testing skipped")
            return []
        host, port = split_host_port(target, 445)
        port = port or 445
        try:
            self.ctx.scope.assert_host(host, port)
        except ScopeViolation as exc:
            self.log.warning("SMB target outside scope: %s", exc)
            return []
        ips = self.ctx.scope.resolved_ips(host)
        if not ips:
            self.log.warning("SMB target did not resolve: %s", host)
            return []
        ip = ips[0]
        domain = self.ctx.config.smb_domain or ""
        connection_failures = 0
        for username in users:
            for password in passwords:
                if not self.budget.consume():
                    self.log.info("Credential attempt budget exhausted")
                    return []
                connection = None
                try:
                    connection = SMBConnection(
                        remoteName=host,
                        remoteHost=ip,
                        sess_port=port,
                        timeout=max(4.0, self.ctx.config.timeout),
                    )
                    connection.login(username, password, domain)
                    self.log.warning("Valid SMB credentials found for %s (username %s)", host, username)
                    return [
                        credential_hit(
                            protocol="SMB",
                            target=f"{host}:{port}",
                            username=username,
                            password=password,
                            request=f"smbclient -L //{host} -U {domain + '/' if domain else ''}{username}",
                            notes=f"SMB login succeeded; domain={domain or '(none)'}",
                            cvss=9.3,
                        )
                    ]
                except SessionError as exc:
                    message = str(exc)
                    lowered = message.lower()
                    if any(token in lowered for token in ("locked", "disabled", "too many", "logon restricted")):
                        self.log.warning("SMB account/lockout indicator at %s; stopping", host)
                        return []
                    connection_failures = 0
                except Exception as exc:
                    message = str(exc)
                    if self.guard.is_lockout(None, message):
                        self.log.warning("SMB rate/lockout indicator at %s; stopping", host)
                        return []
                    connection_failures += 1
                    self.log.debug("SMB attempt failed for %s: %s", host, message)
                    if connection_failures >= 3:
                        self.log.warning("Repeated SMB connection failures at %s; stopping", host)
                        return []
                finally:
                    if connection is not None:
                        with contextlib.suppress(Exception):
                            connection.logoff()
                    self.guard.sleep()
        return []
