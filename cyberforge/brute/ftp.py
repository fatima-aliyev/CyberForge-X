"""FTP password authentication checks."""

from __future__ import annotations

import contextlib
import ftplib

from cyberforge.brute.base import CredentialHit, credential_hit
from cyberforge.brute.guard import AttemptBudget, CredentialGuard
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import ScopeViolation
from cyberforge.core.utils import split_host_port, truncate


class FTPTester:
    def __init__(self, ctx: ModuleContext, guard: CredentialGuard, budget: AttemptBudget) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.guard = guard
        self.budget = budget

    def test(self, target: str, users: list[str], passwords: list[str]) -> list[CredentialHit]:
        host, port = split_host_port(target, 21)
        port = port or 21
        try:
            self.ctx.scope.assert_host(host, port)
        except ScopeViolation as exc:
            self.log.warning("FTP target outside scope: %s", exc)
            return []
        ips = self.ctx.scope.resolved_ips(host)
        if not ips:
            self.log.warning("FTP target did not resolve: %s", host)
            return []
        ip = ips[0]
        connection_failures = 0
        for username in users:
            for password in passwords:
                if not self.budget.consume():
                    self.log.info("Credential attempt budget exhausted")
                    return []
                ftp: ftplib.FTP | None = None
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(ip, port, timeout=max(3.0, self.ctx.config.connect_timeout))
                    banner = truncate(ftp.getwelcome(), 200)
                    ftp.login(username, password)
                    self.log.warning("Valid FTP credentials found for %s (username %s)", host, username)
                    return [
                        credential_hit(
                            protocol="FTP",
                            target=f"{host}:{port}",
                            username=username,
                            password=password,
                            request=f"ftp {host}  # login as {username} with the recovered password",
                            notes=f"FTP login succeeded; server banner: {banner}",
                            cvss=9.3,
                        )
                    ]
                except ftplib.error_perm as exc:
                    message = str(exc)
                    if "too many" in message.lower() or "locked" in message.lower():
                        self.log.warning("FTP lockout indicator at %s; stopping", host)
                        return []
                    connection_failures = 0
                except (ftplib.error_temp, ftplib.error_reply, OSError) as exc:
                    message = str(exc)
                    if self.guard.is_lockout(None, message):
                        self.log.warning("FTP rate/lockout indicator at %s; stopping", host)
                        return []
                    connection_failures += 1
                    self.log.debug("FTP attempt failed for %s: %s", host, message)
                    if connection_failures >= 3:
                        self.log.warning("Repeated FTP connection failures at %s; stopping", host)
                        return []
                finally:
                    if ftp is not None:
                        try:
                            ftp.quit()
                        except Exception:
                            with contextlib.suppress(Exception):
                                ftp.close()
                    self.guard.sleep()
        return []
