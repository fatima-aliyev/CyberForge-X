"""SSH password authentication checks with explicit lockout limits."""

from __future__ import annotations

import contextlib

from cyberforge.brute.base import CredentialHit, credential_hit
from cyberforge.brute.guard import AttemptBudget, CredentialGuard
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import ScopeViolation
from cyberforge.core.utils import split_host_port


class SSHTester:
    def __init__(self, ctx: ModuleContext, guard: CredentialGuard, budget: AttemptBudget) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.guard = guard
        self.budget = budget

    def test(self, target: str, users: list[str], passwords: list[str]) -> list[CredentialHit]:
        try:
            import paramiko
        except ImportError:
            self.ctx.bundle.add_error("brute", "paramiko is required for SSH credential testing")
            self.log.warning("paramiko is not installed; SSH credential testing skipped")
            return []
        host, port = split_host_port(target, 22)
        port = port or 22
        try:
            self.ctx.scope.assert_host(host, port)
        except ScopeViolation as exc:
            self.log.warning("SSH target outside scope: %s", exc)
            return []
        ips = self.ctx.scope.resolved_ips(host)
        if not ips:
            self.log.warning("SSH target did not resolve: %s", host)
            return []
        ip = ips[0]
        connection_failures = 0
        for username in users:
            for password in passwords:
                if not self.budget.consume():
                    self.log.info("Credential attempt budget exhausted")
                    return []
                transport = None
                try:
                    transport = paramiko.Transport((ip, port))
                    transport.banner_timeout = self.ctx.config.connect_timeout
                    transport.start_client(timeout=max(4.0, self.ctx.config.connect_timeout))
                    transport.auth_password(username, password, fallback=False)
                    if transport.is_authenticated():
                        self.log.warning("Valid SSH credentials found for %s (username %s)", host, username)
                        return [
                            credential_hit(
                                protocol="SSH",
                                target=f"{host}:{port}",
                                username=username,
                                password=password,
                                request=f"ssh -o PreferredAuthentications=password {username}@{host}",
                                notes=f"SSH password authentication succeeded; server banner {transport.remote_version}",
                            )
                        ]
                except paramiko.AuthenticationException:
                    connection_failures = 0
                except paramiko.SSHException as exc:
                    message = str(exc)
                    if self.guard.is_lockout(None, message):
                        self.log.warning("SSH lockout indicator at %s; stopping", host)
                        return []
                    connection_failures += 1
                    self.log.debug("SSH attempt failed for %s: %s", host, message)
                    if connection_failures >= 3:
                        self.log.warning("Repeated SSH transport failures at %s; stopping", host)
                        return []
                except Exception as exc:
                    connection_failures += 1
                    self.log.debug("SSH connection error for %s: %s", host, exc)
                    if connection_failures >= 3:
                        return []
                finally:
                    if transport is not None:
                        with contextlib.suppress(Exception):
                            transport.close()
                    self.guard.sleep()
        return []
