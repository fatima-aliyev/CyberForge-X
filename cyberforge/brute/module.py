"""Bounded credential-testing orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from cyberforge.brute.ftp import FTPTester
from cyberforge.brute.guard import AttemptBudget, CredentialGuard
from cyberforge.brute.http_auth import HTTPAuthTester
from cyberforge.brute.http_form import HTTPFormTester
from cyberforge.brute.smb import SMBTester
from cyberforge.brute.ssh import SSHTester
from cyberforge.brute.wordlists import load_passwords, load_users
from cyberforge.core.context import ModuleContext

if TYPE_CHECKING:
    from cyberforge.recon.module import ReconResult

HTTP_PROTOCOLS = {"http-basic", "http-digest", "http-form"}


@dataclass
class BruteResult:
    attempts: int = 0
    findings_added: int = 0
    successes: int = 0
    skipped: str = ""
    protocols: list[str] = field(default_factory=list)


class BruteModule:
    def __init__(self, ctx: ModuleContext, recon_result: ReconResult | None = None) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.recon_result = recon_result
        self.result = BruteResult()

    def run(self) -> BruteResult:
        budget = AttemptBudget(max(1, self.ctx.config.brute_max_attempts))
        guard = CredentialGuard(self.ctx, budget)
        authorized, reason = guard.authorized()
        if not authorized:
            self.result.skipped = reason
            self.log.warning("Credential testing skipped: %s", reason)
            return self.result
        protocols = self._protocols()
        if not protocols:
            self.result.skipped = "no credential protocol selected"
            self.log.info("Credential testing skipped: no protocol selected")
            return self.result
        users = load_users(self.ctx)
        passwords = load_passwords(self.ctx)
        if not users or not passwords:
            self.result.skipped = "credential wordlists are empty"
            self.log.info("Credential testing skipped: wordlists are empty")
            return self.result
        self.result.protocols = protocols
        self.log.info(
            "Starting credential testing: protocols=%s users=%d passwords=%d attempts=%d",
            ",".join(protocols),
            len(users),
            len(passwords),
            budget.max_attempts,
        )
        for protocol in protocols:
            targets = self._targets(protocol)
            if not targets:
                self.log.info("No targets available for protocol %s", protocol)
                continue
            for target in targets:
                if budget.remaining <= 0:
                    self.log.info("Credential attempt budget exhausted")
                    break
                try:
                    hits = self._run_protocol(protocol, target, guard, budget, users, passwords)
                except Exception as exc:
                    self.ctx.bundle.add_error("brute", f"{protocol} {target}: {exc}")
                    self.log.exception("Credential test failed for %s %s: %s", protocol, target, exc)
                    continue
                for hit in hits:
                    if self.ctx.bundle.add_finding(hit.finding):
                        self.result.findings_added += 1
                        self.result.successes += 1
                    self.ctx.bundle.add_credential(hit.record)
                    self.log.warning(
                        "Confirmed credential for %s via %s (username %s); password masked in report",
                        target,
                        protocol,
                        hit.record.get("username", ""),
                    )
            if budget.remaining <= 0:
                break
        self.result.attempts = budget.used
        self.log.info(
            "Credential testing complete: %d attempt(s), %d success(es)",
            self.result.attempts,
            self.result.successes,
        )
        return self.result

    def _run_protocol(
        self,
        protocol: str,
        target: str,
        guard: CredentialGuard,
        budget: AttemptBudget,
        users: list[str],
        passwords: list[str],
    ) -> list:
        if protocol == "http-basic":
            return HTTPAuthTester(self.ctx, guard, budget, digest=False).test(target, users, passwords)
        if protocol == "http-digest":
            return HTTPAuthTester(self.ctx, guard, budget, digest=True).test(target, users, passwords)
        if protocol == "http-form":
            return HTTPFormTester(self.ctx, guard, budget).test(target, users, passwords)
        if protocol == "ssh":
            return SSHTester(self.ctx, guard, budget).test(target, users, passwords)
        if protocol == "ftp":
            return FTPTester(self.ctx, guard, budget).test(target, users, passwords)
        if protocol == "smb":
            return SMBTester(self.ctx, guard, budget).test(target, users, passwords)
        self.log.warning("Unknown credential protocol %s", protocol)
        return []

    def _protocols(self) -> list[str]:
        configured = [protocol for protocol in self.ctx.config.brute_protocols if protocol]
        if configured:
            return configured
        if not self.ctx.config.brute_auto or self.recon_result is None:
            return []
        inferred: list[str] = []
        for asset in self.recon_result.assets:
            for port in asset.ports:
                if port.port == 22:
                    inferred.append("ssh")
                elif port.port == 21:
                    inferred.append("ftp")
                elif port.port == 445:
                    inferred.append("smb")
        return sorted(set(inferred))

    def _targets(self, protocol: str) -> list[str]:
        configured = [target for target in self.ctx.config.brute_targets if target.strip()]
        if configured:
            return configured
        if protocol in HTTP_PROTOCOLS:
            targets = [target for target in self.ctx.config.targets if target.lower().startswith(("http://", "https://"))]
            if not targets and self.recon_result:
                targets = list(self.recon_result.web_targets)
            return targets
        targets = []
        for target in self.ctx.config.targets:
            if target.lower().startswith(("http://", "https://")):
                parts = urlsplit(target)
                if parts.hostname:
                    targets.append(parts.hostname)
            else:
                targets.append(target)
        return targets
