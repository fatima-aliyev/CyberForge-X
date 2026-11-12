"""API module orchestrator."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cyberforge.api.bola import BOLATester
from cyberforge.api.checks import rate_limit_finding, sensitive_schema_findings
from cyberforge.api.discovery import APIDiscovery
from cyberforge.api.jwt_analyzer import JWTAnalyzer
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import RequestBudgetExceeded, ScopeViolation
from cyberforge.core.models import Finding
from cyberforge.web.headers import audit_headers

if TYPE_CHECKING:
    from cyberforge.recon.module import ReconResult


@dataclass
class APIResult:
    surfaces: int = 0
    endpoints: int = 0
    findings_added: int = 0
    jwt_findings: int = 0
    bola_findings: int = 0


class APIModule:
    def __init__(self, ctx: ModuleContext, recon_result: ReconResult | None = None) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.recon_result = recon_result
        self.result = APIResult()

    def run(self) -> APIResult:
        self.log.info("Starting API assessment")
        try:
            discovery = APIDiscovery(self.ctx, self.recon_result).discover()
        except RequestBudgetExceeded:
            self.ctx.bundle.add_error("api", "request budget exhausted during discovery")
            discovery = None
        except ScopeViolation:
            self.ctx.bundle.add_error("api", "API target fell outside the authorized scope")
            discovery = None
        except Exception as exc:
            self.ctx.bundle.add_error("api", f"API discovery failed: {exc}")
            self.log.exception("API discovery failed: %s", exc)
            discovery = None
        if discovery is not None:
            self._add(discovery.findings)
            self.result.surfaces = len(discovery.surfaces)
            self.result.endpoints = len(discovery.endpoints)
            for surface in discovery.surfaces:
                self._add(sensitive_schema_findings(surface))
                try:
                    self._add(audit_headers(self.ctx.session, surface.base_url, module="api"))
                except Exception as exc:
                    self.log.debug("API header audit failed for %s: %s", surface.base_url, exc)
            self._jwt()
            self._bola(discovery.endpoints)
            if discovery.surfaces:
                self._add(rate_limit_finding(self.ctx, discovery.surfaces[0]))
        else:
            self._jwt()
        self.log.info(
            "API module complete: %d surface(s), %d endpoint(s), %d finding(s)",
            self.result.surfaces,
            self.result.endpoints,
            self.result.findings_added,
        )
        return self.result

    def _jwt(self) -> None:
        try:
            findings = JWTAnalyzer(self.ctx).analyze()
        except Exception as exc:
            self.ctx.bundle.add_error("api", f"JWT analysis failed: {exc}")
            self.log.exception("JWT analysis failed: %s", exc)
            return
        self.result.jwt_findings = sum(1 for finding in findings if self.ctx.bundle.add_finding(finding))
        self.result.findings_added += self.result.jwt_findings

    def _bola(self, endpoints: list) -> None:
        try:
            outcome = BOLATester(self.ctx, endpoints).run()
        except RequestBudgetExceeded:
            self.ctx.bundle.add_error("api", "request budget exhausted during BOLA checks")
            return
        except ScopeViolation:
            self.ctx.bundle.add_error("api", "BOLA target fell outside the authorized scope")
            return
        except Exception as exc:
            self.ctx.bundle.add_error("api", f"BOLA checks failed: {exc}")
            self.log.exception("BOLA checks failed: %s", exc)
            return
        self.result.bola_findings = sum(1 for finding in outcome.findings if self.ctx.bundle.add_finding(finding))
        self.result.findings_added += self.result.bola_findings

    def _add(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            if self.ctx.bundle.add_finding(finding):
                self.result.findings_added += 1
