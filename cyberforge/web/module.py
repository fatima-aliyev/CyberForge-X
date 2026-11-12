"""Web application module orchestrator."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import RequestBudgetExceeded, ScopeViolation
from cyberforge.core.models import Finding
from cyberforge.core.utils import normalize_url
from cyberforge.web.crawler import Crawler
from cyberforge.web.fuzz import PathFuzzer
from cyberforge.web.headers import audit_headers
from cyberforge.web.inclusion import InclusionTester
from cyberforge.web.injection import InjectionTester

if TYPE_CHECKING:
    from cyberforge.recon.module import ReconResult

MAX_WEB_TARGETS = 3


@dataclass
class WebResult:
    targets: list[str] = field(default_factory=list)
    pages_crawled: int = 0
    injection_points: int = 0
    findings_added: int = 0


class WebModule:
    def __init__(self, ctx: ModuleContext, recon_result: ReconResult | None = None) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.recon_result = recon_result
        self.result = WebResult()

    def run(self) -> WebResult:
        targets = self._select_targets()
        self.result.targets = targets
        if not targets:
            self.ctx.bundle.add_error("web", "no HTTP(S) targets were available for web testing")
            self.log.warning("No web targets available")
            return self.result
        self.log.info("Starting web assessment against %d target(s)", len(targets))
        for target in targets:
            try:
                self._assess(target)
            except RequestBudgetExceeded:
                self.ctx.bundle.add_error("web", "global request budget exhausted")
                self.log.warning("Stopping web module: request budget exhausted")
                break
            except ScopeViolation:
                self.ctx.bundle.add_error("web", f"{target}: target fell outside scope")
            except Exception as exc:
                self.ctx.bundle.add_error("web", f"{target}: {exc}")
                self.log.exception("web assessment failed for %s: %s", target, exc)
        self.log.info(
            "Web module complete: %d target(s), %d page(s), %d point(s), %d finding(s)",
            len(self.result.targets),
            self.result.pages_crawled,
            self.result.injection_points,
            self.result.findings_added,
        )
        return self.result

    def _assess(self, target: str) -> None:
        self.log.info("Assessing web target %s", target)
        self._add(header for header in audit_headers(self.ctx.session, target))
        crawler = Crawler(self.ctx)
        crawl = crawler.crawl(target)
        self.result.pages_crawled += len(crawl.pages)
        self.result.injection_points += len(crawl.injection_points)
        fuzzer = PathFuzzer(self.ctx)
        fuzz_results = fuzzer.scan(target)
        self._add(fuzzer.findings(target, fuzz_results))
        injector = InjectionTester(self.ctx)
        if crawl.injection_points:
            self._add(injector.test(crawl.injection_points))
            self._add(InclusionTester(self.ctx).test(crawl.injection_points))
        else:
            self.log.info("No injectable parameters discovered on %s", target)
        self._add(injector.dom_flows(crawl))
        self._add(injector.stored_html_injection(crawl))

    def _add(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            if self.ctx.bundle.add_finding(finding):
                self.result.findings_added += 1

    def _select_targets(self) -> list[str]:
        candidates: list[str] = []
        for target in self.ctx.config.targets:
            if target.lower().startswith(("http://", "https://")):
                candidates.append(target)
        if self.recon_result:
            candidates.extend(self.recon_result.web_targets)
        if not candidates:
            candidates.extend(self._infer_targets())
        selected: list[str] = []
        origins: set[tuple[str, str, int | None]] = set()
        for candidate in candidates:
            try:
                normalized = normalize_url(candidate)
                parts = urlsplit(normalized)
                if parts.scheme not in {"http", "https"} or not parts.hostname:
                    continue
                self.ctx.scope.assert_url(normalized)
            except (ScopeViolation, ValueError):
                continue
            origin = (parts.scheme, parts.hostname.lower(), parts.port)
            if origin in origins:
                continue
            origins.add(origin)
            selected.append(normalized)
            if len(selected) >= MAX_WEB_TARGETS:
                break
        return selected

    def _infer_targets(self) -> list[str]:
        inferred: list[str] = []
        for target in self.ctx.config.targets:
            if "://" in target or "/" in target:
                continue
            host, port = target, None
            if target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit():
                host, port_text = target.rsplit(":", 1)
                port = int(port_text)
            scheme = "https" if port in {443, 8443} else "http"
            url = f"{scheme}://{host}" + (f":{port}" if port else "")
            try:
                self.ctx.scope.assert_url(url)
            except ScopeViolation:
                continue
            inferred.append(url)
        return inferred
