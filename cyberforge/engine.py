"""Assessment orchestrator: authorization-gated module execution and reporting."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from cyberforge import __version__
from cyberforge.api import APIModule
from cyberforge.brute import BruteModule
from cyberforge.chains import ChainOrchestrator
from cyberforge.core.config import ScanConfig
from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    AuthorizationError,
    ConfigurationError,
    CyberForgeError,
    OOBError,
)
from cyberforge.core.guard import RequestPolicy
from cyberforge.core.logging import get_logger, log_banner, setup_logging
from cyberforge.core.models import ResultBundle
from cyberforge.core.oob import OOBListener
from cyberforge.core.rate_limit import RateLimiter, RequestBudget
from cyberforge.core.scope import Scope
from cyberforge.core.session import SafeSession
from cyberforge.intel.module import IntelModule
from cyberforge.recon.module import ReconModule
from cyberforge.reporting import ReportGenerator, ReportPaths
from cyberforge.web import WebModule

MODULE_ORDER = ("recon", "intel", "web", "api", "brute", "chains")


class ScanEngine:
    def __init__(
        self,
        config: ScanConfig,
        scope: Scope,
        gate_audit: dict[str, Any] | None = None,
    ) -> None:
        if not config.have_authorization or not config.accept_disclaimer:
            raise AuthorizationError("engine requires a completed authorization gate")
        config.validate()
        _validate_scope_permissions(config, scope)
        self.config = config
        self.scope = scope
        self.gate_audit = gate_audit or scope.audit_metadata()
        self.config.rate = min(float(self.config.rate), float(scope.config.max_rps))
        self.config.max_requests = min(
            int(self.config.max_requests), int(scope.config.max_requests)
        )
        self.run_dir = _run_directory(Path(self.config.output_dir))
        self.config.output_dir = self.run_dir
        self.console = setup_logging(
            level=config.log_level,
            jsonl_path=self.run_dir / "audit.jsonl",
        )
        self.log = get_logger("engine")
        self.session = SafeSession(
            scope=scope,
            limiter=RateLimiter(config.rate, config.jitter),
            budget=RequestBudget(config.max_requests),
            timeout=config.timeout,
            connect_timeout=config.connect_timeout,
            verify=not config.insecure,
            proxy=config.proxy,
            user_agent=config.user_agent,
            extra_headers=config.extra_headers,
            policy=RequestPolicy(
                allow_post=True,
                allow_put=config.enable_write_tests,
                allow_patch=config.enable_write_tests,
                allow_delete=False,
                allow_trace=False,
            ),
        )
        scope_meta = dict(self.gate_audit)
        scope_meta.setdefault("tool_version", __version__)
        self.bundle = ResultBundle(scope.config.engagement, config.targets, scope_meta)
        self.ctx = ModuleContext(
            config=config,
            scope=scope,
            bundle=self.bundle,
            session=self.session,
            output_dir=self.run_dir,
        )
        self.oob: OOBListener | None = None
        self.report_paths: ReportPaths | None = None
        self.interrupted = False

    def run(self) -> ResultBundle:
        log_banner(self.console, __version__)
        self.log.info(
            "Engagement %r | targets=%d | modules=%s | rate=%.1f rps | budget=%d",
            self.scope.config.engagement,
            len(self.config.targets),
            ",".join(self.config.modules),
            self.config.rate,
            self.config.max_requests,
        )
        self.log.info("Output directory: %s", self.run_dir)
        self._start_oob()
        recon_result = None
        try:
            for module in [name for name in MODULE_ORDER if name in self.config.modules]:
                try:
                    if module == "recon":
                        recon_result = ReconModule(self.ctx).run()
                    elif module == "intel":
                        IntelModule(self.ctx).run()
                    elif module == "web":
                        WebModule(self.ctx, recon_result).run()
                    elif module == "api":
                        APIModule(self.ctx, recon_result).run()
                    elif module == "brute":
                        BruteModule(self.ctx, recon_result).run()
                    elif module == "chains":
                        ChainOrchestrator(self.ctx).run()
                except KeyboardInterrupt:
                    self.interrupted = True
                    self.ctx.bundle.add_error(module, "interrupted by operator")
                    self.log.warning(
                        "Assessment interrupted during %s; generating partial results",
                        module,
                    )
                    break
                except CyberForgeError as exc:
                    self.ctx.bundle.add_error(module, str(exc))
                    self.log.error("Module %s failed: %s", module, exc)
                except Exception as exc:
                    self.ctx.bundle.add_error(module, f"{type(exc).__name__}: {exc}")
                    self.log.exception("Module %s failed unexpectedly: %s", module, exc)
        finally:
            self.bundle.request_stats = self.session.snapshot()
            self.bundle.finish()
            try:
                self.report_paths = ReportGenerator(self.ctx).generate(self.bundle)
                self.log.info("Reports written to %s", self.run_dir)
            except Exception as exc:
                self.log.exception("Report generation failed: %s", exc)
            self.session.close()
            if self.oob is not None:
                self.oob.stop()
        return self.bundle

    def _start_oob(self) -> None:
        if not self.config.oob_host:
            return
        try:
            self.oob = OOBListener(
                bind_host="0.0.0.0",
                port=self.config.oob_port,
                public_host=self.config.oob_host,
            )
            self.oob.start()
            self.ctx.oob = self.oob
        except OOBError as exc:
            self.ctx.bundle.add_error("oob", str(exc))
            self.log.warning("OOB listener unavailable: %s", exc)
            self.oob = None


def _validate_scope_permissions(config: ScanConfig, scope: Scope) -> None:
    if "brute" in config.modules and not config.allow_credential_attacks:
        raise ConfigurationError(
            "the brute module requires --allow-credential-attacks and scope permission"
        )
    if config.allow_credential_attacks and not scope.config.allow_credential_attacks:
        raise ConfigurationError(
            "scope does not permit credential attacks; set allow_credential_attacks: true only "
            "with explicit written authorization"
        )
    if (
        config.allow_form_submissions
        or config.allow_stored_xss
        or config.enable_write_tests
    ) and not scope.config.allow_write_tests:
        raise ConfigurationError(
            "form submissions/write tests require allow_write_tests: true in the scope file"
        )


def _run_directory(base: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = base / stamp
    suffix = 1
    while candidate.exists():
        candidate = base / f"{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate
