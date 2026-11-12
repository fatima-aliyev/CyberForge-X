"""Render assessment results into durable report artifacts."""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from cyberforge import __version__
from cyberforge.core.context import ModuleContext
from cyberforge.core.models import ResultBundle, Severity
from cyberforge.core.utils import utc_now_iso

LIMITATIONS = [
    "Testing was limited to assets explicitly listed in the signed scope file.",
    "No denial-of-service, destructive write, data exfiltration, persistence, or cloud-metadata access was performed.",
    "Credential attacks and form submissions were disabled unless explicitly enabled and permitted by scope.",
    "Findings are evidence-based but require analyst validation before remediation or external disclosure.",
    "Online vulnerability candidates require manual applicability review; version matching is not proof of exploitability.",
    "Absence of a finding is not proof of absence; coverage depends on discovery, authentication state, and rate limits.",
]
SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


@dataclass
class ReportPaths:
    output_dir: Path
    json: Path | None = None
    markdown: Path | None = None
    html: Path | None = None
    credentials: Path | None = None


class ReportGenerator:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.config = ctx.config
        self.output_dir = ctx.output_dir
        template_dir = Path(__file__).resolve().parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["datetime"] = _format_datetime
        self.env.filters["cvss"] = _format_cvss
        self.env.filters["shorter"] = _shorten

    def generate(self, bundle: ResultBundle) -> ReportPaths:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        paths = ReportPaths(output_dir=self.output_dir)
        generated_at = utc_now_iso()
        data = bundle.to_dict(show_secrets=False)
        data["tool"] = {
            "name": "CyberForge-X",
            "version": __version__,
            "generated_at": generated_at,
        }
        data["modules"] = list(self.config.modules)
        data["limitations"] = LIMITATIONS
        data["duration_seconds"] = round(
            (bundle.finished_at or bundle.started_at) - bundle.started_at, 2
        )
        groups = _group_findings(bundle)
        context: dict[str, Any] = {
            "report": data,
            "generated_at": generated_at,
            "tool_name": "CyberForge-X",
            "tool_version": __version__,
            "engagement": bundle.engagement,
            "scope": data.get("scope", {}),
            "risk_rating": data.get("risk_rating", "Informational"),
            "severity_counts": data.get("severity_counts", {}),
            "findings_total": len(bundle.findings),
            "groups": groups,
            "chains": data.get("chains", []),
            "assets": data.get("assets", []),
            "api_surfaces": data.get("api_surfaces", []),
            "credentials": data.get("credentials", []),
            "errors": data.get("errors", []),
            "request_stats": data.get("request_stats", {}),
            "modules": data.get("modules", []),
            "limitations": LIMITATIONS,
            "duration_seconds": data.get("duration_seconds", 0),
        }
        if "json" in self.config.formats:
            paths.json = self.output_dir / "report.json"
            paths.json.write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n",
                encoding="utf-8",
            )
        if "md" in self.config.formats:
            paths.markdown = self.output_dir / "report.md"
            paths.markdown.write_text(
                self.env.get_template("report.md.j2").render(**context),
                encoding="utf-8",
            )
        if "html" in self.config.formats:
            paths.html = self.output_dir / "report.html"
            paths.html.write_text(
                self.env.get_template("report.html.j2").render(**context),
                encoding="utf-8",
            )
        if bundle.credentials:
            paths.credentials = self.output_dir / "credentials.json"
            credential_data = {
                "engagement": bundle.engagement,
                "generated_at": generated_at,
                "warning": (
                    "SENSITIVE: raw credentials are stored here for authorized remediation. "
                    "Protect and delete according to engagement policy."
                ),
                "credentials": list(bundle.credentials),
            }
            paths.credentials.write_text(
                json.dumps(credential_data, indent=2, ensure_ascii=False, default=str) + "\n",
                encoding="utf-8",
            )
            with contextlib.suppress(OSError):
                os.chmod(paths.credentials, 0o600)
        return paths


def _group_findings(bundle: ResultBundle) -> list[dict[str, Any]]:
    grouped = bundle.findings_by_severity()
    groups: list[dict[str, Any]] = []
    for severity in SEVERITY_ORDER:
        findings = grouped.get(severity, [])
        groups.append(
            {
                "severity": severity.value,
                "label": severity.value.capitalize(),
                "findings": findings,
                "count": len(findings),
            }
        )
    return groups


def _format_datetime(value: Any) -> str:
    if value in (None, ""):
        return "n/a"
    try:
        if isinstance(value, (int, float)):
            moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError, OverflowError):
        return str(value)


def _format_cvss(value: Any) -> str:
    if value in (None, ""):
        return "n/a"
    try:
        return f"{float(value):.1f}"
    except (ValueError, TypeError):
        return str(value)


def _shorten(value: Any, length: int = 300) -> str:
    text = str(value or "").replace("\x00", "")
    if len(text) <= length:
        return text
    return text[:length] + "..."
