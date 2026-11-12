from __future__ import annotations

import json
from types import SimpleNamespace

from cyberforge.core.models import Evidence, Finding, ResultBundle, Severity
from cyberforge.reporting import ReportGenerator


def _bundle() -> ResultBundle:
    bundle = ResultBundle(
        "Reporting Test",
        ["https://example.test"],
        {"engagement": "Reporting Test", "authorized_by": "Owner", "gate": "passed"},
    )
    bundle.add_finding(
        Finding(
            title="Reflected payload",
            severity=Severity.HIGH,
            module="web",
            target="https://example.test/?q=1",
            description="Untrusted markup: <script>alert(1)</script>",
            remediation="Encode output.",
            evidence=Evidence(payload="<script>alert(1)</script>"),
            cvss=8.1,
            tags=["xss"],
        )
    )
    bundle.add_credential(
        {
            "target": "https://example.test/login",
            "username": "admin",
            "password": "raw-secret",
            "protocol": "http-form",
        }
    )
    bundle.request_stats = {"requests": 3}
    bundle.finish()
    return bundle


def test_report_artifacts_are_escaped_and_credentials_are_isolated(tmp_path) -> None:
    ctx = SimpleNamespace(
        config=SimpleNamespace(modules=["web"], formats=["json", "md", "html"]),
        output_dir=tmp_path,
    )
    paths = ReportGenerator(ctx).generate(_bundle())
    assert paths.json and paths.markdown and paths.html and paths.credentials
    html = paths.html.read_text(encoding="utf-8")
    markdown = paths.markdown.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in markdown
    main_report = json.loads(paths.json.read_text(encoding="utf-8"))
    assert main_report["credentials"][0]["password"] != "raw-secret"
    credentials = json.loads(paths.credentials.read_text(encoding="utf-8"))
    assert credentials["credentials"][0]["password"] == "raw-secret"


def test_report_can_be_generated_without_credentials(tmp_path) -> None:
    bundle = _bundle()
    bundle.credentials.clear()
    ctx = SimpleNamespace(
        config=SimpleNamespace(modules=["web"], formats=["json"]),
        output_dir=tmp_path,
    )
    paths = ReportGenerator(ctx).generate(bundle)
    assert paths.credentials is None
    assert paths.json is not None
