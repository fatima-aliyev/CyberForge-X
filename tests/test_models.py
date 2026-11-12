from __future__ import annotations

from cyberforge.core.models import Evidence, Finding, ResultBundle, Severity


def _finding(title: str, severity: Severity, parameter: str = "") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        module="test",
        target="https://example.test",
        description="description",
        remediation="remediation",
        evidence=Evidence(payload="payload"),
        metadata={"parameter": parameter},
    )


def test_duplicate_findings_are_suppressed() -> None:
    bundle = ResultBundle("E", ["https://example.test"], {})
    first = _finding("Duplicate", Severity.HIGH, "q")
    assert bundle.add_finding(first) is True
    assert bundle.add_finding(_finding("Duplicate", Severity.HIGH, "q")) is False
    assert bundle.add_finding(_finding("Duplicate", Severity.HIGH, "id")) is True


def test_findings_grouped_by_severity_newest_first() -> None:
    bundle = ResultBundle("E", ["https://example.test"], {})
    older = _finding("Older", Severity.HIGH)
    newer = _finding("Newer", Severity.HIGH)
    older.timestamp = 10.0
    newer.timestamp = 20.0
    bundle.add_finding(older)
    bundle.add_finding(newer)
    grouped = bundle.findings_by_severity()
    assert [finding.title for finding in grouped[Severity.HIGH]] == ["Newer", "Older"]


def test_risk_rating_and_counts() -> None:
    bundle = ResultBundle("E", ["https://example.test"], {})
    assert bundle.risk_rating() == "Informational"
    bundle.add_finding(_finding("Medium", Severity.MEDIUM))
    assert bundle.severity_counts()["medium"] == 1
    assert bundle.risk_rating() == "Medium"


def test_main_export_masks_credentials() -> None:
    bundle = ResultBundle("E", ["https://example.test"], {})
    bundle.add_credential(
        {
            "target": "https://example.test",
            "username": "admin",
            "password": "super-secret",
            "protocol": "http-form",
        }
    )
    exported = bundle.to_dict(show_secrets=False)
    assert exported["credentials"][0]["password"] != "super-secret"
    assert "super-secret" not in str(exported)
    assert bundle.to_dict(show_secrets=True)["credentials"][0]["password"] == "super-secret"


def test_finish_records_timestamp() -> None:
    bundle = ResultBundle("E", ["https://example.test"], {})
    assert bundle.finished_at is None
    bundle.finish()
    assert bundle.finished_at is not None
    assert bundle.finished_at >= bundle.started_at
