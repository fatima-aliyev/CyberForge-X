"""Shared credential-hit construction without exposing passwords in findings."""

from __future__ import annotations

from dataclasses import dataclass

from cyberforge.core.models import Evidence, Finding, Severity
from cyberforge.core.utils import utc_now_iso


@dataclass
class CredentialHit:
    finding: Finding
    record: dict[str, object]


def credential_hit(
    *,
    protocol: str,
    target: str,
    username: str,
    password: str,
    request: str,
    notes: str,
    cvss: float = 9.1,
) -> CredentialHit:
    finding = Finding(
        title=f"Valid credentials accepted ({protocol})",
        severity=Severity.CRITICAL,
        module="brute",
        target=target,
        description=(
            f"Authentication succeeded with a weak or commonly used credential pair over {protocol}. "
            "This confirms an account takeover path for an authorized engagement."
        ),
        remediation=(
            "Rotate the affected credentials, enforce strong password policy and MFA, add progressive "
            "lockout/rate limiting, and monitor authentication anomalies."
        ),
        evidence=Evidence(
            request=request,
            notes=f"Username: {username}\nPassword: {mask_password(password)}\n{notes}",
        ),
        cvss=cvss,
        confidence="high",
        tags=["credentials", "weak-authentication", protocol.lower().replace(" ", "-")],
        metadata={
            "protocol": protocol,
            "username": username,
            "password_masked": mask_password(password),
        },
        reproduction=request,
    )
    record = {
        "protocol": protocol,
        "target": target,
        "username": username,
        "password": password,
        "verified_at": utc_now_iso(),
    }
    return CredentialHit(finding=finding, record=record)


def mask_password(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 2:
        return "**"
    if len(value) <= 6:
        return value[0] + "****"
    return value[:2] + "****" + value[-2:]
