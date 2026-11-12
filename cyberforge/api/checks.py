"""Schema-level review and explicitly gated API rate-limit observation."""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.models import APISurface, Evidence, Finding, Severity
from cyberforge.core.utils import format_curl

SENSITIVE_FIELDS = {
    "role",
    "roles",
    "is_admin",
    "isadmin",
    "admin",
    "superuser",
    "verified",
    "email_verified",
    "is_verified",
    "active",
    "is_active",
    "status",
    "balance",
    "credits",
    "price",
    "amount",
    "discount",
    "owner_id",
    "user_id",
    "account_id",
    "permission",
    "permissions",
    "scope",
    "plan",
    "subscription",
    "tier",
}
RATE_LIMIT_HEADERS = {
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
}


def sensitive_schema_findings(surface: APISurface) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in surface.endpoints:
        sensitive = sorted(
            {field for field in endpoint.body_fields if field.lower() in SENSITIVE_FIELDS}
        )
        if not sensitive:
            continue
        findings.append(
            Finding(
                title="Authorization-sensitive fields accepted by API schema",
                severity=Severity.INFO,
                module="api",
                target=endpoint.url,
                description=(
                    "The documented request body includes fields commonly associated with privilege, "
                    "ownership, or billing state. Whether clients may set them depends on server-side "
                    "authorization and is not tested here."
                ),
                remediation=(
                    "Use server-side allowlists for writable fields; ignore client-supplied role, owner, "
                    "verification, and billing attributes unless explicitly authorized."
                ),
                evidence=Evidence(
                    notes=f"Fields: {', '.join(sensitive[:20])}",
                    response_excerpt=f"{endpoint.method} {urlsplit(endpoint.url).path}",
                ),
                confidence="medium",
                tags=["api", "mass-assignment", "schema-review"],
                metadata={
                    "fields": sensitive[:20],
                    "method": endpoint.method,
                    "needs_manual_verification": True,
                },
            )
        )
    return findings


def rate_limit_finding(ctx: ModuleContext, surface: APISurface) -> list[Finding]:
    if not ctx.config.check_rate_limits:
        return []
    target = ctx.config.api_base or _endpoint_for_rate_limit(surface)
    if not target:
        return []
    statuses: list[int] = []
    headers_seen: set[str] = set()
    try:
        for _ in range(15):
            result = ctx.session.get(target, headers={"Accept": "application/json, */*"})
            if result.status is None:
                continue
            statuses.append(result.status)
            for name in result.headers:
                if name.lower() in RATE_LIMIT_HEADERS:
                    headers_seen.add(name.lower())
    except RequestBudgetExceeded:
        return []
    except (ScopeViolation, PolicyViolation):
        return []
    if not statuses:
        return []
    triggered = 429 in statuses
    if triggered or headers_seen:
        return []
    counts = Counter(statuses)
    return [
        Finding(
            title="No API rate limiting observed during a bounded probe",
            severity=Severity.LOW,
            module="api",
            target=target,
            description=(
                "Fifteen consecutive GET requests produced no HTTP 429 response and no standard "
                "rate-limit headers. This is a bounded observation, not proof that rate limiting is absent."
            ),
            remediation=(
                "Implement per-identity rate limiting for authentication and expensive endpoints; return "
                "429 with Retry-After and expose non-sensitive limit headers."
            ),
            evidence=Evidence(
                request=format_curl("GET", target),
                response_excerpt="Status distribution: " + ", ".join(f"{code}x{count}" for code, count in counts.items()),
                notes="Only 15 requests were sent with the configured global rate limit.",
            ),
            cvss=3.1,
            confidence="low",
            tags=["api", "rate-limit", "needs-review"],
            metadata={"statuses": dict(counts)},
        )
    ]


def _endpoint_for_rate_limit(surface: APISurface) -> str:
    for endpoint in surface.endpoints:
        if endpoint.method.upper() == "GET":
            return endpoint.url
    return surface.base_url
