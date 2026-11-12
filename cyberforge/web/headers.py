"""Passive security-header, cookie, and CORS review."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from cyberforge.core.exceptions import PolicyViolation, ScopeViolation
from cyberforge.core.models import Evidence, Finding, Severity
from cyberforge.core.session import HttpResult, SafeSession
from cyberforge.core.utils import format_curl, safe_excerpt

FRAME_OPTIONS = {"deny", "sameorigin"}
CORS_ORIGINS = ("https://cfx-test.invalid", "null")
COOKIE_SPLIT_RE = re.compile(r",(?=\s*[^;,=\s]+=)")
COOKIE_NAME_RE = re.compile(r"^\s*([^=;,\s]+)=")


def audit_headers(session: SafeSession, url: str, module: str = "web") -> list[Finding]:
    try:
        result = session.get(url)
    except (ScopeViolation, PolicyViolation):
        return []
    if result.status is None:
        return []
    target = result.url or url
    findings: list[Finding] = []
    findings.extend(_transport_finding(result, target, module))
    findings.extend(_header_findings(result, target, module))
    findings.extend(_cookie_findings(result, target, module))
    findings.extend(_info_disclosure(result, target, module))
    findings.extend(_cors_findings(session, target, module))
    return findings


def _transport_finding(result: HttpResult, target: str, module: str) -> list[Finding]:
    if urlsplit(target).scheme != "http":
        return []
    return [
        Finding(
            title="Web application served over plain HTTP",
            severity=Severity.MEDIUM,
            module=module,
            target=target,
            description=(
                "The application is reachable over HTTP without an enforced upgrade to HTTPS. "
                "Traffic, including credentials or session cookies, may be intercepted."
            ),
            remediation="Redirect all HTTP traffic to HTTPS and deploy HSTS after validating the certificate.",
            evidence=Evidence(
                request=format_curl("GET", target, result.request_headers),
                notes=f"Final URL: {result.url}",
            ),
            cvss=5.3,
            confidence="high",
            tags=["web", "tls", "transport"],
        )
    ]


def _header_findings(result: HttpResult, target: str, module: str) -> list[Finding]:
    scheme = urlsplit(target).scheme
    hsts = result.header("Strict-Transport-Security")
    csp = result.header("Content-Security-Policy")
    xcto = result.header("X-Content-Type-Options")
    xfo = result.header("X-Frame-Options")
    referrer = result.header("Referrer-Policy")
    permissions = result.header("Permissions-Policy")
    missing: list[str] = []
    weak: list[str] = []
    if scheme == "https":
        if not hsts:
            missing.append("Strict-Transport-Security (HSTS)")
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if not match or int(match.group(1)) < 15552000:
                weak.append("HSTS max-age is below six months")
    if not csp:
        missing.append("Content-Security-Policy (CSP)")
    else:
        lowered = csp.lower()
        if "'unsafe-inline'" in lowered or "'unsafe-eval'" in lowered:
            weak.append("CSP permits unsafe-inline or unsafe-eval")
        if re.search(r"(?:^|[\s;])default-src\s+\*", lowered) or re.search(
            r"(?:^|[\s;])script-src\s+[^;]*\*", lowered
        ):
            weak.append("CSP uses a wildcard source")
    if not xcto:
        missing.append("X-Content-Type-Options: nosniff")
    elif xcto.strip().lower() != "nosniff":
        weak.append("X-Content-Type-Options does not use nosniff")
    if not xfo and not (csp and "frame-ancestors" in csp.lower()):
        missing.append("X-Frame-Options or CSP frame-ancestors")
    elif xfo and xfo.strip().lower() not in FRAME_OPTIONS and not xfo.lower().startswith("allow-from"):
        weak.append("X-Frame-Options value is not DENY/SAMEORIGIN")
    if not referrer:
        missing.append("Referrer-Policy")
    if not permissions:
        missing.append("Permissions-Policy")
    if not missing and not weak:
        return []
    lines: list[str] = []
    if missing:
        lines.append("Missing: " + ", ".join(missing))
    if weak:
        lines.append("Weak: " + "; ".join(weak))
    return [
        Finding(
            title="Security headers missing or weak",
            severity=Severity.LOW,
            module=module,
            target=target,
            description=(
                "Browser security headers are missing or configured weakly. This increases exposure "
                "to clickjacking, MIME sniffing, and content-injection classes of attack."
            ),
            remediation=(
                "Add HSTS on HTTPS, a restrictive CSP, X-Content-Type-Options: nosniff, "
                "frame-ancestors/X-Frame-Options, Referrer-Policy, and Permissions-Policy."
            ),
            evidence=Evidence(
                request=format_curl("GET", target, result.request_headers),
                response_excerpt="\n".join(lines),
            ),
            cvss=3.7,
            confidence="high",
            tags=["web", "headers", "hardening"],
            metadata={"missing": missing, "weak": weak},
        )
    ]


def _cookie_findings(result: HttpResult, target: str, module: str) -> list[Finding]:
    raw_cookies = result.header("Set-Cookie")
    if not raw_cookies:
        return []
    https = urlsplit(target).scheme == "https"
    issues: list[str] = []
    names: list[str] = []
    for chunk in COOKIE_SPLIT_RE.split(raw_cookies):
        match = COOKIE_NAME_RE.match(chunk)
        if not match:
            continue
        name = match.group(1).strip()
        names.append(name)
        lowered = chunk.lower()
        missing: list[str] = []
        if https and "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            issues.append(f"{name}: missing {', '.join(missing)}")
    if not issues:
        return []
    return [
        Finding(
            title="Session cookie security flags missing",
            severity=Severity.LOW,
            module=module,
            target=target,
            description=(
                "One or more cookies lack security attributes, increasing exposure to theft, "
                "cross-site scripting, or cross-site request forgery."
            ),
            remediation="Set Secure, HttpOnly, and an appropriate SameSite value on session cookies.",
            evidence=Evidence(
                request=format_curl("GET", target, result.request_headers),
                response_excerpt="\n".join(issues[:20]),
                notes=f"Cookies observed: {', '.join(names[:20])} (values withheld)",
            ),
            cvss=3.7,
            confidence="high",
            tags=["web", "cookies", "session"],
            metadata={"issues": issues[:20]},
        )
    ]


def _info_disclosure(result: HttpResult, target: str, module: str) -> list[Finding]:
    server = result.header("Server")
    powered = result.header("X-Powered-By")
    pieces = []
    if server and re.search(r"\d", server):
        pieces.append(f"Server: {server}")
    if powered:
        pieces.append(f"X-Powered-By: {powered}")
    if not pieces:
        return []
    return [
        Finding(
            title="Technology version disclosure in response headers",
            severity=Severity.INFO,
            module=module,
            target=target,
            description="Response headers disclose software names or versions that assist fingerprinting.",
            remediation="Suppress detailed Server and X-Powered-By headers at the proxy or application layer.",
            evidence=Evidence(
                request=format_curl("GET", target, result.request_headers),
                response_excerpt=safe_excerpt("\n".join(pieces), 300),
            ),
            confidence="high",
            tags=["web", "headers", "fingerprinting"],
        )
    ]


def _cors_findings(session: SafeSession, target: str, module: str) -> list[Finding]:
    observations: list[tuple[str, str, str, str]] = []
    methods_checked: set[str] = set()
    for origin in CORS_ORIGINS:
        for method in ("OPTIONS", "GET"):
            if method in methods_checked and method == "OPTIONS":
                continue
            methods_checked.add(method)
            headers = {"Origin": origin, "Accept": "*/*"}
            if method == "OPTIONS":
                headers["Access-Control-Request-Method"] = "GET"
                headers["Access-Control-Request-Headers"] = "authorization, content-type"
            try:
                result = session.request(method, target, headers=headers)
            except (ScopeViolation, PolicyViolation):
                continue
            if result.status is None:
                continue
            allow_origin = result.header("Access-Control-Allow-Origin")
            allow_credentials = result.header("Access-Control-Allow-Credentials").lower() == "true"
            allow_methods = result.header("Access-Control-Allow-Methods")
            if allow_origin:
                observations.append((origin, allow_origin, str(allow_credentials).lower(), allow_methods))
    if not observations:
        return []
    strongest: Finding | None = None
    for origin, allow_origin, credentials, methods in observations:
        reflected = allow_origin == origin
        wildcard = allow_origin == "*"
        with_credentials = credentials == "true"
        if not reflected and not wildcard:
            continue
        if with_credentials and (reflected or wildcard):
            severity = Severity.HIGH
            cvss = 8.1
            title = "CORS allows credentialed access from untrusted origins"
            description = (
                "The server returns a credentialed CORS policy for an arbitrary or null origin. "
                "A malicious site may be able to read authenticated responses in a browser context."
            )
        elif reflected:
            severity = Severity.LOW
            cvss = 3.7
            title = "CORS reflects arbitrary origins without credentials"
            description = (
                "The server reflects arbitrary origins in Access-Control-Allow-Origin without "
                "allowing credentials. Exposure is limited but should be reviewed."
            )
        else:
            severity = Severity.LOW
            cvss = 3.1
            title = "CORS permits any origin"
            description = (
                "The server allows Access-Control-Allow-Origin: * without credentials. This is often "
                "intentional for public resources but should be confirmed."
            )
        finding = Finding(
            title=title,
            severity=severity,
            module=module,
            target=target,
            description=description,
            remediation=(
                "Use an explicit allowlist of trusted origins; never reflect arbitrary origins with "
                "Access-Control-Allow-Credentials: true. Treat the null origin as untrusted."
            ),
            evidence=Evidence(
                request=format_curl("OPTIONS", target, {"Origin": origin, "Access-Control-Request-Method": "GET"}),
                response_excerpt=(
                    f"Tested Origin: {origin}\n"
                    f"Access-Control-Allow-Origin: {allow_origin}\n"
                    f"Access-Control-Allow-Credentials: {credentials}"
                    + (f"\nAccess-Control-Allow-Methods: {methods}" if methods else "")
                ),
            ),
            cvss=cvss,
            confidence="high",
            tags=["web", "cors", "access-control"],
            metadata={"origin": origin, "allow_origin": allow_origin, "credentials": with_credentials},
        )
        if strongest is None or finding.severity.rank > strongest.severity.rank:
            strongest = finding
    return [strongest] if strongest else []
