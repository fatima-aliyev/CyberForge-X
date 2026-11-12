"""Low-impact SQLi, command-injection, XSS, and DOM-flow checks."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
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
from cyberforge.web.crawler import (
    CrawlResult,
    InjectionPoint,
    is_sensitive_point,
)

SQL_ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"SQLSTATE\[",
        r"mysql_(?:fetch|query|num_rows)",
        r"mysqli?_",
        r"ORA-\d{4,5}",
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"SQLite(?:3)?::",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"syntax error.*(?:SQL|near)",
        r"ODBC SQL Server Driver",
        r"JDBC Driver",
        r"Microsoft OLE DB Provider",
        r"You have an error in your SQL syntax",
        r"SQL command not properly ended",
    )
]
DOM_SOURCES = [
    r"location\.(?:search|hash|href)",
    r"document\.(?:URL|documentURI|referrer|location)",
    r"window\.name",
    r"localStorage",
    r"sessionStorage",
    r"URLSearchParams",
    r"(?:event|evt|e)\.data",
]
DOM_SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write(?:ln)?\s*\(",
    r"\beval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"new\s+Function\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"\$\([^)]*\)\.html\s*\(",
    r"\.html\s*\(",
    r"location(?:\.href)?\s*=",
    r"location\.(?:assign|replace)\s*\(",
    r"\.srcdoc\s*=",
]
XSS_PAYLOADS = [
    '{marker}"><svg/onload=alert("{marker}")>',
    "{marker}'><img src=x onerror=alert('{marker}')>",
    '"><script>alert("{marker}")</script>',
    '";alert("{marker}");//',
    "javascript:alert('{marker}')",
]
SLEEP_SECONDS = 3
TIME_POINTS_LIMIT = 8
MAX_TIME_PAYLOADS_SQL = 3
MAX_TIME_PAYLOADS_CMD = 3


@dataclass
class _ResponseState:
    result: HttpResult
    normalized: str
    length: int


class InjectionTester:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.session = ctx.session
        self.markings: set[str] = set()
        self.time_point_count = 0

    def test(self, points: list[InjectionPoint]) -> list[Finding]:
        selected = [point for point in points if not is_sensitive_point(point)]
        if not self.ctx.config.allow_form_submissions:
            selected = [point for point in selected if point.method != "POST"]
        selected = selected[: self.ctx.config.max_injection_points]
        findings: list[Finding] = []
        for point in selected:
            try:
                findings.extend(self._test_point(point))
            except RequestBudgetExceeded:
                self.log.warning("request budget exhausted during injection testing")
                break
            except (ScopeViolation, PolicyViolation):
                continue
        self.log.info("Injection testing: %d parameter(s), %d confirmation(s)", len(selected), len(findings))
        return findings

    def _test_point(self, point: InjectionPoint) -> list[Finding]:
        baseline_result = self._send(point, point.value)
        if baseline_result is None or baseline_result.status is None:
            return []
        if baseline_result.status in {404, 410} or baseline_result.status >= 500:
            return []
        baseline = _state(baseline_result)
        findings: list[Finding] = []
        sql_error = self._sqli_error(point, baseline)
        if sql_error:
            findings.append(sql_error)
        else:
            boolean = self._sqli_boolean(point, baseline)
            if boolean:
                findings.append(boolean)
        xss = self._xss(point)
        if xss:
            findings.append(xss)
        if not findings and self.time_point_count < TIME_POINTS_LIMIT:
            self.time_point_count += 1
            sql_time = self._sqli_time(point, baseline)
            if sql_time:
                findings.append(sql_time)
            else:
                command = self._command_time(point, baseline)
                if command:
                    findings.append(command)
        return findings

    # ------------------------------------------------------------------ request
    def _send(self, point: InjectionPoint, value: str, timeout: float | None = None) -> HttpResult | None:
        params = point.stable_params(value)
        try:
            if point.method == "GET":
                return self.session.get(point.url, params=params, timeout=timeout)
            if not self.ctx.config.allow_form_submissions:
                return None
            return self.session.post(point.url, data=params, timeout=timeout)
        except (ScopeViolation, PolicyViolation):
            return None

    def _reproduction(self, point: InjectionPoint, payload: str) -> str:
        if point.method == "GET":
            delimiter = "&" if "?" in point.url else "?"
            return format_curl("GET", f"{point.url}{delimiter}{urlencode(point.stable_params(payload))}")
        return format_curl("POST", point.url, data=urlencode(point.stable_params(payload)))

    # ------------------------------------------------------------------ sqli
    def _sqli_error(self, point: InjectionPoint, baseline: _ResponseState) -> Finding | None:
        for payload in ("'", '"', "')", "\\", "';"):
            result = self._send(point, payload)
            if result is None or result.status is None or not result.text:
                continue
            for pattern in SQL_ERROR_PATTERNS:
                if pattern.search(result.text) and not pattern.search(baseline.result.text):
                    return Finding(
                        title="SQL injection (error-based)",
                        severity=Severity.HIGH,
                        module="web",
                        target=result.url or point.url,
                        description=(
                            "A database error was triggered by a crafted parameter value, indicating "
                            "that input reaches a SQL query without safe parameterization."
                        ),
                        remediation=(
                            "Use parameterized queries for all database access, validate input types, "
                            "and suppress detailed database errors."
                        ),
                        evidence=Evidence(
                            payload=payload,
                            request=self._reproduction(point, payload),
                            response_excerpt=_context_excerpt(result.text, pattern.pattern),
                            notes=f"Matched error signature: {pattern.pattern}",
                        ),
                        cvss=8.6,
                        confidence="high",
                        tags=["web", "sqli", "injection"],
                        reproduction=self._reproduction(point, payload),
                        metadata={
                            "parameter": point.parameter,
                            "method": point.method,
                            "technique": "error-based",
                        },
                    )
        return None

    def _sqli_boolean(self, point: InjectionPoint, baseline: _ResponseState) -> Finding | None:
        numeric = bool(point.value.strip()) and point.value.strip().isdigit()
        if numeric:
            pairs = [
                ("1 AND 1=1", "1 AND 1=2"),
                ("1) AND (1=1", "1) AND (1=2"),
            ]
        else:
            pairs = [
                ("' AND '1'='1", "' AND '1'='2"),
                ('" AND "1"="1', '" AND "1"="2'),
                ("') AND ('1'='1", "') AND ('1'='2"),
            ]
        for true_payload, false_payload in pairs[:3]:
            true_result = self._send(point, true_payload)
            false_result = self._send(point, false_payload)
            if (
                true_result is None
                or false_result is None
                or true_result.status is None
                or false_result.status is None
            ):
                continue
            if true_result.status != false_result.status:
                continue
            true_state = _state(true_result)
            false_state = _state(false_result)
            base_ratio = similarity(baseline.normalized, true_state.normalized)
            diff_ratio = similarity(true_state.normalized, false_state.normalized)
            length_delta = abs(true_state.length - false_state.length)
            if base_ratio >= 0.97 and diff_ratio <= 0.90 and length_delta >= 20:
                return Finding(
                    title="SQL injection (boolean-based)",
                    severity=Severity.HIGH,
                    module="web",
                    target=true_result.url or point.url,
                    description=(
                        "Boolean conditions produced materially different responses, indicating "
                        "that the parameter can alter SQL query logic."
                    ),
                    remediation="Use parameterized queries and avoid string concatenation for SQL.",
                    evidence=Evidence(
                        payload=f"{true_payload}  |  {false_payload}",
                        request=self._reproduction(point, true_payload),
                        response_excerpt=(
                            f"True-condition similarity to baseline: {base_ratio:.3f}\n"
                            f"True/false response similarity: {diff_ratio:.3f}\n"
                            f"Response length delta: {length_delta} bytes"
                        ),
                    ),
                    cvss=8.6,
                    confidence="high" if diff_ratio <= 0.80 else "medium",
                    tags=["web", "sqli", "injection"],
                    metadata={
                        "parameter": point.parameter,
                        "method": point.method,
                        "technique": "boolean-based",
                    },
                )
        return None

    def _sqli_time(self, point: InjectionPoint, baseline: _ResponseState) -> Finding | None:
        payloads = [
            "'; SELECT SLEEP(3)-- -",
            "' OR SLEEP(3)-- -",
            "'; SELECT pg_sleep(3)-- -",
            "' WAITFOR DELAY '0:0:3'-- -",
        ][:MAX_TIME_PAYLOADS_SQL]
        return self._time_confirmation(
            point,
            baseline,
            payloads,
            "SQL injection (time-based)",
            "The database delayed its response when a time-delay SQL expression was supplied.",
            "sqli",
            8.6,
        )

    # ------------------------------------------------------------------ command
    def _command_time(self, point: InjectionPoint, baseline: _ResponseState) -> Finding | None:
        payloads = [
            "; sleep 3",
            "| sleep 3",
            "& sleep 3",
            "$(sleep 3)",
            "; timeout /T 3",
            "& ping -n 4 127.0.0.1",
        ][:MAX_TIME_PAYLOADS_CMD]
        return self._time_confirmation(
            point,
            baseline,
            payloads,
            "OS command injection (time-based)",
            (
                "A command that causes a controlled delay produced a delayed response, indicating "
                "that input may reach an OS command."
            ),
            "command-injection",
            9.1,
        )

    def _time_confirmation(
        self,
        point: InjectionPoint,
        baseline: _ResponseState,
        payloads: list[str],
        title: str,
        description: str,
        tag: str,
        cvss: float,
    ) -> Finding | None:
        threshold = max(2.0, baseline.result.elapsed + (SLEEP_SECONDS - 1.2))
        for payload_suffix in payloads:
            payload = f"{point.value}{payload_suffix}"
            result = self._send(point, payload, timeout=max(self.ctx.config.timeout, SLEEP_SECONDS + 4))
            if result is None or result.status is None:
                continue
            if result.elapsed < threshold:
                continue
            confirm = self._send(point, payload, timeout=max(self.ctx.config.timeout, SLEEP_SECONDS + 4))
            if confirm is None or confirm.status is None or confirm.elapsed < threshold:
                continue
            return Finding(
                title=title,
                severity=Severity.CRITICAL if tag == "command-injection" else Severity.HIGH,
                module="web",
                target=result.url or point.url,
                description=description,
                remediation=(
                    "Avoid shell execution for user-controlled values. Use allowlists, fixed "
                    "subcommands, and safe APIs; run services with least privilege."
                ),
                evidence=Evidence(
                    payload=payload,
                    request=self._reproduction(point, payload),
                    notes=(
                        f"Baseline {baseline.result.elapsed:.2f}s; first {result.elapsed:.2f}s; "
                        f"confirmation {confirm.elapsed:.2f}s; threshold {threshold:.2f}s"
                    ),
                ),
                cvss=cvss,
                confidence="high",
                tags=["web", tag, "injection", "time-based"],
                metadata={"parameter": point.parameter, "method": point.method},
            )
        return None

    # ------------------------------------------------------------------ xss
    def _xss(self, point: InjectionPoint) -> Finding | None:
        marker = f"cfx{secrets.token_hex(4)}"
        if marker in self.markings:
            return None
        for template in XSS_PAYLOADS:
            payload = template.format(marker=marker)
            result = self._send(point, payload)
            if result is None or not result.text or payload not in result.text:
                continue
            context = _xss_context(result.text, payload)
            self.markings.add(marker)
            return Finding(
                title="Reflected cross-site scripting (XSS)",
                severity=Severity.MEDIUM,
                module="web",
                target=result.url or point.url,
                description=(
                    "A crafted value was reflected verbatim in the HTML response. The supplied marker "
                    "contains an executable browser construct and can run script in a victim's session."
                ),
                remediation=(
                    "Apply context-aware output encoding, a restrictive Content-Security-Policy, and "
                    "validate/allowlist input. Prefer framework auto-escaping."
                ),
                evidence=Evidence(
                    payload=payload,
                    request=self._reproduction(point, payload),
                    response_excerpt=_marker_excerpt(result.text, marker),
                    notes=f"Reflection context: {context}",
                ),
                cvss=6.1,
                confidence="high" if context.endswith("executable") else "medium",
                tags=["web", "xss", "injection"],
                metadata={
                    "parameter": point.parameter,
                    "method": point.method,
                    "context": context,
                },
            )
        return None

    def dom_flows(self, crawl: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        seen_sources: set[str] = set()
        fetched = 0
        for page in crawl.pages:
            candidates = list(page.inline_scripts)
            for script_url in page.script_urls:
                if fetched >= 8:
                    break
                fetched += 1
                try:
                    result = self.session.get(script_url)
                except RequestBudgetExceeded:
                    self.log.warning("request budget exhausted during DOM analysis")
                    return findings
                except (ScopeViolation, PolicyViolation):
                    continue
                if result.status and result.status == 200 and result.text:
                    candidates.append(result.text)
            for index, script in enumerate(candidates):
                if not script:
                    continue
                source_match = _first_match(script, DOM_SOURCES)
                sink_match = _first_match(script, DOM_SINKS)
                if not source_match or not sink_match:
                    continue
                identity = f"{page.url}|{index}"
                if identity in seen_sources:
                    continue
                seen_sources.add(identity)
                findings.append(
                    Finding(
                        title="Potential DOM-based XSS source-to-sink flow",
                        severity=Severity.INFO,
                        module="web",
                        target=page.url,
                        description=(
                            "Client-side script reads a browser-controllable source and assigns it to "
                            "an HTML/JavaScript sink. This is a static lead; browser execution was not tested."
                        ),
                        remediation=(
                            "Avoid passing untrusted sources to HTML/JavaScript sinks. Use textContent, "
                            "safe templating, URL validation, and a restrictive CSP."
                        ),
                        evidence=Evidence(
                            response_excerpt=truncate(
                                f"Source: {source_match}\nSink: {sink_match}\nSnippet: {_snippet(script, sink_match)}",
                                600,
                            ),
                            notes="Static analysis only; no malicious payload executed.",
                        ),
                        confidence="medium",
                        tags=["web", "xss", "dom", "static-analysis"],
                        metadata={"page": page.url, "script_index": index},
                    )
                )
        self.log.info("DOM analysis: %d potential source/sink flow(s)", len(findings))
        return findings

    def stored_html_injection(self, crawl: CrawlResult) -> list[Finding]:
        if not (self.ctx.config.allow_stored_xss and self.ctx.config.allow_form_submissions):
            return []
        findings: list[Finding] = []
        tested = 0
        for page in crawl.pages:
            for form in page.forms:
                if tested >= 2:
                    return findings
                if form.method != "POST" or form.has_password:
                    continue
                text_fields = [
                    name
                    for name, input_type in form.input_types.items()
                    if input_type in {"text", "search", "url", "email", "textarea"}
                ]
                if not text_fields:
                    continue
                marker = f"cfx{secrets.token_hex(4)}"
                payload = f'<b data-cfx="{marker}">CyberForge marker</b>'
                field = text_fields[0]
                data = dict(form.fields)
                data[field] = payload
                try:
                    result = self.session.post(form.action_url, data=data)
                except (ScopeViolation, PolicyViolation):
                    continue
                except RequestBudgetExceeded:
                    self.log.warning("request budget exhausted during stored-XSS marker test")
                    return findings
                tested += 1
                if result.status is None:
                    continue
                verify = self.session.get(page.url)
                if verify.status and payload in (verify.text or ""):
                    findings.append(
                        Finding(
                            title="Stored HTML injection (benign marker)",
                            severity=Severity.MEDIUM,
                            module="web",
                            target=page.url,
                            description=(
                                "A benign HTML marker submitted through a form was stored and rendered "
                                "without escaping. This demonstrates stored content injection and a likely "
                                "XSS path; no script was executed."
                            ),
                            remediation=(
                                "Escape stored content on output, validate input, and deploy CSP. "
                                "Remove the marker entry created during testing."
                            ),
                            evidence=Evidence(
                                payload=payload,
                                request=format_curl("POST", form.action_url, data=field + "=marker"),
                                response_excerpt=_marker_excerpt(verify.text, marker),
                            ),
                            cvss=5.3,
                            confidence="high",
                            tags=["web", "xss", "stored", "html-injection"],
                            metadata={"parameter": field, "form_action": form.action_url},
                        )
                    )
        return findings


def _state(result: HttpResult) -> _ResponseState:
    normalized = normalize_for_diff(result.text)
    return _ResponseState(result=result, normalized=normalized, length=len(result.text or ""))


def _first_match(script: str, patterns: list[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, script)
        if match:
            return match.group(0)
    return ""


def _snippet(script: str, needle: str, radius: int = 160) -> str:
    index = script.find(needle)
    if index < 0:
        return truncate(script, 300)
    start = max(0, index - radius)
    end = min(len(script), index + len(needle) + radius)
    return re.sub(r"\s+", " ", script[start:end]).strip()


def _xss_context(text: str, payload: str) -> str:
    index = text.find(payload)
    if index < 0:
        return "unknown"
    before = text[:index].lower()
    script_open = before.rfind("<script")
    script_close = before.rfind("</script>")
    if script_open > script_close:
        return "javascript-string (review manually)"
    tag_start = before.rfind("<")
    tag_end = before.rfind(">")
    if tag_start > tag_end:
        return "HTML attribute or tag context (executable)"
    return "HTML body context (executable)"


def _marker_excerpt(text: str, marker: str, limit: int = 500) -> str:
    index = text.find(marker)
    if index < 0:
        return safe_excerpt(text, limit)
    start = max(0, index - 200)
    end = min(len(text), index + 300)
    return safe_excerpt(text[start:end], limit)


def _context_excerpt(text: str, needle: str, limit: int = 500) -> str:
    match = re.search(needle, text, re.IGNORECASE)
    if not match:
        return safe_excerpt(text, limit)
    start = max(0, match.start() - 200)
    end = min(len(text), match.end() + 300)
    return safe_excerpt(text[start:end], limit)
