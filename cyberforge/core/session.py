"""Scope-enforcing, rate-limited HTTP session with manual redirect following."""

from __future__ import annotations

import threading
import time
import warnings
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cyberforge.core.exceptions import PolicyViolation, ScopeViolation
from cyberforge.core.guard import RequestPolicy
from cyberforge.core.logging import get_logger
from cyberforge.core.rate_limit import RateLimiter, RequestBudget
from cyberforge.core.scope import Scope
from cyberforge.core.utils import (
    get_header,
    is_text_content,
    redact_sensitive_text,
    safe_excerpt,
    sanitize_headers,
    sanitize_url,
    utc_now_iso,
)

MAX_RESPONSE_BYTES = 2_000_000
REDIRECT_CODES = {301, 302, 303, 307, 308}
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


@dataclass
class HttpResult:
    requested_url: str
    url: str
    method: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    raw: bytes = b""
    elapsed: float = 0.0
    error: str | None = None
    history: list[int] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return get_header(self.headers, "Content-Type")

    def header(self, name: str, default: str = "") -> str:
        return get_header(self.headers, name, default)

    def json(self) -> Any | None:
        import json

        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None

    def excerpt(self, limit: int = 800) -> str:
        return safe_excerpt(self.text, limit)


class SafeSession:
    def __init__(
        self,
        scope: Scope,
        limiter: RateLimiter,
        budget: RequestBudget,
        timeout: float = 10.0,
        connect_timeout: float = 3.0,
        verify: bool = True,
        proxy: str = "",
        user_agent: str = "CyberForge-X/1.0 (authorized-security-assessment)",
        extra_headers: dict[str, str] | None = None,
        policy: RequestPolicy | None = None,
        max_body: int = MAX_RESPONSE_BYTES,
        max_redirects: int = 5,
        logger_name: str = "http",
    ) -> None:
        self.scope = scope
        self.limiter = limiter
        self.budget = budget
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.verify = verify
        self.proxy = proxy
        self.user_agent = user_agent
        self.extra_headers = dict(extra_headers or {})
        self.policy = policy or RequestPolicy()
        self.max_body = max_body
        self.max_redirects = max_redirects
        self.log = get_logger(logger_name)
        self.session = requests.Session()
        self.session.max_redirects = max_redirects
        self.session.headers.clear()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.8",
                "Connection": "close",
            }
        )
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            status=0,
            backoff_factor=0.4,
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=32)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        self._stats_lock = threading.Lock()
        self._stats: dict[str, Any] = {
            "requests": 0,
            "errors": 0,
            "bytes": 0,
            "by_method": {},
            "by_host": {},
            "status_codes": {},
            "started_at": utc_now_iso(),
        }

    # ------------------------------------------------------------------ requests
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | list[tuple[str, Any]] | None = None,
        data: dict[str, Any] | list[tuple[str, Any]] | str | bytes | None = None,
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
        auth: Any | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        timeout: float | None = None,
    ) -> HttpResult:
        method = method.upper()
        self.policy.check(method)
        self.scope.assert_url(url)

        current_url = url
        current_method = method
        current_data = data
        current_json = json_body
        history: list[int] = []
        request_headers = self._merge_headers(headers, url)
        redirects_left = self.max_redirects if allow_redirects else 0

        while True:
            self.policy.check(current_method)
            self.scope.assert_url(current_url)
            self.budget.consume()
            self.limiter.acquire()
            start = time.monotonic()
            response: requests.Response | None = None
            try:
                response = self.session.request(
                    current_method,
                    current_url,
                    params=params if not history else None,
                    data=current_data,
                    json=current_json,
                    headers=request_headers,
                    auth=auth,
                    cookies=cookies,
                    allow_redirects=False,
                    timeout=(self.connect_timeout, timeout or self.timeout),
                    verify=self.verify,
                    proxies=self.proxies,
                    stream=True,
                )
                elapsed = time.monotonic() - start

                if (
                    response.status_code in REDIRECT_CODES
                    and redirects_left > 0
                    and response.headers.get("Location")
                ):
                    location = response.headers.get("Location", "")
                    next_url = urljoin(response.url, location)
                    history.append(response.status_code)
                    previous_host = (urlsplit(response.url).hostname or "").lower()
                    next_host = (urlsplit(next_url).hostname or "").lower()
                    if next_host and next_host != previous_host:
                        request_headers = {
                            key: value
                            for key, value in request_headers.items()
                            if key.lower() not in SENSITIVE_HEADERS
                        }
                    response.close()
                    if response.status_code == 303 or (
                        response.status_code in {301, 302} and current_method not in {"GET", "HEAD"}
                    ):
                        current_method = "GET"
                        current_data = None
                        current_json = None
                    current_url = next_url
                    redirects_left -= 1
                    self.log.debug(
                        "redirect %s -> %s (%s)", response.status_code, sanitize_url(current_url), history
                    )
                    continue

                text, truncated, raw = self._read_limited(response)
                result = HttpResult(
                    requested_url=url,
                    url=response.url,
                    method=method,
                    status=response.status_code,
                    headers=dict(response.headers),
                    text=text,
                    raw=raw,
                    elapsed=elapsed,
                    history=history,
                    request_headers=sanitize_headers(request_headers),
                    truncated=truncated,
                )
                self._record(result, len(text), response.headers.get("Content-Type", ""))
                self.log.debug(
                    "HTTP %s %s -> %s (%.2fs%s)",
                    method,
                    sanitize_url(url),
                    response.status_code,
                    elapsed,
                    ", truncated" if truncated else "",
                )
                response.close()
                return result
            except (ScopeViolation, PolicyViolation):
                if response is not None:
                    response.close()
                raise
            except requests.RequestException as exc:
                elapsed = time.monotonic() - start
                error = redact_sensitive_text(str(exc), limit=300)
                self._record_error(url, method)
                self.log.debug("HTTP %s %s failed: %s", method, sanitize_url(url), error)
                if response is not None:
                    response.close()
                return HttpResult(
                    requested_url=url,
                    url=current_url,
                    method=method,
                    status=None,
                    elapsed=elapsed,
                    error=error,
                    history=history,
                    request_headers=sanitize_headers(request_headers),
                )
            except Exception as exc:  # defensive: never leak an unexpected parser error as success
                if response is not None:
                    response.close()
                self._record_error(url, method)
                error = f"{type(exc).__name__}: {redact_sensitive_text(str(exc), limit=300)}"
                self.log.debug("HTTP %s %s unexpected failure: %s", method, sanitize_url(url), error)
                return HttpResult(
                    requested_url=url,
                    url=current_url,
                    method=method,
                    status=None,
                    elapsed=time.monotonic() - start,
                    error=error,
                    history=history,
                    request_headers=sanitize_headers(request_headers),
                )

    def get(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("POST", url, **kwargs)

    # ------------------------------------------------------------------ helpers
    def _merge_headers(self, headers: dict[str, str] | None, url: str) -> dict[str, str]:
        merged = {"User-Agent": self.user_agent, "Accept": "*/*", "Connection": "close"}
        merged.update(self.extra_headers)
        if headers:
            merged.update(headers)
        if self.extra_headers.get("Host") and "Host" not in (headers or {}):
            merged["Host"] = self.extra_headers["Host"]
        if self.verify is False:
            self.log.debug("TLS verification disabled for %s", sanitize_url(url))
        return merged

    def _read_limited(self, response: requests.Response) -> tuple[str, bool, bytes]:
        content_type = response.headers.get("Content-Type", "")
        truncated = False
        limit = 131072 if not is_text_content(content_type) else self.max_body
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= limit:
                    truncated = True
                    break
        except requests.RequestException as exc:
            truncated = True
            self.log.debug("response read interrupted: %s", redact_sensitive_text(str(exc), 200))
        raw = b"".join(chunks)[:limit]
        if not is_text_content(content_type):
            return raw[:65536].decode("utf-8", errors="replace"), truncated, raw
        encoding = response.encoding
        if not encoding:
            try:
                encoding = requests.utils.get_encoding_from_headers(response.headers)
            except Exception:
                encoding = None
        if not encoding:
            encoding = "utf-8"
        try:
            text = raw.decode(encoding, errors="replace")
        except (LookupError, UnicodeError):
            text = raw.decode("utf-8", errors="replace")
        return text, truncated, raw

    def _record(self, result: HttpResult, byte_count: int, content_type: str) -> None:
        host = (urlsplit(result.url).hostname or "").lower()
        with self._stats_lock:
            self._stats["requests"] += 1
            self._stats["bytes"] += byte_count
            self._stats["by_method"][result.method] = self._stats["by_method"].get(result.method, 0) + 1
            self._stats["by_host"][host] = self._stats["by_host"].get(host, 0) + 1
            if result.status is not None:
                code = str(result.status)
                self._stats["status_codes"][code] = self._stats["status_codes"].get(code, 0) + 1

    def _record_error(self, url: str, method: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        with self._stats_lock:
            self._stats["requests"] += 1
            self._stats["errors"] += 1
            self._stats["by_method"][method] = self._stats["by_method"].get(method, 0) + 1
            self._stats["by_host"][host] = self._stats["by_host"].get(host, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        with self._stats_lock:
            return {
                "requests": self._stats["requests"],
                "errors": self._stats["errors"],
                "bytes": self._stats["bytes"],
                "by_method": dict(self._stats["by_method"]),
                "by_host": dict(self._stats["by_host"]),
                "status_codes": dict(self._stats["status_codes"]),
                "budget_used": self.budget.used,
                "budget_remaining": self.budget.remaining,
            }

    def clone(
        self,
        *,
        extra_headers: dict[str, str] | None = None,
        clear_cookies: bool = False,
        logger_name: str | None = None,
    ) -> SafeSession:
        clone = SafeSession(
            scope=self.scope,
            limiter=self.limiter,
            budget=self.budget,
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
            verify=self.verify,
            proxy=self.proxy,
            user_agent=self.user_agent,
            extra_headers={**self.extra_headers, **(extra_headers or {})},
            policy=self.policy,
            max_body=self.max_body,
            max_redirects=self.max_redirects,
            logger_name=logger_name or "http",
        )
        if not clear_cookies:
            clone.session.cookies.update(self.session.cookies)
        return clone

    def close(self) -> None:
        self.session.close()
