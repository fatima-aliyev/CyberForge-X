"""Bounded, read-only same-host crawler and injection-point discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import RequestBudgetExceeded, ScopeViolation
from cyberforge.core.session import HttpResult
from cyberforge.core.utils import is_text_content, normalize_url, same_host, truncate

SKIP_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".tar",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".wav",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".css",
    ".js",
    ".map",
    ".exe",
    ".dmg",
    ".iso",
    ".apk",
    ".bin",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pyc",
    ".sql",
}
UNSAFE_TOKENS = {
    "delete",
    "remove",
    "destroy",
    "drop",
    "purge",
    "revoke",
    "deactivate",
    "disable",
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "unsubscribe",
    "terminate",
    "shutdown",
    "restart",
    "reset-password",
    "resetpassword",
    "password-reset",
}
AUTH_PATH_TOKENS = {
    "login",
    "signin",
    "sign-in",
    "sign_in",
    "logon",
    "logout",
    "register",
    "signup",
    "sign-up",
    "password",
    "forgot",
    "reset",
    "checkout",
    "payment",
    "otp",
    "mfa",
}
SENSITIVE_PARAMS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "csrf",
    "csrf_token",
    "csrftoken",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "token",
    "_token",
    "session",
    "sessionid",
    "session_id",
    "captcha",
    "otp",
    "mfa",
    "code",
    "submit",
    "button",
    "file",
    "upload",
    "viewstate",
    "__viewstate",
    "__eventvalidation",
}
SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


@dataclass
class InjectionPoint:
    url: str
    method: str
    parameter: str
    base_params: dict[str, str]
    value: str
    source: str = "url"

    def key(self) -> tuple[str, str, str]:
        return (self.url, self.method.upper(), self.parameter)

    def stable_params(self, value: str) -> dict[str, str]:
        params = dict(self.base_params)
        params[self.parameter] = value
        return params


@dataclass
class FormSpec:
    action_url: str
    method: str
    fields: dict[str, str]
    input_types: dict[str, str]
    page_url: str

    @property
    def has_password(self) -> bool:
        return any(value == "password" for value in self.input_types.values())

    def to_dict(self) -> dict[str, object]:
        return {
            "action_url": self.action_url,
            "method": self.method,
            "fields": dict(self.fields),
            "input_types": dict(self.input_types),
            "page_url": self.page_url,
        }


@dataclass
class Page:
    url: str
    depth: int
    status: int
    links: list[str] = field(default_factory=list)
    forms: list[FormSpec] = field(default_factory=list)
    script_urls: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    title: str = ""


@dataclass
class CrawlResult:
    start_url: str
    pages: list[Page] = field(default_factory=list)
    injection_points: list[InjectionPoint] = field(default_factory=list)
    forms: list[FormSpec] = field(default_factory=list)

    def dedupe_points(self) -> None:
        seen: set[tuple[str, str, str]] = set()
        unique: list[InjectionPoint] = []
        for point in self.injection_points:
            key = point.key()
            if key in seen:
                continue
            seen.add(key)
            unique.append(point)
        self.injection_points = unique


class Crawler:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.max_pages = ctx.config.max_pages
        self.max_depth = ctx.config.crawl_depth
        self.allow_forms = ctx.config.allow_form_submissions
        self.result = CrawlResult(start_url="")

    def crawl(self, start_url: str) -> CrawlResult:
        self.result = CrawlResult(start_url=start_url)
        queue: list[tuple[str, int]] = [(normalize_url(start_url), 0)]
        seen: set[str] = set()
        while queue and len(self.result.pages) < self.max_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if not self._url_allowed(url):
                continue
            self._collect_query_points(url, "url")
            try:
                result = self.ctx.session.get(url)
            except RequestBudgetExceeded:
                self.log.warning("request budget exhausted while crawling")
                break
            except ScopeViolation:
                continue
            if result.status is None:
                self.log.debug("crawl request failed for %s: %s", url, result.error)
                continue
            if result.status >= 400:
                continue
            if not _is_html(result):
                continue
            page = self._parse_page(url, depth, result)
            self.result.pages.append(page)
            self.result.forms.extend(page.forms)
            if depth >= self.max_depth:
                continue
            for link in page.links:
                normalized = normalize_url(link)
                if normalized in seen or not self._url_allowed(normalized):
                    continue
                if _unsafe_url(normalized):
                    continue
                queue.append((normalized, depth + 1))
        self.result.dedupe_points()
        self.log.info(
            "Crawl %s: %d page(s), %d form(s), %d injection point(s)",
            start_url,
            len(self.result.pages),
            len(self.result.forms),
            len(self.result.injection_points),
        )
        return self.result

    # ------------------------------------------------------------------ parsing
    def _parse_page(self, url: str, depth: int, result: HttpResult) -> Page:
        page = Page(url=result.url or url, depth=depth, status=result.status or 0)
        try:
            soup = BeautifulSoup(result.text or "", "html.parser")
        except Exception as exc:
            self.log.debug("HTML parse failed for %s: %s", url, exc)
            return page
        title = soup.title.get_text(strip=True) if soup.title else ""
        page.title = truncate(title, 200)
        for anchor in soup.find_all(["a", "area"]):
            href = anchor.get("href")
            if not href:
                continue
            link = urljoin(page.url, href)
            if not link.lower().startswith(("http://", "https://")):
                continue
            if not same_host(link, page.url):
                continue
            page.links.append(link)
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                script_url = urljoin(page.url, src)
                if script_url.lower().startswith(("http://", "https://")) and same_host(script_url, page.url):
                    page.script_urls.append(script_url)
            elif script.string and len(script.string) < 50000:
                page.inline_scripts.append(script.string)
        if len(page.inline_scripts) < 10:
            inline = SCRIPT_RE.findall(result.text or "")
            for snippet in inline:
                if snippet.strip() and snippet not in page.inline_scripts and len(snippet) < 50000:
                    page.inline_scripts.append(snippet)
        for form in soup.find_all("form"):
            form_spec = self._parse_form(page.url, form)
            if form_spec is None:
                continue
            page.forms.append(form_spec)
            self._collect_form_points(form_spec)
        self._collect_query_points(page.url, "page")
        for link in page.links:
            self._collect_query_points(link, "link")
        return page

    def _parse_form(self, page_url: str, form: BeautifulSoup) -> FormSpec | None:
        action = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        if not action_url.lower().startswith(("http://", "https://")) or not same_host(action_url, page_url):
            return None
        method = (form.get("method") or "GET").upper()
        if method not in {"GET", "POST"}:
            return None
        fields: dict[str, str] = {}
        input_types: dict[str, str] = {}
        for input_node in form.find_all(["input", "textarea", "select"]):
            name = input_node.get("name")
            if not name:
                continue
            if input_node.has_attr("disabled"):
                continue
            input_type = (input_node.get("type") or ("textarea" if input_node.name == "textarea" else "select")).lower()
            if input_type in {"submit", "button", "reset", "image", "file"}:
                continue
            if input_type in {"checkbox", "radio"} and not input_node.has_attr("checked"):
                continue
            value = input_node.get("value") or ""
            if input_node.name == "textarea":
                value = input_node.get_text() or ""
            if input_node.name == "select":
                option = input_node.find("option", selected=True) or input_node.find("option")
                value = option.get("value", option.get_text(strip=True)) if option else ""
            fields[str(name)] = str(value)
            input_types[str(name)] = input_type
        return FormSpec(
            action_url=action_url,
            method=method,
            fields=fields,
            input_types=input_types,
            page_url=page_url,
        )

    def _collect_form_points(self, form: FormSpec) -> None:
        if not self._url_allowed(form.action_url):
            return
        if form.method == "POST" and not self.allow_forms:
            return
        if form.has_password or _auth_url(form.action_url):
            return
        if form.method == "GET":
            parsed = urlsplit(form.action_url)
            merged = dict(parse_qsl(parsed.query, keep_blank_values=True))
            merged.update(form.fields)
            base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            for name, value in form.fields.items():
                if _skip_parameter(name):
                    continue
                self.result.injection_points.append(
                    InjectionPoint(
                        url=base_url,
                        method="GET",
                        parameter=name,
                        base_params=merged,
                        value=value,
                        source=f"form:{form.page_url}",
                    )
                )
        else:
            for name, value in form.fields.items():
                if _skip_parameter(name):
                    continue
                if form.input_types.get(name) in {"checkbox", "radio", "select"}:
                    continue
                self.result.injection_points.append(
                    InjectionPoint(
                        url=form.action_url,
                        method="POST",
                        parameter=name,
                        base_params=dict(form.fields),
                        value=value,
                        source=f"form:{form.page_url}",
                    )
                )

    def _collect_query_points(self, url: str, source: str) -> None:
        if not self._url_allowed(url) or _auth_url(url):
            return
        parsed = urlsplit(url)
        if not parsed.query:
            return
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        for name, value in params.items():
            if _skip_parameter(name):
                continue
            self.result.injection_points.append(
                InjectionPoint(
                    url=base_url,
                    method="GET",
                    parameter=name,
                    base_params=params,
                    value=value,
                    source=source,
                )
            )

    def _url_allowed(self, url: str) -> bool:
        if _unsafe_url(url):
            return False
        path = urlsplit(url).path.lower()
        if any(path.endswith(extension) for extension in SKIP_EXTENSIONS):
            return False
        try:
            self.ctx.scope.assert_url(url)
        except ScopeViolation:
            return False
        return True


def _is_html(result: HttpResult) -> bool:
    content_type = result.content_type.lower()
    if "html" in content_type:
        return True
    if content_type and not is_text_content(content_type):
        return False
    return "<html" in (result.text or "")[:2000].lower()


def _unsafe_url(url: str) -> bool:
    lowered = url.lower()
    if any(token in lowered for token in UNSAFE_TOKENS):
        return True
    return bool(lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "ftp:")))


def _auth_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(token in path for token in AUTH_PATH_TOKENS)


def _skip_parameter(name: str) -> bool:
    lowered = (name or "").lower().strip("[]")
    return lowered in SENSITIVE_PARAMS or lowered.startswith("utm_")


def is_sensitive_point(point: InjectionPoint) -> bool:
    return _skip_parameter(point.parameter) or _auth_url(point.url)
