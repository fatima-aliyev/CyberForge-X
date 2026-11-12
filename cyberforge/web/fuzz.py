"""Calibrated content discovery for sensitive files and exposed paths."""

from __future__ import annotations

import re
import secrets
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from cyberforge.core.context import ModuleContext
from cyberforge.core.exceptions import (
    PolicyViolation,
    RequestBudgetExceeded,
    ScopeViolation,
)
from cyberforge.core.models import Evidence, Finding, Severity
from cyberforge.core.session import HttpResult, SafeSession
from cyberforge.core.utils import (
    format_curl,
    load_lines,
    normalize_for_diff,
    read_package_lines,
    safe_excerpt,
    similarity,
)

BENIGN_PATHS = {
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "humans.txt",
    "ads.txt",
    "manifest.json",
    ".well-known/security.txt",
}
BACKUP_SUFFIXES = (".bak", ".old", ".orig", "~", ".save", ".swp", ".copy", ".1", ".2")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sql")
SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|connection[_-]?string|database_url|smtp|aws_|azure_|gcp_)"
)
ENV_LINE_RE = re.compile(r"^([A-Z0-9_]{2,})=", re.MULTILINE)
SQL_DUMP_RE = re.compile(r"(?i)(insert\s+into|create\s+table|mysql dump|pg_dump|sql dump)")
DIRECTORY_LISTING_RE = re.compile(r"(?i)<title>\s*index of /|directory listing for")
SWAGGER_HINTS = ("swagger", "openapi", "api-docs", "api_docs", "/docs", "graphql")


@dataclass
class SensitiveHit:
    severity: Severity
    title: str
    description: str
    remediation: str
    cvss: float | None
    evidence: str
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class FuzzResult:
    url: str
    status: int
    length: int
    content_type: str
    redirect: str = ""
    sensitive: SensitiveHit | None = None
    request: str = ""


@dataclass
class _Baseline:
    status: int | None = None
    text: str = ""
    length: int = 0


class PathFuzzer:
    def __init__(self, ctx: ModuleContext, session: SafeSession | None = None) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.session = session or ctx.session
        self._baselines: dict[str, _Baseline] = {}

    def default_paths(self) -> list[str]:
        paths = read_package_lines("wordlists", "web_paths.txt")
        if self.ctx.config.web_wordlist:
            paths.extend(load_lines(self.ctx.config.web_wordlist))
        return _dedupe(paths)

    def calibrate(self, origin: str) -> _Baseline:
        cached = self._baselines.get(origin)
        if cached:
            return cached
        baseline = _Baseline()
        samples: list[HttpResult] = []
        for _ in range(2):
            token = f"cfx-{secrets.token_hex(8)}.txt"
            probe = urljoin(origin.rstrip("/") + "/", token)
            try:
                result = self.session.get(probe)
            except RequestBudgetExceeded:
                raise
            except (ScopeViolation, PolicyViolation):
                continue
            samples.append(result)
            if result.status == 200:
                baseline.status = 200
                baseline.text = normalize_for_diff(result.text)
                baseline.length = len(result.text or "")
                break
        self._baselines[origin] = baseline
        return baseline

    def scan(self, base_url: str, paths: list[str] | None = None) -> list[FuzzResult]:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"}:
            return []
        origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        path_list = _dedupe(paths if paths is not None else self.default_paths())[:500]
        try:
            baseline = self.calibrate(origin)
        except RequestBudgetExceeded:
            self.log.warning("request budget exhausted during soft-404 calibration")
            return []
        results: list[FuzzResult] = []
        candidates = [(path, _build_url(origin, path)) for path in path_list]
        candidates = [(path, url) for path, url in candidates if url is not None]
        if not candidates:
            return []
        workers = max(1, min(self.ctx.config.workers, 12))
        stop = threading.Event()
        budget_hit = False
        futures: dict[Future[FuzzResult | None], tuple[str, str]] = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cfx-fuzz") as pool:
            iterator = iter(candidates)
            for _ in range(workers * 2):
                if stop.is_set():
                    break
                item = next(iterator, None)
                if item is None:
                    break
                path, url = item
                futures[pool.submit(self._probe, origin, path, url, baseline)] = item
            while futures:
                done, _ = wait(list(futures), return_when=FIRST_COMPLETED)
                for future in done:
                    _path, url = futures.pop(future)
                    try:
                        result = future.result()
                    except RequestBudgetExceeded:
                        stop.set()
                        if not budget_hit:
                            budget_hit = True
                            self.log.warning("request budget exhausted during content discovery")
                        continue
                    except (ScopeViolation, PolicyViolation):
                        continue
                    except Exception as exc:
                        self.log.debug("fuzz probe failed for %s: %s", url, exc)
                        continue
                    if result is not None:
                        results.append(result)
                    if stop.is_set():
                        continue
                    item = next(iterator, None)
                    if item is not None:
                        path, url = item
                        futures[pool.submit(self._probe, origin, path, url, baseline)] = item
            if stop.is_set():
                for future in futures:
                    future.cancel()
        self.log.info("Content discovery %s: %d interesting response(s)", origin, len(results))
        return results

    def _probe(self, origin: str, path: str, url: str, baseline: _Baseline) -> FuzzResult | None:
        try:
            result = self.session.get(url)
        except (ScopeViolation, PolicyViolation):
            return None
        if result.status is None:
            return None
        text = result.text or ""
        soft_404 = False
        if (
            baseline.status == 200
            and result.status == 200
            and similarity(_safe_diff(text), baseline.text) >= 0.985
        ):
            soft_404 = True
        if result.status in {404, 410} or soft_404:
            return None
        if result.status >= 500:
            return None
        normalized_path = urlsplit(url).path.strip("/").lower()
        if normalized_path in BENIGN_PATHS:
            return None
        if any(hint in normalized_path for hint in SWAGGER_HINTS):
            return None
        final_path = urlsplit(result.url or url).path.strip("/").lower()
        hit = self._classify(url, normalized_path, result) if final_path == normalized_path else None
        redirect = result.header("Location")
        return FuzzResult(
            url=result.url or url,
            status=result.status,
            length=len(text),
            content_type=result.content_type,
            redirect=redirect,
            sensitive=hit,
            request=format_curl("GET", url, result.request_headers),
        )

    def _classify(self, url: str, path: str, result: HttpResult) -> SensitiveHit | None:
        status = result.status or 0
        text = result.text or ""
        low_path = path
        if status in {401, 403}:
            return None
        if result.header("WWW-Authenticate"):
            return None
        if any(low_path.endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
            if low_path.endswith(".sql") and SQL_DUMP_RE.search(text):
                return SensitiveHit(
                    Severity.HIGH,
                    "Database dump exposed",
                    "A downloadable file appears to contain a database dump. It was not downloaded or reproduced.",
                    "Remove the dump from the web root and rotate any credentials or data referenced by it.",
                    7.5,
                    "Response contained SQL dump markers (CREATE TABLE/INSERT INTO); content intentionally not reproduced.",
                    ["exposure", "database", "sensitive-file"],
                )
            raw = result.raw[:16]
            archive = raw.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!"))
            if archive or "zip" in result.content_type or "octet-stream" in result.content_type:
                return SensitiveHit(
                    Severity.MEDIUM,
                    "Archive file exposed",
                    "An archive file is directly downloadable from the web server.",
                    "Remove backup archives from the web root and block access to archive extensions.",
                    5.3,
                    f"Downloadable archive: {url} (HTTP {status}, {len(result.raw)} bytes inspected).",
                    ["exposure", "backup"],
                )
        if low_path.endswith(".env") or "/.env" in low_path:
            keys = ENV_LINE_RE.findall(text)
            if keys:
                listed = ", ".join(keys[:20])
                return SensitiveHit(
                    Severity.HIGH,
                    "Environment file exposed",
                    "An .env file is readable. Environment files commonly contain database and API credentials.",
                    "Remove the file from the web root, rotate all exposed secrets, and restrict dotfile access.",
                    7.5,
                    f"Exposed variable names (values not reproduced): {listed}",
                    ["exposure", "secrets", "sensitive-file"],
                )
        if ".git/config" in low_path or low_path.endswith(".git/head"):
            return SensitiveHit(
                Severity.HIGH,
                "Git repository metadata exposed",
                "Git metadata is reachable over HTTP, which can permit source-code reconstruction.",
                "Block access to .git directories and remove repository metadata from deployment artifacts.",
                7.5,
                safe_excerpt(text, 300),
                ["exposure", "source-code", "sensitive-file"],
            )
        if (
            low_path.endswith("phpinfo.php") or low_path.endswith("info.php")
        ) and ("phpinfo()" in text or "PHP Version" in text):
            return SensitiveHit(
                    Severity.MEDIUM,
                    "PHP information page exposed",
                    "phpinfo() discloses server paths, configuration, and module details.",
                    "Remove the information page from production.",
                    5.3,
                    "Response contains phpinfo() configuration output.",
                    ["exposure", "php"],
                )
        if low_path.endswith(("server-status", "server-info")) and (
            "Apache Server Status" in text or "Server Settings" in text
        ):
            return SensitiveHit(
                    Severity.MEDIUM,
                    "Apache status page exposed",
                    "Apache server-status/server-info is publicly reachable.",
                    "Restrict these handlers to localhost or authorized operators.",
                    5.3,
                    "Response contains Apache status output.",
                    ["exposure", "apache"],
                )
        if low_path.endswith(".ds_store"):
            return SensitiveHit(
                Severity.LOW,
                "macOS metadata file exposed",
                "A .DS_Store file is downloadable and may reveal directory or file names.",
                "Remove .DS_Store from deployments and block dotfiles.",
                3.7,
                "Response returned a .DS_Store file.",
                ["exposure"],
            )
        if DIRECTORY_LISTING_RE.search(text):
            return SensitiveHit(
                Severity.MEDIUM,
                "Directory listing enabled",
                "The server returns a directory index that reveals stored files.",
                "Disable directory listing and add explicit index files.",
                5.3,
                safe_excerpt(text, 250),
                ["exposure", "directory-listing"],
            )
        if low_path.endswith((".bak", ".old", ".orig", "~", ".save", ".swp", ".copy", ".1", ".2")):
            return SensitiveHit(
                Severity.MEDIUM,
                "Backup file exposed",
                "A backup copy of an application file is directly downloadable.",
                "Remove backup files from the web root and block backup extensions.",
                5.3,
                f"Backup file reachable: {url} (HTTP {status}, {len(text)} bytes text inspected).",
                ["exposure", "backup"],
            )
        if low_path.endswith(("web.config", "application.properties", "application.yml", "appsettings.json", ".ini")):
            suspicious = SECRET_KEY_RE.findall(text[:20000])
            if suspicious:
                names = sorted({name.lower() for name in suspicious})[:15]
                return SensitiveHit(
                    Severity.HIGH,
                    "Configuration file with secret references exposed",
                    "A server configuration file is readable and contains secret-related keys.",
                    "Remove the file from the web root and rotate referenced credentials.",
                    7.5,
                    f"Secret-related keys observed (values redacted): {', '.join(names)}",
                    ["exposure", "configuration", "secrets"],
                )
            return SensitiveHit(
                Severity.LOW,
                "Configuration file exposed",
                "A server configuration file is readable over HTTP.",
                "Serve only required static files and block configuration extensions.",
                3.7,
                f"Configuration file reachable: {url}",
                ["exposure", "configuration"],
            )
        if low_path.endswith(("composer.json", "package.json", "requirements.txt", "gemfile.lock")):
            return SensitiveHit(
                Severity.INFO,
                "Dependency manifest exposed",
                "A dependency manifest is readable and may aid version fingerprinting.",
                "Block build manifests from production web roots.",
                None,
                f"Dependency manifest reachable: {url}",
                ["exposure", "fingerprinting"],
            )
        return None

    def findings(self, base_url: str, results: list[FuzzResult], module: str = "web") -> list[Finding]:
        findings: list[Finding] = []
        generic: list[str] = []
        protected: list[str] = []
        for item in results:
            if item.sensitive:
                hit = item.sensitive
                findings.append(
                    Finding(
                        title=hit.title,
                        severity=hit.severity,
                        module=module,
                        target=item.url,
                        description=hit.description,
                        remediation=hit.remediation,
                        evidence=Evidence(
                            request=item.request,
                            response_excerpt=hit.evidence,
                            notes=f"HTTP {item.status}; content-type {item.content_type or 'unknown'}",
                        ),
                        cvss=hit.cvss,
                        confidence="high" if hit.severity.rank >= Severity.MEDIUM.rank else "medium",
                        tags=["web", "fuzzing", *hit.tags],
                        reproduction=item.request,
                        metadata={
                            "path": urlsplit(item.url).path,
                            "status": item.status,
                            "length": item.length,
                        },
                    )
                )
            elif item.status in {401, 403}:
                protected.append(f"{item.status} {urlsplit(item.url).path} ({item.length} bytes)")
            elif item.status in {200, 201, 202, 204, 301, 302, 307, 308}:
                generic.append(f"{item.status} {urlsplit(item.url).path} ({item.length} bytes)")
        if generic or protected:
            lines: list[str] = []
            if generic:
                lines.append("Accessible paths:")
                lines.extend(f"  {line}" for line in _dedupe(generic)[:50])
            if protected:
                lines.append("Protected paths (authentication/authorization required):")
                lines.extend(f"  {line}" for line in _dedupe(protected)[:50])
            findings.append(
                Finding(
                    title="Web paths and protected areas discovered",
                    severity=Severity.INFO,
                    module=module,
                    target=base_url,
                    description=(
                        "Content discovery identified reachable and protected paths. These are mapping "
                        "results, not confirmed vulnerabilities; protected paths are useful only for "
                        "authorized follow-up."
                    ),
                    remediation="Review exposed paths and remove content not intended for public access.",
                    evidence=Evidence(
                        request=format_curl("GET", base_url),
                        response_excerpt="\n".join(lines),
                    ),
                    confidence="high",
                    tags=["web", "discovery", "mapping"],
                    metadata={"accessible": len(generic), "protected": len(protected)},
                )
            )
        return findings


def backup_variants(seeds: list[str]) -> list[str]:
    variants: list[str] = []
    for seed in seeds:
        cleaned = seed.strip().lstrip("/")
        if not cleaned:
            continue
        variants.append(cleaned)
        for suffix in BACKUP_SUFFIXES:
            variants.append(cleaned + suffix)
        if "." in cleaned:
            stem = cleaned.rsplit(".", 1)[0]
            variants.extend([f"{stem}.zip", f"{stem}.tar.gz", f"{stem}.sql"])
        else:
            variants.extend([f"{cleaned}.zip", f"{cleaned}.tar.gz", f"{cleaned}/backup.zip"])
    return _dedupe(variants)


def _build_url(origin: str, path: str) -> str | None:
    candidate = path.strip()
    if not candidate:
        return None
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"}:
            return None
        return candidate
    url = urljoin(origin.rstrip("/") + "/", candidate.lstrip("/"))
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return url


def _safe_diff(text: str) -> str:
    return normalize_for_diff(text)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
