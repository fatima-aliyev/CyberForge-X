"""Local CVE seed matching plus NVD 2.0 and EPSS enrichment."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from cyberforge.core.logging import get_logger
from cyberforge.core.models import Evidence, Finding, Severity
from cyberforge.core.utils import safe_json_loads, truncate, utc_now_iso
from cyberforge.intel.banner import ProductVersion
from cyberforge.intel.versioning import (
    describe_constraints,
    match_product_aliases,
    parse_version,
    version_matches,
)

log = get_logger("intel.cve")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_CACHE_TTL = 7 * 24 * 3600
EPSS_CACHE_TTL = 24 * 3600


@dataclass
class Vulnerability:
    cve: str
    title: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    cvss: float | None = None
    severity: Severity | None = None
    source: str = "curated-local-db"
    confidence: str = "medium"
    affected: str = ""
    product: str = ""
    version: str = ""
    published: str = ""
    epss: float | None = None
    epss_percentile: float | None = None


class LocalVulnDB:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = (
            Path(path)
            if path
            else Path(__file__).resolve().parent / "data" / "vulndb.json"
        )
        self.records: list[dict[str, Any]] = []
        self.load_error = ""
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            records = data.get("records", [])
            if not isinstance(records, list):
                raise ValueError("records must be a list")
            self.records = [record for record in records if self._valid(record)]
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.load_error = str(exc)
            log.warning("offline vulnerability database unavailable: %s", exc)

    @staticmethod
    def _valid(record: dict[str, Any]) -> bool:
        return all(key in record for key in ("product", "cve", "constraints", "title"))

    def lookup(self, product: str, version: str) -> list[Vulnerability]:
        if not product or not version:
            return []
        parsed = parse_version(version)
        if parsed is None:
            return []
        results: list[Vulnerability] = []
        for record in self.records:
            aliases = [record.get("product", ""), *record.get("aliases", [])]
            if match_product_aliases(product, aliases) == 0:
                continue
            constraints = record.get("constraints") or []
            if not version_matches(parsed, constraints):
                continue
            results.append(
                Vulnerability(
                    cve=record["cve"],
                    title=record.get("title", record["cve"]),
                    description=record.get("description", ""),
                    remediation=record.get("remediation", "Apply the vendor security update."),
                    references=list(record.get("references", [])),
                    cvss=float(record["cvss"]) if record.get("cvss") is not None else None,
                    severity=_severity_from_name(record.get("severity")),
                    source="curated-local-db",
                    confidence="high" if any("eq" in constraint for constraint in constraints) else "medium",
                    affected=describe_constraints(constraints),
                    product=record.get("product", product),
                    version=version,
                )
            )
        return sorted(results, key=lambda item: (-(item.cvss or 0), item.cve))

    def record_count(self) -> int:
        return len(self.records)


class NVDClient:
    def __init__(
        self,
        cache_dir: Path,
        api_key: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "CyberForge-X/1.0 (authorized security assessment; NVD enrichment)",
                "Accept": "application/json",
            }
        )
        self._lock = threading.Lock()
        self._last_request = 0.0

    def search(self, keyword: str, version: str, limit: int = 10) -> list[Vulnerability]:
        query = f"{keyword} {version}".strip()
        cache_key = hashlib.sha256(f"{query}|{limit}".encode()).hexdigest()[:20]
        cached = self._read_cache(cache_key, NVD_CACHE_TTL)
        if cached is not None:
            return self._parse(cached, keyword, version)[:limit]
        self._throttle()
        log.info("Querying NVD for %r", query)
        try:
            response = self.session.get(
                NVD_URL,
                params={"keywordSearch": query, "resultsPerPage": max(1, min(limit, 20))},
                timeout=self.timeout,
                headers={"apiKey": self.api_key} if self.api_key else None,
            )
        except requests.RequestException as exc:
            log.warning("NVD query failed for %r: %s", query, exc)
            return []
        if response.status_code == 403:
            log.warning("NVD rate limit or API-key rejection (HTTP 403)")
            return []
        if response.status_code != 200:
            log.warning("NVD query returned HTTP %s for %r", response.status_code, query)
            return []
        data = safe_json_loads(response.text)
        if not isinstance(data, dict):
            log.warning("NVD returned an unparseable response for %r", query)
            return []
        self._write_cache(cache_key, data)
        return self._parse(data, keyword, version)[:limit]

    def _throttle(self) -> None:
        interval = 0.8 if self.api_key else 6.5
        with self._lock:
            wait = self._last_request + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait + random.uniform(0, 0.4))
            self._last_request = time.monotonic()

    def _parse(self, data: dict[str, Any], keyword: str, version: str) -> list[Vulnerability]:
        results: list[Vulnerability] = []
        token_set = {token for token in _product_tokens(keyword) if len(token) > 2}
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve") or {}
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions") or []
            description = next(
                (entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"),
                descriptions[0].get("value", "") if descriptions else "",
            )
            lowered = description.lower()
            if token_set and not any(token in lowered for token in token_set):
                continue
            if not _nvd_version_applicable(cve, version):
                continue
            cvss, severity = _nvd_metrics(cve)
            title = description.split(".", 1)[0][:180] or cve_id
            results.append(
                Vulnerability(
                    cve=cve_id,
                    title=title,
                    description=description,
                    remediation=(
                        "Apply the vendor security update for the affected product line. "
                        "Validate the installed version against the NVD CPE ranges and vendor advisory "
                        "before treating this keyword match as confirmed."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                    cvss=cvss,
                    severity=severity,
                    source="nvd-keyword",
                    confidence="low",
                    affected=_nvd_affected_summary(cve),
                    product=keyword,
                    version=version,
                    published=cve.get("published", ""),
                )
            )
        results.sort(key=lambda item: (-(item.cvss or 0), item.cve))
        return results

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"nvd_{key}.json"

    def _read_cache(self, key: str, ttl: float) -> dict[str, Any] | None:
        path = self._cache_path(key)
        try:
            if path.is_file() and time.time() - path.stat().st_mtime < ttl:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None
        return None

    def _write_cache(self, key: str, data: dict[str, Any]) -> None:
        with contextlib.suppress(OSError):
            self._cache_path(key).write_text(json.dumps(data), encoding="utf-8")


class EPSSClient:
    def __init__(self, cache_dir: Path, timeout: float = 20.0) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberForge-X/1.0 (EPSS enrichment)"})

    def lookup(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        wanted = sorted({cve.upper() for cve in cve_ids if cve.upper().startswith("CVE-")})
        if not wanted:
            return {}
        results: dict[str, tuple[float, float]] = {}
        for batch_start in range(0, len(wanted), 100):
            batch = wanted[batch_start : batch_start + 100]
            cache_key = hashlib.sha256(",".join(batch).encode()).hexdigest()[:20]
            cached = self._read_cache(cache_key)
            if cached is not None:
                results.update(cached)
                continue
            try:
                response = self.session.get(
                    EPSS_URL,
                    params={"cve": ",".join(batch), "limit": len(batch)},
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                log.debug("EPSS query failed: %s", exc)
                continue
            if response.status_code != 200:
                log.debug("EPSS returned HTTP %s", response.status_code)
                continue
            data = safe_json_loads(response.text)
            if not isinstance(data, dict):
                continue
            parsed: dict[str, tuple[float, float]] = {}
            for entry in data.get("data", []):
                try:
                    parsed[str(entry["cve"]).upper()] = (float(entry["epss"]), float(entry["percentile"]))
                except (KeyError, TypeError, ValueError):
                    continue
            results.update(parsed)
            self._write_cache(cache_key, parsed)
        return results

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"epss_{key}.json"

    def _read_cache(self, key: str) -> dict[str, tuple[float, float]] | None:
        path = self._cache_path(key)
        try:
            if path.is_file() and time.time() - path.stat().st_mtime < EPSS_CACHE_TTL:
                data = json.loads(path.read_text(encoding="utf-8"))
                return {str(k): (float(v[0]), float(v[1])) for k, v in data.items()}
        except (OSError, ValueError, TypeError):
            return None
        return None

    def _write_cache(self, key: str, data: dict[str, tuple[float, float]]) -> None:
        with contextlib.suppress(OSError):
            self._cache_path(key).write_text(json.dumps(data), encoding="utf-8")


def default_cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "cyberforge" / "intel"
    return Path.home() / ".cache" / "cyberforge" / "intel"


def vulnerability_to_finding(
    vuln: Vulnerability,
    product_version: ProductVersion,
    target: str,
) -> Finding:
    if vuln.cvss is not None:
        severity = Severity.from_cvss(vuln.cvss)
    elif vuln.severity is not None:
        severity = vuln.severity
    else:
        severity = Severity.MEDIUM
    epss_note = ""
    if vuln.epss is not None:
        epss_note = f" EPSS probability: {vuln.epss:.3f} (percentile {vuln.epss_percentile or 0:.1f}%)."
    description = (
        f"{vuln.description}\n\n"
        f"Detection source: {vuln.source}. Detected software: {product_version.product} "
        f"{product_version.version}. Affected range: {vuln.affected or 'see references'}. "
        f"Confidence: {vuln.confidence}.{epss_note}"
    )
    evidence = Evidence(
        payload=f"{product_version.product} {product_version.version}",
        notes=f"{product_version.source}; version detection is banner-based and may be inaccurate",
        response_excerpt=truncate(product_version.banner, 700),
    )
    metadata: dict[str, Any] = {
        "product": product_version.product,
        "version": product_version.version,
        "source": vuln.source,
        "affected": vuln.affected,
        "epss": vuln.epss,
        "epss_percentile": vuln.epss_percentile,
        "published": vuln.published,
        "detected_at": utc_now_iso(),
    }
    return Finding(
        title=f"{vuln.cve}: {vuln.title}",
        severity=severity,
        module="intel",
        target=target,
        description=description,
        remediation=vuln.remediation,
        evidence=evidence,
        cvss=vuln.cvss,
        cve_ids=[vuln.cve],
        references=vuln.references,
        confidence=vuln.confidence,
        tags=["cve", "vulnerability-intel", vuln.source],
        metadata=metadata,
    )


def _severity_from_name(value: Any) -> Severity | None:
    if not value:
        return None
    try:
        return Severity(str(value).lower())
    except ValueError:
        return None


def _product_tokens(product: str) -> set[str]:
    import re

    return set(re.findall(r"[a-z0-9]+", (product or "").lower()))


def _nvd_metrics(cve: dict[str, Any]) -> tuple[float | None, Severity | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
        cvss_data = primary.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity_name = primary.get("baseSeverity") or cvss_data.get("baseSeverity")
        try:
            score_value = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_value = None
        return score_value, _severity_from_name(severity_name)
    return None, None


def _nvd_version_applicable(cve: dict[str, Any], version: str) -> bool:
    parsed = parse_version(version)
    if parsed is None:
        return True
    seen_constraint = False
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                bounds = [
                    match.get("versionStartIncluding"),
                    match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"),
                    match.get("versionEndExcluding"),
                ]
                if not any(bounds):
                    continue
                seen_constraint = True
                if _version_within_bounds(parsed, match):
                    return True
    return not seen_constraint


def _version_within_bounds(parsed: Any, match: dict[str, Any]) -> bool:
    from cyberforge.intel.versioning import compare_versions

    try:
        start_including = parse_version(match.get("versionStartIncluding"))
        start_excluding = parse_version(match.get("versionStartExcluding"))
        end_including = parse_version(match.get("versionEndIncluding"))
        end_excluding = parse_version(match.get("versionEndExcluding"))
        if start_including is not None and compare_versions(parsed, start_including) < 0:
            return False
        if start_excluding is not None and compare_versions(parsed, start_excluding) <= 0:
            return False
        if end_including is not None and compare_versions(parsed, end_including) > 0:
            return False
        if end_excluding is not None and compare_versions(parsed, end_excluding) >= 0:
            return False
    except ValueError:
        return True
    return True


def _nvd_affected_summary(cve: dict[str, Any]) -> str:
    values: list[str] = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                criteria = str(match.get("criteria", ""))
                start = match.get("versionStartIncluding") or match.get("versionStartExcluding") or ""
                end = match.get("versionEndIncluding") or match.get("versionEndExcluding") or ""
                if start or end:
                    values.append(f"{criteria} ({start} - {end})")
                else:
                    values.append(criteria)
    return truncate("; ".join(values[:5]), 500)
