"""Domain models used by every CyberForge-X module."""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


def severity_sort_key(severity: Severity) -> int:
    return -severity.rank


@dataclass
class Evidence:
    payload: str = ""
    request: str = ""
    response_excerpt: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "request": self.request,
            "response_excerpt": self.response_excerpt,
            "notes": self.notes,
        }


@dataclass
class Finding:
    title: str
    severity: Severity
    module: str
    target: str
    description: str
    remediation: str
    evidence: Evidence = field(default_factory=Evidence)
    cvss: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    reproduction: str = ""
    id: str = field(default_factory=lambda: f"CFX-{uuid.uuid4().hex[:10].upper()}")
    timestamp: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        raw = "|".join(
            [
                self.module,
                self.title,
                self.target,
                ",".join(sorted(self.cve_ids)),
                str(self.metadata.get("parameter", "")),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "module": self.module,
            "target": self.target,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence.to_dict(),
            "cvss": self.cvss,
            "cve_ids": list(self.cve_ids),
            "references": list(self.references),
            "confidence": self.confidence,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "reproduction": self.reproduction,
            "timestamp": self.timestamp,
        }


@dataclass
class Technology:
    name: str
    category: str = "unknown"
    version: str = ""
    confidence: str = "medium"
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    tls: bool = False
    version: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "tls": self.tls,
            "version": self.version,
            "extra": dict(self.extra),
        }


@dataclass
class DNSInfo:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    soa: str = ""
    ptr: list[str] = field(default_factory=list)
    spf: list[str] = field(default_factory=list)
    dmarc: list[str] = field(default_factory=list)
    dkim_selectors: list[str] = field(default_factory=list)
    subdomains: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "a": list(self.a),
            "aaaa": list(self.aaaa),
            "mx": list(self.mx),
            "ns": list(self.ns),
            "txt": list(self.txt),
            "cname": list(self.cname),
            "soa": self.soa,
            "ptr": list(self.ptr),
            "spf": list(self.spf),
            "dmarc": list(self.dmarc),
            "dkim_selectors": list(self.dkim_selectors),
            "subdomains": {k: list(v) for k, v in self.subdomains.items()},
        }


@dataclass
class HostAsset:
    host: str
    ips: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    dns: DNSInfo = field(default_factory=DNSInfo)
    os: str = ""
    cdn: str = ""
    waf: str = ""
    favicon_hash: str = ""
    notes: list[str] = field(default_factory=list)

    def add_port(self, port: PortInfo) -> None:
        for existing in self.ports:
            if existing.port == port.port and existing.protocol == port.protocol:
                if port.banner and not existing.banner:
                    existing.banner = port.banner
                if port.version and not existing.version:
                    existing.version = port.version
                if port.tls:
                    existing.tls = True
                existing.extra.update(port.extra)
                return
        self.ports.append(port)

    def add_technology(self, tech: Technology) -> None:
        key = (tech.name.lower(), tech.category.lower())
        for existing in self.technologies:
            if (existing.name.lower(), existing.category.lower()) == key:
                if tech.version and not existing.version:
                    existing.version = tech.version
                if tech.confidence == "high":
                    existing.confidence = tech.confidence
                return
        self.technologies.append(tech)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ips": list(self.ips),
            "urls": list(self.urls),
            "ports": [p.to_dict() for p in self.ports],
            "technologies": [t.to_dict() for t in self.technologies],
            "dns": self.dns.to_dict(),
            "os": self.os,
            "cdn": self.cdn,
            "waf": self.waf,
            "favicon_hash": self.favicon_hash,
            "notes": list(self.notes),
        }


@dataclass
class APIEndpoint:
    method: str
    url: str
    summary: str = ""
    parameters: list[str] = field(default_factory=list)
    body_fields: list[str] = field(default_factory=list)
    operation_id: str = ""
    security: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "summary": self.summary,
            "parameters": list(self.parameters),
            "body_fields": list(self.body_fields),
            "operation_id": self.operation_id,
            "security": list(self.security),
        }


@dataclass
class APISurface:
    base_url: str
    docs_urls: list[str] = field(default_factory=list)
    endpoints: list[APIEndpoint] = field(default_factory=list)
    graphql_urls: list[str] = field(default_factory=list)
    graphql_introspection: bool = False
    security_schemes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "docs_urls": list(self.docs_urls),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "graphql_urls": list(self.graphql_urls),
            "graphql_introspection": self.graphql_introspection,
            "security_schemes": list(self.security_schemes),
            "notes": list(self.notes),
        }


@dataclass
class ChainStep:
    action: str
    result: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "result": self.result, "evidence": self.evidence}


@dataclass
class ChainResult:
    name: str
    description: str
    target: str
    executed: bool
    steps: list[ChainStep] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "executed": self.executed,
            "steps": [s.to_dict() for s in self.steps],
            "finding_ids": list(self.finding_ids),
            "notes": self.notes,
        }


class ResultBundle:
    """Thread-safe aggregation of assets, findings, chains, and audit data."""

    def __init__(self, engagement: str, targets: list[str], scope_meta: dict[str, Any]) -> None:
        self.engagement = engagement
        self.targets = list(targets)
        self.scope_meta = dict(scope_meta)
        self.assets: dict[str, HostAsset] = {}
        self.api_surfaces: list[APISurface] = []
        self.findings: list[Finding] = []
        self.chains: list[ChainResult] = []
        self.errors: list[dict[str, str]] = []
        self.credentials: list[dict[str, Any]] = []
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.request_stats: dict[str, Any] = {}
        self._fingerprints: set[str] = set()
        self._lock = threading.RLock()

    def add_asset(self, asset: HostAsset) -> HostAsset:
        with self._lock:
            existing = self.assets.get(asset.host.lower())
            if existing is None:
                self.assets[asset.host.lower()] = asset
                return asset
            for ip in asset.ips:
                if ip not in existing.ips:
                    existing.ips.append(ip)
            for url in asset.urls:
                if url not in existing.urls:
                    existing.urls.append(url)
            for port in asset.ports:
                existing.add_port(port)
            for tech in asset.technologies:
                existing.add_technology(tech)
            for key in ("a", "aaaa", "mx", "ns", "txt", "cname", "spf", "dmarc", "ptr"):
                target_list = getattr(existing.dns, key)
                for item in getattr(asset.dns, key):
                    if item not in target_list:
                        target_list.append(item)
            existing.dns.subdomains.update(asset.dns.subdomains)
            if asset.os and not existing.os:
                existing.os = asset.os
            if asset.cdn and not existing.cdn:
                existing.cdn = asset.cdn
            if asset.waf and not existing.waf:
                existing.waf = asset.waf
            if asset.favicon_hash and not existing.favicon_hash:
                existing.favicon_hash = asset.favicon_hash
            for note in asset.notes:
                if note not in existing.notes:
                    existing.notes.append(note)
            return existing

    def add_finding(self, finding: Finding) -> bool:
        with self._lock:
            fp = finding.fingerprint()
            if fp in self._fingerprints:
                return False
            self._fingerprints.add(fp)
            self.findings.append(finding)
            return True

    def add_findings(self, findings: list[Finding]) -> int:
        added = 0
        for finding in findings:
            if self.add_finding(finding):
                added += 1
        return added

    def add_api_surface(self, surface: APISurface) -> None:
        with self._lock:
            self.api_surfaces.append(surface)

    def add_chain(self, result: ChainResult) -> None:
        with self._lock:
            self.chains.append(result)

    def add_error(self, module: str, message: str) -> None:
        with self._lock:
            self.errors.append({"module": module, "message": message})

    def add_credential(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.credentials.append(record)

    def get_asset(self, host: str) -> HostAsset | None:
        with self._lock:
            return self.assets.get(host.lower())

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        with self._lock:
            for finding in self.findings:
                grouped[finding.severity].append(finding)
        for items in grouped.values():
            items.sort(key=lambda f: f.timestamp, reverse=True)
        return grouped

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        with self._lock:
            for finding in self.findings:
                counts[finding.severity.value] += 1
        return counts

    def risk_rating(self) -> str:
        counts = self.severity_counts()
        if counts["critical"]:
            return "Critical"
        if counts["high"]:
            return "High"
        if counts["medium"]:
            return "Medium"
        if counts["low"]:
            return "Low"
        return "Informational"

    def sorted_findings(self) -> list[Finding]:
        with self._lock:
            return sorted(self.findings, key=lambda f: (-f.severity.rank, f.title.lower()))

    def finish(self) -> None:
        self.finished_at = time.time()

    def to_dict(self, show_secrets: bool = False) -> dict[str, Any]:
        with self._lock:
            credentials = []
            for record in self.credentials:
                item = dict(record)
                if not show_secrets:
                    item["password"] = _mask_value(str(item.get("password", "")))
                credentials.append(item)
            return {
                "engagement": self.engagement,
                "targets": list(self.targets),
                "scope": dict(self.scope_meta),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "risk_rating": self.risk_rating(),
                "severity_counts": self.severity_counts(),
                "assets": [asset.to_dict() for asset in self.assets.values()],
                "api_surfaces": [surface.to_dict() for surface in self.api_surfaces],
                "findings": [finding.to_dict() for finding in self.sorted_findings()],
                "chains": [chain.to_dict() for chain in self.chains],
                "errors": list(self.errors),
                "credentials": credentials,
                "request_stats": dict(self.request_stats),
            }


def _mask_value(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "****"
    if len(value) <= 8:
        return value[0] + "****" + value[-1]
    return value[:2] + "****" + value[-2:]
