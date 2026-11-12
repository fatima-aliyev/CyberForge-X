"""Intelligence module: CVE mapping, EPSS enrichment, misconfigurations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyberforge.core.context import ModuleContext
from cyberforge.core.models import Severity
from cyberforge.intel.banner import ProductVersion, collect_product_versions
from cyberforge.intel.cve import (
    EPSSClient,
    LocalVulnDB,
    NVDClient,
    Vulnerability,
    default_cache_dir,
    vulnerability_to_finding,
)
from cyberforge.intel.misconfig import MisconfigScanner


@dataclass
class Hit:
    asset: Any
    product_version: ProductVersion
    vulnerability: Vulnerability


class IntelModule:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.db = LocalVulnDB()
        cache_dir = default_cache_dir()
        self.nvd = NVDClient(cache_dir / "nvd", api_key=ctx.config.nvd_api_key) if not ctx.config.offline_intel else None
        self.epss = EPSSClient(cache_dir / "epss")
        self.misconfig = MisconfigScanner(ctx)
        self._queried_products: set[tuple[str, str]] = set()
        self._hits: list[Hit] = []

    def run(self) -> None:
        assets = list(self.ctx.bundle.assets.values())
        if not assets:
            self.log.warning("no assets available for intelligence mapping")
            return
        self.log.info(
            "Starting intelligence mapping across %d asset(s); offline DB records: %d%s",
            len(assets),
            self.db.record_count(),
            "" if self.nvd else " (online NVD disabled)",
        )
        if self.db.load_error:
            self.ctx.bundle.add_error("intel", f"offline vulnerability DB: {self.db.load_error}")

        for asset in assets:
            try:
                self._assess_asset(asset)
            except Exception as exc:
                self.log.exception("intel failed for %s: %s", asset.host, exc)
                self.ctx.bundle.add_error("intel", f"{asset.host}: {exc}")

        found_cves = {hit.vulnerability.cve for hit in self._hits}
        epss_values: dict[str, tuple[float, float]] = {}
        if found_cves:
            self.log.info("Enriching %d CVE(s) with EPSS", len(found_cves))
            epss_values = self.epss.lookup(sorted(found_cves))
        for hit in self._hits:
            values = epss_values.get(hit.vulnerability.cve)
            if values:
                hit.vulnerability.epss, hit.vulnerability.epss_percentile = values

        emitted = 0
        for hit in self._hits:
            finding = vulnerability_to_finding(hit.vulnerability, hit.product_version, hit.asset.host)
            if self.ctx.bundle.add_finding(finding):
                emitted += 1
        if found_cves:
            self.log.info("Intelligence mapping produced %d unique CVE finding(s)", emitted)

    def _assess_asset(self, asset: Any) -> None:
        products = collect_product_versions(asset)
        deduped: dict[tuple[str, str], ProductVersion] = {}
        for item in products:
            if item.version:
                deduped.setdefault((item.product.lower(), item.version.lower()), item)
        products = list(deduped.values())[:40]
        if products:
            self.log.info(
                "Version inventory for %s: %s",
                asset.host,
                ", ".join(f"{item.product} {item.version}" for item in products[:10]),
            )
        for product_version in products:
            self._local_lookup(asset, product_version)
            self._online_lookup(asset, product_version)
        if not products:
            self.log.info("No versioned software detected for %s; CVE mapping skipped", asset.host)

        try:
            misconfig_findings = self.misconfig.scan(asset)
        except Exception as exc:
            self.log.warning("misconfiguration checks failed for %s: %s", asset.host, exc)
            misconfig_findings = []
        for finding in misconfig_findings:
            self.ctx.bundle.add_finding(finding)

    def _local_lookup(self, asset: Any, product_version: ProductVersion) -> None:
        matches = self.db.lookup(product_version.product, product_version.version)
        if not matches:
            return
        self.log.info(
            "Offline DB matched %d CVE(s) for %s %s",
            len(matches),
            product_version.product,
            product_version.version,
        )
        for vulnerability in matches:
            self._hits.append(Hit(asset=asset, product_version=product_version, vulnerability=vulnerability))

    def _online_lookup(self, asset: Any, product_version: ProductVersion) -> None:
        if self.nvd is None:
            return
        key = (product_version.product.lower(), product_version.version.lower())
        if key in self._queried_products:
            for existing in self._hits:
                if (
                    existing.asset.host == asset.host
                    and existing.product_version.product.lower() == key[0]
                    and existing.product_version.version.lower() == key[1]
                    and existing.vulnerability.source == "nvd-keyword"
                ):
                    self._hits.append(Hit(asset=asset, product_version=product_version, vulnerability=existing.vulnerability))
            return
        if len(self._queried_products) >= self.ctx.config.max_products_to_query:
            return
        self._queried_products.add(key)
        results = self.nvd.search(
            product_version.product,
            product_version.version,
            limit=self.ctx.config.nvd_results_per_product,
        )
        local_cves = {
            hit.vulnerability.cve
            for hit in self._hits
            if hit.asset.host == asset.host
            and hit.product_version.product == product_version.product
            and hit.product_version.version == product_version.version
        }
        for vulnerability in results:
            if vulnerability.cve in local_cves:
                continue
            self._hits.append(Hit(asset=asset, product_version=product_version, vulnerability=vulnerability))
        if results:
            self.log.info(
                "NVD returned %d candidate(s) for %s %s (requires manual verification)",
                len(results),
                product_version.product,
                product_version.version,
            )


def summarize_intel(ctx: ModuleContext) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in ctx.bundle.findings:
        if finding.module == "intel":
            counts[finding.severity.value] += 1
    return counts
