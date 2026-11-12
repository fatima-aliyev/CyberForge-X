"""Correlate findings into attack paths with opt-in authenticated discovery."""

from __future__ import annotations

from urllib.parse import urlsplit

from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from cyberforge.core.context import ModuleContext
from cyberforge.core.models import ChainResult, ChainStep, Finding, Severity
from cyberforge.core.utils import normalize_url
from cyberforge.web.fuzz import PathFuzzer, backup_variants

BACKUP_SEEDS = [
    "backup",
    "db",
    "database",
    "dump",
    "site",
    "www",
    "config",
    "admin",
    "app",
    "wp-config",
    "index",
]


class ChainOrchestrator:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self._seen: set[tuple[str, str]] = set()

    def run(self) -> list[ChainResult]:
        findings = list(self.ctx.bundle.findings)
        chains: list[ChainResult] = []
        chains.extend(self._api_docs_bola(findings))
        chains.extend(self._anonymous_datastore(findings))
        chains.extend(self._source_exposure(findings))
        chains.extend(self._outdated_admin(findings))
        chains.extend(self._admin_credentials_backup(findings))
        for chain in chains:
            key = (chain.name, chain.target)
            if key in self._seen:
                continue
            self._seen.add(key)
            self.ctx.bundle.add_chain(chain)
        self.log.info("Chains: %d attack path(s) recorded", len(self._seen))
        return chains

    # ------------------------------------------------------------------ static
    def _api_docs_bola(self, findings: list[Finding]) -> list[ChainResult]:
        docs = _tagged(findings, "documentation")
        bola = _tagged(findings, "bola")
        if not docs or not bola:
            return []
        target = bola[0].target
        return [
            ChainResult(
                name="api-documentation-to-bola",
                description=(
                    "Exposed API documentation supplied object identifiers, and authorization checks "
                    "found an object-access weakness. Together they form a direct data-exposure path."
                ),
                target=target,
                executed=False,
                steps=[
                    ChainStep(
                        action="Enumerate API documentation",
                        result=f"{len(docs)} documentation finding(s)",
                        evidence=docs[0].target,
                    ),
                    ChainStep(
                        action="Test object-level authorization",
                        result=f"{len(bola)} BOLA/IDOR finding(s)",
                        evidence=bola[0].title,
                    ),
                ],
                finding_ids=[docs[0].id, *[finding.id for finding in bola[:3]]],
                notes="Derived from existing evidence; no additional exploitation was performed.",
            )
        ]

    def _anonymous_datastore(self, findings: list[Finding]) -> list[ChainResult]:
        exposed = _tagged(findings, "anonymous-access")
        if not exposed:
            return []
        return [
            ChainResult(
                name="unauthenticated-data-service",
                description=(
                    "One or more data services accept unauthenticated access. An attacker could read "
                    "or manipulate exposed data within the authorized scope."
                ),
                target=exposed[0].target,
                executed=False,
                steps=[
                    ChainStep(
                        action="Reach data service",
                        result="Unauthenticated service access confirmed",
                        evidence=exposed[0].title,
                    ),
                    ChainStep(
                        action="Assess data exposure",
                        result=f"{len(exposed)} related finding(s)",
                        evidence="\n".join(finding.title for finding in exposed[:5]),
                    ),
                ],
                finding_ids=[finding.id for finding in exposed[:5]],
                notes="Derived from existing findings; no data was extracted.",
            )
        ]

    def _source_exposure(self, findings: list[Finding]) -> list[ChainResult]:
        exposed = _tagged(findings, "source-code")
        if not exposed:
            return []
        return [
            ChainResult(
                name="source-code-disclosure",
                description=(
                    "Repository metadata or source files are exposed. Reviewing them may reveal secrets, "
                    "internal endpoints, and authorization logic."
                ),
                target=exposed[0].target,
                executed=False,
                steps=[
                    ChainStep(
                        action="Retrieve exposed source metadata",
                        result="Source disclosure confirmed",
                        evidence=exposed[0].title,
                    ),
                    ChainStep(
                        action="Review for secrets and hidden endpoints",
                        result="Manual review required",
                    ),
                ],
                finding_ids=[finding.id for finding in exposed[:5]],
                notes="No repository contents were reproduced in this report.",
            )
        ]

    def _outdated_admin(self, findings: list[Finding]) -> list[ChainResult]:
        admin = _tagged(findings, "admin-panel")
        outdated = [
            finding
            for finding in findings
            if finding.cve_ids and finding.severity.rank >= Severity.HIGH.rank
        ]
        if not admin or not outdated:
            return []
        return [
            ChainResult(
                name="outdated-component-with-admin-surface",
                description=(
                    "An exposed administrative interface runs on infrastructure with a high-severity "
                    "known vulnerability. This combination increases the likelihood of remote compromise."
                ),
                target=admin[0].target,
                executed=False,
                steps=[
                    ChainStep(action="Locate administrative interface", result="Admin panel reachable", evidence=admin[0].target),
                    ChainStep(
                        action="Identify vulnerable component",
                        result=f"{len(outdated)} high/critical CVE finding(s)",
                        evidence=", ".join(finding.cve_ids[0] for finding in outdated[:5] if finding.cve_ids),
                    ),
                ],
                finding_ids=[admin[0].id, *[finding.id for finding in outdated[:3]]],
                notes="CVE applicability requires manual verification before exploitation.",
            )
        ]

    # ------------------------------------------------------------------ active
    def _admin_credentials_backup(self, findings: list[Finding]) -> list[ChainResult]:
        admin = _tagged(findings, "admin-panel")
        credentials = [
            record
            for record in list(self.ctx.bundle.credentials)
            if str(record.get("protocol", "")).lower().startswith("http")
        ]
        if not admin or not credentials:
            return []
        panel = admin[0]
        record = credentials[0]
        panel_host = (urlsplit(panel.target).hostname or "").lower()
        credential_host = (urlsplit(str(record.get("target", ""))).hostname or "").lower()
        if panel_host and credential_host and panel_host != credential_host:
            return []
        username = str(record.get("username", ""))
        protocol = str(record.get("protocol", ""))
        credential_finding = next(
            (
                finding
                for finding in findings
                if "weak-authentication" in finding.tags
                and finding.metadata.get("username") == username
            ),
            None,
        )
        replayable = protocol.lower().startswith(("http basic", "http digest"))
        if not self.ctx.config.allow_auto_chains or not replayable:
            reason = (
                "Requires --auto-chains"
                if not self.ctx.config.allow_auto_chains
                else "Form-session replay is not automated; validate the session manually"
            )
            return [
                ChainResult(
                    name="admin-credentials-backup",
                    description=(
                        "An exposed administrative panel and valid HTTP credentials were both confirmed. "
                        "Authenticated backup discovery is available but was not executed."
                    ),
                    target=panel.target,
                    executed=False,
                    steps=[
                        ChainStep(action="Locate admin panel", result="Panel reachable", evidence=panel.target),
                        ChainStep(
                            action="Use confirmed credentials",
                            result=f"{protocol} credentials for {username}",
                            evidence="Password withheld",
                        ),
                        ChainStep(
                            action="Authenticated backup discovery",
                            result="Not executed",
                            evidence=reason,
                        ),
                    ],
                    finding_ids=[panel.id] + ([credential_finding.id] if credential_finding else []),
                    notes=(
                        "Re-run with --auto-chains to perform GET-only authenticated content discovery "
                        "when Basic or Digest authentication was confirmed."
                    ),
                )
            ]
        base = f"{urlsplit(panel.target).scheme}://{urlsplit(panel.target).netloc}/"
        try:
            session = self._authenticated_session(protocol, username, str(record.get("password", "")))
        except Exception as exc:
            self.log.warning("Unable to build authenticated chain session: %s", exc)
            return []
        paths = backup_variants(BACKUP_SEEDS)
        paths.extend([".env", ".git/config", "phpinfo.php", "server-status", "backup.zip", "database.sql"])
        fuzzer = PathFuzzer(self.ctx, session=session)
        try:
            results = fuzzer.scan(base, paths)
        except Exception as exc:
            self.log.warning("Authenticated backup discovery failed: %s", exc)
            return []
        additions = fuzzer.findings(base, results, module="web")
        added_ids: list[str] = []
        for finding in additions:
            if self.ctx.bundle.add_finding(finding):
                added_ids.append(finding.id)
        sensitive = [result for result in results if result.sensitive]
        steps = [
            ChainStep(action="Locate admin panel", result="Panel reachable", evidence=panel.target),
            ChainStep(
                action="Use confirmed credentials",
                result=f"{protocol} session established for {username}",
                evidence="Password withheld",
            ),
            ChainStep(
                action="Authenticated backup/sensitive-file discovery",
                result=f"{len(results)} response(s); {len(sensitive)} sensitive result(s)",
                evidence="\n".join(_path_of(item.url) for item in sensitive[:15]),
            ),
        ]
        return [
            ChainResult(
                name="admin-credentials-backup",
                description=(
                    "Confirmed HTTP credentials opened the administrative surface, and authenticated "
                    "content discovery was performed for backups and sensitive files."
                ),
                target=panel.target,
                executed=True,
                steps=steps,
                finding_ids=[panel.id]
                + ([credential_finding.id] if credential_finding else [])
                + added_ids,
                notes="Only read-only GET requests were used; no files were downloaded.",
            )
        ]

    def _authenticated_session(self, protocol: str, username: str, password: str):
        if protocol.lower().startswith("http basic"):
            session = self.ctx.new_session(clear_cookies=True, name="chain-auth")
            session.session.auth = HTTPBasicAuth(username, password)
            return session
        if protocol.lower().startswith("http digest"):
            session = self.ctx.new_session(clear_cookies=True, name="chain-auth")
            session.session.auth = HTTPDigestAuth(username, password)
            return session
        return self.ctx.new_session(name="chain-auth")


def _tagged(findings: list[Finding], tag: str) -> list[Finding]:
    return [finding for finding in findings if tag in finding.tags]


def _path_of(url: str) -> str:
    parsed = urlsplit(normalize_url(url))
    return parsed.path or "/"
