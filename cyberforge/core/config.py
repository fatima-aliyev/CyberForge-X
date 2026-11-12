"""Validated runtime configuration for a CyberForge-X assessment."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberforge.core.exceptions import ConfigurationError
from cyberforge.core.utils import clamp, parse_ports

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,631,993,995,"
    "1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5672,5900,"
    "6379,7001,8000-8090,8088,8180,8443,8888,9000,9090,9200,9300,10000,"
    "11211,15672,27017,50000"
)

SUPPORTED_MODULES = ("recon", "intel", "web", "api", "brute", "chains")
SUPPORTED_FORMATS = ("json", "md", "html")
BRUTE_PROTOCOLS = ("http-basic", "http-digest", "http-form", "ssh", "ftp", "smb")


@dataclass
class ScanConfig:
    targets: list[str] = field(default_factory=list)
    scope_file: Path = Path("scope.yaml")
    modules: list[str] = field(default_factory=lambda: ["recon", "intel", "web", "api", "chains"])
    output_dir: Path = Path("cyberforge-output")
    formats: list[str] = field(default_factory=lambda: ["json", "md", "html"])

    authorization_confirmation: str = ""
    have_authorization: bool = False
    accept_disclaimer: bool = False
    show_secrets: bool = False
    allow_form_submissions: bool = False
    allow_stored_xss: bool = False
    enable_write_tests: bool = False
    check_rate_limits: bool = False
    rate_limit_username: str = ""
    allow_lockout_risk: bool = False
    allow_credential_attacks: bool = False
    allow_auto_chains: bool = False

    timeout: float = 10.0
    connect_timeout: float = 3.0
    rate: float = 5.0
    jitter: float = 0.15
    workers: int = 8
    max_requests: int = 2500
    user_agent: str = "CyberForge-X/1.0 (authorized-security-assessment)"
    proxy: str = ""
    insecure: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)

    ports: str = DEFAULT_PORTS
    udp: bool = False
    nmap: bool = False
    nmap_path: str = "nmap"
    os_fingerprint: bool = False
    subdomains: bool = True
    zone_transfer: bool = False
    subdomain_wordlist: Path | None = None
    scan_subdomains: bool = False
    scan_all_ips: bool = False
    max_subdomains_to_scan: int = 5

    web_wordlist: Path | None = None
    crawl_depth: int = 3
    max_pages: int = 40
    max_injection_points: int = 25
    oob_host: str = ""
    oob_port: int = 0
    oob_timeout: float = 5.0
    ssrf_ports: list[int] = field(default_factory=lambda: [80, 8080])

    offline_intel: bool = False
    nvd_api_key: str = ""
    nvd_results_per_product: int = 10
    max_products_to_query: int = 8

    api_base: str = ""
    bola_endpoints: list[str] = field(default_factory=list)
    bola_ids: str = "1,2,3"
    auth_a: str = ""
    auth_b: str = ""
    jwt_tokens: list[str] = field(default_factory=list)
    jwt_file: Path | None = None
    jwt_secret_wordlist: Path | None = None
    jwt_test_url: str = ""
    jwt_public_key: Path | None = None
    jwt_active_tests: bool = False
    graphql_discovery: bool = True

    brute_targets: list[str] = field(default_factory=list)
    brute_protocols: list[str] = field(default_factory=list)
    brute_users: Path | None = None
    brute_passwords: Path | None = None
    brute_max_attempts: int = 20
    brute_delay: float = 1.0
    brute_auto: bool = False
    brute_success_url: str = ""
    brute_success_regex: str = ""
    brute_failure_regex: str = ""
    brute_user_field: str = ""
    brute_pass_field: str = ""
    smb_domain: str = ""

    report_title: str = "CyberForge-X Security Assessment"
    log_level: str = "INFO"
    json_logs: bool = False

    def validate(self) -> None:
        if not self.targets:
            raise ConfigurationError("at least one --target is required")
        unknown_modules = [m for m in self.modules if m not in SUPPORTED_MODULES]
        if unknown_modules:
            raise ConfigurationError(f"unknown modules: {', '.join(unknown_modules)}")
        bad_formats = [f for f in self.formats if f not in SUPPORTED_FORMATS]
        if bad_formats:
            raise ConfigurationError(f"unsupported report formats: {', '.join(bad_formats)}")
        bad_protocols = [p for p in self.brute_protocols if p not in BRUTE_PROTOCOLS]
        if bad_protocols:
            raise ConfigurationError(f"unsupported brute protocols: {', '.join(bad_protocols)}")
        parse_ports(self.ports)
        if not 0.1 <= self.rate <= 50:
            raise ConfigurationError("rate must be between 0.1 and 50 requests/second")
        self.workers = int(clamp(self.workers, 1, 32))
        self.jitter = float(clamp(self.jitter, 0.0, 2.0))
        self.max_requests = int(clamp(self.max_requests, 10, 50000))
        self.max_pages = int(clamp(self.max_pages, 1, 500))
        self.crawl_depth = int(clamp(self.crawl_depth, 0, 8))
        self.max_injection_points = int(clamp(self.max_injection_points, 1, 200))
        self.brute_max_attempts = int(clamp(self.brute_max_attempts, 1, 50))
        self.brute_delay = float(clamp(self.brute_delay, 0.2, 30.0))
        self.timeout = float(clamp(self.timeout, 1.0, 120.0))
        self.connect_timeout = float(clamp(self.connect_timeout, 1.0, 30.0))
        if self.max_subdomains_to_scan > 50:
            self.max_subdomains_to_scan = 50
        if not 1 <= self.oob_port <= 65535 and self.oob_port != 0:
            raise ConfigurationError("oob-port must be 0 (auto) or a valid TCP port")
        if self.allow_stored_xss and not self.allow_form_submissions:
            raise ConfigurationError("stored XSS testing requires --allow-form-submissions")
        if self.jwt_active_tests and not self.jwt_test_url:
            raise ConfigurationError("JWT active tests require --jwt-test-url")
        if not self.formats:
            raise ConfigurationError("at least one report format is required")
        if self.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError(f"unsupported log level: {self.log_level}")

    def to_dict(self) -> dict[str, Any]:
        return {
            key: str(value) if isinstance(value, Path) else value
            for key, value in self.__dict__.items()
        }
