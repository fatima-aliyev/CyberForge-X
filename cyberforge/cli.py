"""Command-line interface for CyberForge-X."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from cyberforge import __version__
from cyberforge.core.config import BRUTE_PROTOCOLS, SUPPORTED_FORMATS, SUPPORTED_MODULES, ScanConfig
from cyberforge.core.exceptions import (
    AuthorizationError,
    ConfigurationError,
    CyberForgeError,
    ScopeViolation,
)
from cyberforge.core.guard import AuthorizationGate
from cyberforge.core.scope import Scope, load_scope
from cyberforge.engine import ScanEngine
from cyberforge.reporting import ReportPaths


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] not in {
        "scan",
        "modules",
        "validate-scope",
        "version",
        "-h",
        "--help",
    }:
        arguments.insert(0, "scan")
    parser = _build_parser()
    args = parser.parse_args(arguments)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "version":
        print(f"CyberForge-X {__version__}")
        return 0
    if args.command == "modules":
        _print_modules()
        return 0
    if args.command == "validate-scope":
        return _validate_scope(args)
    return _scan(args)


def _scan(args: argparse.Namespace) -> int:
    console = Console(highlight=False)
    try:
        config = _config_from_args(args)
        config.validate()
        _, scope = load_scope(args.scope)
        _cross_validate(config, scope)
        audit = AuthorizationGate.enforce(
            scope=scope,
            engagement_confirmation=config.authorization_confirmation,
            have_authorization=config.have_authorization,
            accept_disclaimer=config.accept_disclaimer,
            console=console,
        )
        config.accept_disclaimer = True
        _validate_targets(config, scope)
        engine = ScanEngine(config, scope, audit)
        bundle = engine.run()
    except (ConfigurationError, AuthorizationError, ScopeViolation) as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        return 2
    except CyberForgeError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted.[/bold yellow]")
        return 130
    _print_summary(console, bundle, engine.report_paths)
    return 130 if engine.interrupted else 0


def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig()
    config.targets = list(args.target or [])
    config.scope_file = Path(args.scope)
    config.output_dir = Path(args.output)
    config.authorization_confirmation = args.authorization
    config.have_authorization = bool(args.i_have_authorization)
    config.accept_disclaimer = bool(args.accept_disclaimer)
    if args.modules:
        config.modules = _csv(args.modules)
    if args.formats:
        config.formats = _csv(args.formats)
    config.timeout = args.timeout
    config.connect_timeout = args.connect_timeout
    config.rate = args.rate
    config.jitter = args.jitter
    config.workers = args.workers
    config.max_requests = args.max_requests
    config.user_agent = args.user_agent
    config.proxy = args.proxy
    config.insecure = bool(args.insecure)
    if args.ports:
        config.ports = args.ports
    config.udp = bool(args.udp)
    config.nmap = bool(args.nmap)
    config.nmap_path = args.nmap_path
    config.os_fingerprint = bool(args.os_fingerprint)
    if args.subdomains is not None:
        config.subdomains = bool(args.subdomains)
    config.zone_transfer = bool(args.zone_transfer)
    config.subdomain_wordlist = args.subdomain_wordlist
    config.scan_subdomains = bool(args.scan_subdomains)
    config.scan_all_ips = bool(args.scan_all_ips)
    config.max_subdomains_to_scan = args.max_subdomains
    config.web_wordlist = args.web_wordlist
    config.crawl_depth = args.crawl_depth
    config.max_pages = args.max_pages
    config.max_injection_points = args.max_injection_points
    config.allow_form_submissions = bool(args.allow_form_submissions)
    config.allow_stored_xss = bool(args.allow_stored_xss)
    config.enable_write_tests = bool(args.enable_write_tests)
    config.ssrf_ports = _int_csv(args.ssrf_ports, "ssrf-ports")
    config.oob_host = args.oob_host
    config.oob_port = args.oob_port
    config.oob_timeout = args.oob_timeout
    config.offline_intel = bool(args.offline_intel)
    config.nvd_api_key = args.nvd_api_key
    config.nvd_results_per_product = args.nvd_results
    config.max_products_to_query = args.max_products
    config.api_base = args.api_base
    config.bola_endpoints = list(args.bola_endpoint or [])
    config.bola_ids = args.bola_ids
    config.auth_a = args.auth_a
    config.auth_b = args.auth_b
    config.jwt_tokens = list(args.jwt_token or [])
    config.jwt_file = args.jwt_file
    config.jwt_secret_wordlist = args.jwt_secret_wordlist
    config.jwt_test_url = args.jwt_test_url
    config.jwt_public_key = args.jwt_public_key
    config.jwt_active_tests = bool(args.jwt_active_tests)
    if args.graphql is not None:
        config.graphql_discovery = bool(args.graphql)
    config.check_rate_limits = bool(args.check_rate_limits)
    config.rate_limit_username = args.rate_limit_username
    config.allow_credential_attacks = bool(args.allow_credential_attacks)
    config.allow_auto_chains = bool(args.auto_chains)
    config.brute_targets = list(args.brute_target or [])
    config.brute_protocols = _csv_many(args.brute_protocol)
    config.brute_users = args.brute_users
    config.brute_passwords = args.brute_passwords
    config.brute_max_attempts = args.brute_max_attempts
    config.brute_delay = args.brute_delay
    config.brute_auto = bool(args.brute_auto)
    config.brute_success_url = args.brute_success_url
    config.brute_success_regex = args.brute_success_regex
    config.brute_failure_regex = args.brute_failure_regex
    config.brute_user_field = args.brute_user_field
    config.brute_pass_field = args.brute_pass_field
    config.smb_domain = args.smb_domain
    config.log_level = args.log_level
    config.extra_headers = _headers(args.header)
    return config


def _cross_validate(config: ScanConfig, scope: Scope) -> None:
    if "brute" in config.modules and not config.allow_credential_attacks:
        raise ConfigurationError(
            "the brute module requires --allow-credential-attacks and scope permission"
        )
    if config.allow_credential_attacks and not scope.config.allow_credential_attacks:
        raise ConfigurationError(
            "scope does not permit credential attacks; set allow_credential_attacks: true "
            "only with explicit written authorization"
        )
    if (
        config.allow_form_submissions
        or config.allow_stored_xss
        or config.enable_write_tests
    ) and not scope.config.allow_write_tests:
        raise ConfigurationError(
            "form submissions/write tests require allow_write_tests: true in the scope file"
        )
    if config.allow_stored_xss and not config.allow_form_submissions:
        raise ConfigurationError("stored XSS testing requires --allow-form-submissions")
    if config.oob_host and "://" in config.oob_host:
        raise ConfigurationError("--oob-host must be a hostname or IP, without a scheme")


def _validate_targets(config: ScanConfig, scope: Scope) -> None:
    if config.api_base:
        scope.assert_url(config.api_base)
    if config.jwt_test_url:
        scope.assert_url(config.jwt_test_url)
    for target in config.targets:
        scope.assert_target(target)
    for target in config.brute_targets:
        scope.assert_target(target)
    for endpoint in config.bola_endpoints:
        if "://" in endpoint:
            scope.assert_url(endpoint)


def _validate_scope(args: argparse.Namespace) -> int:
    console = Console(highlight=False)
    try:
        scope_config, scope = load_scope(args.scope)
        for target in args.target or []:
            scope.assert_target(target)
    except (ConfigurationError, ScopeViolation) as exc:
        console.print(f"[bold red]Scope error:[/bold red] {exc}")
        return 2
    table = Table(title=f"Scope: {scope_config.engagement}", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Authorized by", scope_config.authorized_by)
    table.add_row("Authorization ref", scope_config.authorization_ref or "(none)")
    table.add_row("Allowed hosts", ", ".join(scope_config.allowed_hosts) or "(none)")
    table.add_row("Allowed CIDRs", ", ".join(scope_config.allowed_cidrs) or "(none)")
    table.add_row("Excluded hosts", ", ".join(scope_config.excluded_hosts) or "(none)")
    table.add_row(
        "Allowed ports",
        ", ".join(str(port) for port in scope_config.allowed_ports) or "(all)",
    )
    table.add_row("Credential attacks", "allowed" if scope_config.allow_credential_attacks else "denied")
    table.add_row("Write tests", "allowed" if scope_config.allow_write_tests else "denied")
    table.add_row("Max requests/sec", str(scope_config.max_rps))
    table.add_row("Max requests", str(scope_config.max_requests))
    console.print(table)
    return 0


def _print_modules() -> None:
    console = Console(highlight=False)
    console.print(f"[bold]Modules:[/bold] {', '.join(SUPPORTED_MODULES)}")
    console.print(f"[bold]Brute protocols:[/bold] {', '.join(BRUTE_PROTOCOLS)}")
    console.print(f"[bold]Report formats:[/bold] {', '.join(SUPPORTED_FORMATS)}")


def _print_summary(console: Console, bundle: Any, paths: ReportPaths | None) -> None:
    if paths is None:
        console.print("[bold red]No reports were generated.[/bold red]")
        return
    table = Table(title="Assessment Summary", show_header=True, header_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    table.add_row("Critical", str(bundle.severity_counts()["critical"]))
    table.add_row("High", str(bundle.severity_counts()["high"]))
    table.add_row("Medium", str(bundle.severity_counts()["medium"]))
    table.add_row("Low", str(bundle.severity_counts()["low"]))
    table.add_row("Info", str(bundle.severity_counts()["info"]))
    table.add_row("Risk rating", bundle.risk_rating())
    table.add_row("Requests", str(bundle.request_stats.get("requests", 0)))
    table.add_row("Errors", str(len(bundle.errors)))
    console.print(table)
    if paths.json:
        console.print(f"JSON: {paths.json}")
    if paths.markdown:
        console.print(f"Markdown: {paths.markdown}")
    if paths.html:
        console.print(f"HTML: {paths.html}")
    if paths.credentials:
        console.print(f"[bold yellow]SENSITIVE credentials:[/bold yellow] {paths.credentials}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberforge",
        description="CyberForge-X: authorization-gated, non-destructive security assessment.",
    )
    parser.add_argument("--version", action="version", version=f"CyberForge-X {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="run an authorized assessment")
    _add_scan_arguments(scan)
    modules = subparsers.add_parser("modules", help="list modules and protocols")
    modules.set_defaults(command="modules")
    validate = subparsers.add_parser("validate-scope", help="validate and display a scope file")
    validate.add_argument("--scope", default="scope.yaml")
    validate.add_argument("--target", action="append", default=[])
    validate.set_defaults(command="validate-scope")
    version = subparsers.add_parser("version", help="show the version")
    version.set_defaults(command="version")
    return parser


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("authorization and scope")
    required.add_argument("--scope", default="scope.yaml", help="signed scope YAML file")
    required.add_argument("--authorization", default="", help="exact scope engagement name")
    required.add_argument("--i-have-authorization", action="store_true")
    required.add_argument("--accept-disclaimer", action="store_true")
    required.add_argument("--target", action="append", default=[], help="target host, URL, or host:port")
    required.add_argument(
        "--modules",
        default="recon,intel,web,api,chains",
        help="comma-separated modules (recon,intel,web,api,brute,chains)",
    )
    required.add_argument("--output", default="cyberforge-output", help="report base directory")
    required.add_argument("--formats", default="json,md,html", help="comma-separated report formats")

    options = parser.add_argument_group("safety gates")
    options.add_argument("--allow-form-submissions", action="store_true")
    options.add_argument("--allow-stored-xss", action="store_true")
    options.add_argument("--enable-write-tests", action="store_true")
    options.add_argument("--check-rate-limits", action="store_true")
    options.add_argument("--rate-limit-username", default="")
    options.add_argument("--allow-credential-attacks", action="store_true")
    options.add_argument("--auto-chains", action="store_true")
    options.add_argument("--jwt-active-tests", action="store_true")

    network = parser.add_argument_group("network and HTTP")
    network.add_argument("--timeout", type=float, default=10.0)
    network.add_argument("--connect-timeout", type=float, default=3.0)
    network.add_argument("--rate", type=float, default=5.0)
    network.add_argument("--jitter", type=float, default=0.15)
    network.add_argument("--workers", type=int, default=8)
    network.add_argument("--max-requests", type=int, default=2500)
    network.add_argument("--user-agent", default="CyberForge-X/1.0 (authorized-security-assessment)")
    network.add_argument("--proxy", default="")
    network.add_argument("--insecure", action="store_true")
    network.add_argument("--header", action="append", default=[], help="extra 'Name: value' header")

    recon = parser.add_argument_group("reconnaissance")
    recon.add_argument("--ports", default=None, help="ports/ranges for service discovery")
    recon.add_argument("--udp", action="store_true")
    recon.add_argument("--nmap", action="store_true")
    recon.add_argument("--nmap-path", default="nmap")
    recon.add_argument("--os-fingerprint", action="store_true")
    recon.add_argument("--subdomains", action=argparse.BooleanOptionalAction, default=None)
    recon.add_argument("--zone-transfer", action="store_true")
    recon.add_argument("--subdomain-wordlist", type=Path)
    recon.add_argument("--scan-subdomains", action="store_true")
    recon.add_argument("--scan-all-ips", action="store_true")
    recon.add_argument("--max-subdomains", type=int, default=5)

    web = parser.add_argument_group("web testing")
    web.add_argument("--web-wordlist", type=Path)
    web.add_argument("--crawl-depth", type=int, default=3)
    web.add_argument("--max-pages", type=int, default=40)
    web.add_argument("--max-injection-points", type=int, default=25)
    web.add_argument("--ssrf-ports", default="80,8080")
    web.add_argument("--oob-host", default="", help="public callback hostname/IP")
    web.add_argument("--oob-port", type=int, default=0)
    web.add_argument("--oob-timeout", type=float, default=5.0)

    intel = parser.add_argument_group("intelligence")
    intel.add_argument("--offline-intel", action="store_true")
    intel.add_argument("--nvd-api-key", default="")
    intel.add_argument("--nvd-results", type=int, default=10)
    intel.add_argument("--max-products", type=int, default=8)

    api = parser.add_argument_group("API testing")
    api.add_argument("--api-base", default="")
    api.add_argument("--bola-endpoint", action="append", default=[])
    api.add_argument("--bola-ids", default="1,2,3")
    api.add_argument("--auth-a", default="")
    api.add_argument("--auth-b", default="")
    api.add_argument("--jwt-token", action="append", default=[])
    api.add_argument("--jwt-file", type=Path)
    api.add_argument("--jwt-secret-wordlist", type=Path)
    api.add_argument("--jwt-test-url", default="")
    api.add_argument("--jwt-public-key", type=Path)
    api.add_argument("--graphql", action=argparse.BooleanOptionalAction, default=None)

    brute = parser.add_argument_group("bounded credential testing")
    brute.add_argument("--brute-target", action="append", default=[])
    brute.add_argument("--brute-protocol", action="append", default=[])
    brute.add_argument("--brute-users", type=Path)
    brute.add_argument("--brute-passwords", type=Path)
    brute.add_argument("--brute-max-attempts", type=int, default=20)
    brute.add_argument("--brute-delay", type=float, default=1.0)
    brute.add_argument("--brute-auto", action="store_true")
    brute.add_argument("--brute-success-url", default="")
    brute.add_argument("--brute-success-regex", default="")
    brute.add_argument("--brute-failure-regex", default="")
    brute.add_argument("--brute-user-field", default="")
    brute.add_argument("--brute-pass-field", default="")
    brute.add_argument("--smb-domain", default="")

    logging = parser.add_argument_group("logging")
    logging.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )


def _csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _csv_many(values: list[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        result.extend(_csv(value))
    return result


def _int_csv(value: str, name: str) -> list[int]:
    items: list[int] = []
    for part in _csv(value):
        try:
            port = int(part)
        except ValueError as exc:
            raise ConfigurationError(f"{name} must contain comma-separated integers") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError(f"{name} contains an invalid port: {port}")
        items.append(port)
    return items


def _headers(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        name, separator, header_value = value.partition(":")
        if not separator or not name.strip():
            raise ConfigurationError(f"invalid --header {value!r}; expected 'Name: value'")
        headers[name.strip()] = header_value.strip()
    return headers


if __name__ == "__main__":
    raise SystemExit(main())
