"""Async TCP/UDP scanning with optional nmap service/OS enrichment."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import socket
import ssl
import struct
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any

from cyberforge.core.logging import get_logger
from cyberforge.core.models import PortInfo
from cyberforge.core.utils import resolve_all, truncate

SERVICE_MAP: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1099: "rmi",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    3000: "http-alt",
    3260: "iscsi",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http-alt",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    6379: "redis",
    7001: "weblogic",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp13",
    8080: "http-proxy",
    8081: "http-alt",
    8088: "http-alt",
    8180: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "cslistener",
    9042: "cassandra",
    9090: "http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9443: "https-alt",
    10000: "webmin",
    11211: "memcache",
    15672: "rabbitmq-management",
    27017: "mongod",
    50000: "db2",
    61616: "activemq",
}

TLS_PORTS = {443, 465, 636, 993, 995, 2376, 3260, 5986, 6443, 8443, 9443}
HTTP_PORTS = {
    80,
    443,
    3000,
    5000,
    5601,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8180,
    8443,
    8888,
    9000,
    9090,
    9443,
    10000,
    15672,
}
UDP_PROBE_PORTS = [53, 123, 161, 1900]
UDP_SERVICES = {53: "domain", 123: "ntp", 161: "snmp", 1900: "ssdp"}

HTTP_REQUEST = (
    "HEAD / HTTP/1.0\r\n"
    "Host: {host}\r\n"
    "User-Agent: CyberForge-X/1.0\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n\r\n"
)

log = get_logger("recon.ports")


class ScanCancelled(Exception):
    pass


async def tcp_probe(ip: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> bool:
    async with semaphore:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, limit=65536), timeout=timeout
            )
            del reader
            return True
        except (TimeoutError, asyncio.TimeoutError, OSError):
            return False
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass


async def scan_tcp(
    host: str,
    ip: str,
    ports: list[int],
    timeout: float = 1.5,
    concurrency: int = 200,
    grab_banners: bool = True,
    progress: Callable[[int, int], None] | None = None,
) -> list[PortInfo]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    tasks = [asyncio.create_task(tcp_probe(ip, port, timeout, semaphore)) for port in ports]
    open_ports: list[int] = []
    for completed, (port, task) in enumerate(zip(ports, tasks, strict=False), start=1):
        try:
            is_open = await task
        except Exception:
            is_open = False
        if is_open:
            open_ports.append(port)
        if progress and completed % 100 == 0:
            progress(completed, len(ports))

    log.info("TCP scan %s: %d/%d ports open", host, len(open_ports), len(ports))
    results = [
        PortInfo(port=port, protocol="tcp", state="open", service=SERVICE_MAP.get(port, "unknown"))
        for port in open_ports
    ]
    if not grab_banners or not results:
        return results

    banner_semaphore = asyncio.Semaphore(10)
    banner_tasks = [
        asyncio.create_task(grab_banner(host, ip, item, timeout=max(2.0, timeout + 1.0), semaphore=banner_semaphore))
        for item in results
    ]
    gathered = await asyncio.gather(*banner_tasks, return_exceptions=True)
    for item, outcome in zip(results, gathered, strict=False):
        if isinstance(outcome, Exception) or outcome is None:
            continue
        item.banner, item.tls, item.extra = outcome
        if not item.version and item.banner:
            match = re.search(r"\b(\d+\.\d+(?:\.\d+)*)\b", item.banner)
            if match:
                item.version = match.group(1)
    return results


async def grab_banner(
    hostname: str,
    ip: str,
    port: PortInfo,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> tuple[str, bool, dict[str, Any]] | None:
    async with semaphore:
        use_tls = port.port in TLS_PORTS or "https" in port.service or port.service in {"imaps", "smtps", "pop3s"}
        if use_tls:
            outcome = await _grab_tls(hostname, ip, port.port, timeout)
            if outcome is not None:
                return outcome
        return await _grab_plain(hostname, ip, port.port, timeout)


async def _grab_tls(hostname: str, ip: str, port: int, timeout: float) -> tuple[str, bool, dict[str, Any]] | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=hostname, limit=65536),
            timeout=timeout,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        extra: dict[str, Any] = {"tls": True}
        if ssl_object is not None:
            cert = ssl_object.getpeercert(binary_form=True)
            if cert:
                extra["cert_sha256"] = hashlib.sha256(cert).hexdigest()
            extra["tls_version"] = ssl_object.version()
            cipher = ssl_object.cipher()
            if cipher:
                extra["cipher"] = cipher[0]
        if port in HTTP_PORTS or port in {443, 8443, 9443}:
            writer.write(HTTP_REQUEST.format(host=hostname).encode("ascii", "ignore"))
            await writer.drain()
        data = await _read_limited(reader, timeout)
        return data, True, extra
    except (TimeoutError, asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass


async def _grab_plain(hostname: str, ip: str, port: int, timeout: float) -> tuple[str, bool, dict[str, Any]]:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, limit=65536), timeout=timeout
        )
        if port in HTTP_PORTS:
            writer.write(HTTP_REQUEST.format(host=hostname).encode("ascii", "ignore"))
            await writer.drain()
        data = await _read_limited(reader, timeout)
        return data, False, {}
    except (TimeoutError, asyncio.TimeoutError, OSError):
        return "", False, {}
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass


async def _read_limited(reader: asyncio.StreamReader, timeout: float) -> str:
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (TimeoutError, asyncio.TimeoutError, OSError):
        data = b""
    return truncate(data.decode("utf-8", errors="replace"), 600)


async def scan_udp(host: str, ip: str, ports: list[int], timeout: float = 2.0) -> list[PortInfo]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    loop = asyncio.get_running_loop()
    results: list[PortInfo] = []
    for port in ports:
        payload = _udp_payload(port, host)
        if not payload:
            continue
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, payload, (ip, port))
            data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 8192), timeout=timeout)
            if data and _valid_udp_response(port, data):
                banner = _udp_banner(port, data)
                results.append(
                    PortInfo(
                        port=port,
                        protocol="udp",
                        state="open",
                        service=UDP_SERVICES.get(port, "unknown"),
                        banner=banner,
                    )
                )
        except (TimeoutError, asyncio.TimeoutError, OSError):
            continue
        finally:
            sock.close()
    log.info("UDP probe %s: %d/%d responsive", host, len(results), len(ports))
    return results


def _udp_payload(port: int, host: str) -> bytes:
    if port == 53:
        transaction = os.urandom(2)
        qname = b"".join(bytes([len(part)]) + part.encode("idna", "ignore") for part in host.split(".") if part) + b"\x00"
        return transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    if port == 123:
        return b"\x1b" + b"\x00" * 47
    if port == 161:
        return _snmp_get()
    if port == 1900:
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )
    return b""


def _valid_udp_response(port: int, data: bytes) -> bool:
    if port == 53:
        return len(data) >= 12 and bool(data[2] & 0x80)
    if port == 123:
        return len(data) >= 48 and (data[0] & 0x38) >> 3 in {3, 4}
    if port == 161:
        return data.startswith(b"\x30")
    if port == 1900:
        return b"HTTP/1.1" in data[:64] or b"ST:" in data[:200]
    return False


def _udp_banner(port: int, data: bytes) -> str:
    if port == 1900:
        return truncate(data.decode("utf-8", errors="replace"), 400)
    printable = re.findall(rb"[\x20-\x7e]{4,}", data)
    return truncate(" | ".join(chunk.decode("ascii", "replace") for chunk in printable[:8]), 400)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + value


def _snmp_get() -> bytes:
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, oid) + b"\x05\x00")
    varbinds = _ber_tlv(0x30, varbind)
    pdu = _ber_tlv(
        0xA0,
        _ber_tlv(0x02, b"\x00\x00\x00\x01")
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x02, b"\x00")
        + varbinds,
    )
    return _ber_tlv(0x30, _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, b"public") + pdu)


def compress_ports(ports: list[int]) -> str:
    if not ports:
        return ""
    ordered = sorted(set(ports))
    ranges: list[str] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def nmap_scan(
    host: str,
    ports: list[int],
    nmap_path: str = "nmap",
    os_fingerprint: bool = False,
    timeout: float = 300.0,
) -> tuple[list[PortInfo], list[str], str]:
    """Run a bounded nmap -sV scan and parse XML. No NSE scripts are used."""
    if not ports:
        return [], [], "no ports"
    args = [
        nmap_path,
        "-Pn",
        "-n",
        "-sV",
        "--version-light",
        "-T3",
        "--host-timeout",
        "5m",
        "-oX",
        "-",
        "-p",
        compress_ports(ports),
        host,
    ]
    if os_fingerprint:
        args[1:1] = ["-O", "--osscan-guess"]
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return [], [], "nmap executable not found"
    except subprocess.TimeoutExpired:
        return [], [], "nmap timed out"
    except OSError as exc:
        return [], [], f"nmap failed: {exc}"
    if not completed.stdout.strip():
        return [], [], (completed.stderr or "nmap returned no XML").strip()[:500]
    try:
        root = ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        return [], [], f"nmap XML parse error: {exc}"
    parsed_ports: list[PortInfo] = []
    os_matches: list[str] = []
    for host_node in root.findall("host"):
        for os_node in host_node.findall("./os/osmatch"):
            name = os_node.get("name", "")
            accuracy = os_node.get("accuracy", "")
            if name:
                os_matches.append(f"{name} ({accuracy}%)")
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            service_node = port_node.find("service")
            port_id = int(port_node.get("portid", "0"))
            protocol = port_node.get("protocol", "tcp")
            service = service_node.get("name", "unknown") if service_node is not None else "unknown"
            version = ""
            extra: dict[str, Any] = {}
            if service_node is not None:
                version = service_node.get("version", "") or ""
                if service_node.get("product"):
                    extra["product"] = service_node.get("product")
                if service_node.get("extrainfo"):
                    extra["extrainfo"] = service_node.get("extrainfo")
                if service_node.get("ostype"):
                    extra["ostype"] = service_node.get("ostype")
                cpe = service_node.findall("cpe")
                if cpe:
                    extra["cpe"] = [node.text for node in cpe if node.text]
            parsed_ports.append(
                PortInfo(
                    port=port_id,
                    protocol=protocol,
                    state="open",
                    service=service,
                    version=version,
                    extra=extra,
                )
            )
    return parsed_ports, os_matches, ""


async def scan_host(
    hostname: str,
    ports: list[int],
    timeout: float = 1.5,
    concurrency: int = 200,
    grab_banners: bool = True,
) -> tuple[list[PortInfo], list[str]]:
    ips = resolve_all(hostname)
    if not ips:
        raise OSError(f"unable to resolve {hostname}")
    ip = ips[0]
    results = await scan_tcp(
        hostname,
        ip,
        ports,
        timeout=timeout,
        concurrency=concurrency,
        grab_banners=grab_banners,
    )
    return results, ips


def is_http_port(port: int, service: str = "") -> bool:
    return port in HTTP_PORTS or "http" in (service or "").lower()


def is_tls_port(port: int, service: str = "") -> bool:
    return port in TLS_PORTS or "https" in (service or "").lower()


def summarize_banner(banner: str) -> str:
    return truncate(re.sub(r"[\r\n]+", " ", banner or ""), 200)


def _struct_ntp() -> bytes:
    return struct.pack("!B", 0x1B) + b"\x00" * 47
