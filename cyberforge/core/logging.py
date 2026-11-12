"""Rich console logging plus structured JSONL audit logs."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

from cyberforge.core.utils import sanitize_headers, utc_now_iso

_LOGGER_NAME = "cyberforge"
_CONSOLE: Console | None = None


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": utc_now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "taskName",
            }:
                continue
            if key.startswith("_"):
                continue
            if key == "headers" and isinstance(value, dict):
                payload[key] = sanitize_headers(value)
            elif isinstance(value, (str, int, float, bool, list, dict, type(None))):
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(
    level: str = "INFO",
    jsonl_path: str | Path | None = None,
    quiet: bool = False,
) -> Console:
    global _CONSOLE
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = Console(stderr=False, highlight=False)
    _CONSOLE = console
    rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=False,
        show_time=True,
        markup=False,
        enable_link_path=False,
    )
    rich_handler.setLevel(logging.CRITICAL if quiet else getattr(logging, level.upper(), logging.INFO))
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(rich_handler)

    if jsonl_path:
        path = Path(jsonl_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonLineFormatter())
        root.addHandler(file_handler)

    for noisy in ("urllib3", "requests", "paramiko", "dnspython", "asyncio", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("charset_normalizer").setLevel(logging.ERROR)
    return console


def get_console() -> Console:
    global _CONSOLE
    if _CONSOLE is None:
        _CONSOLE = Console(highlight=False)
    return _CONSOLE


def get_logger(name: str) -> logging.Logger:
    if name.startswith(_LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")


def log_banner(console: Console, version: str) -> None:
    console.print(
        f"[bold cyan]CyberForge-X[/bold cyan] [dim]v{version}[/dim] "
        "[yellow]authorized, non-destructive assessment only[/yellow]"
    )
    if sys.platform == "win32":
        console.print("[dim]Windows host detected. Firewall prompts may appear for OOB callbacks.[/dim]")
