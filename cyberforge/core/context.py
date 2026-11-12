"""Shared module execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from cyberforge.core.config import ScanConfig
from cyberforge.core.logging import get_logger
from cyberforge.core.models import ResultBundle
from cyberforge.core.scope import Scope
from cyberforge.core.session import SafeSession

if TYPE_CHECKING:
    import logging

    from cyberforge.core.oob import OOBListener


@dataclass
class ModuleContext:
    config: ScanConfig
    scope: Scope
    bundle: ResultBundle
    session: SafeSession
    output_dir: Path
    oob: OOBListener | None = None
    logger: logging.Logger = field(init=False)

    def __post_init__(self) -> None:
        self.logger = get_logger("module")

    def new_session(
        self,
        extra_headers: dict[str, str] | None = None,
        clear_cookies: bool = False,
        name: str = "http",
    ) -> SafeSession:
        return self.session.clone(extra_headers=extra_headers, clear_cookies=clear_cookies, logger_name=name)
