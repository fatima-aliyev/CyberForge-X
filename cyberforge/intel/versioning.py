"""Version parsing and constraint evaluation for CVE matching.

Supports normal releases, pre-releases (alpha/beta/rc), OpenSSH ``pN`` patches,
and distro suffixes such as ``2.4.49-ubuntu0.1``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_VERSION_RE = re.compile(
    r"(?<!\d)(\d+(?:\.\d+){0,3})"
    r"(?:[-_.]?(alpha|beta|pre|rc|dev)[-_.]?(\d+))?"
    r"(?:p(\d+))?",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_PRE_RANK = {"dev": 0, "alpha": 1, "beta": 2, "pre": 3, "rc": 4}


@dataclass(frozen=True)
class Version:
    parts: tuple[int, ...]
    prerelease: tuple[str, int] | None = None

    def __str__(self) -> str:
        base = ".".join(str(part) for part in self.parts)
        if self.prerelease:
            return f"{base}-{self.prerelease[0]}{self.prerelease[1]}"
        return base


def parse_version(value: str | None) -> Version | None:
    if not value:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    text = re.sub(r"^\d+:", "", text)
    text = text.replace("_", ".")
    match = _VERSION_RE.search(text)
    if not match:
        return None
    try:
        parts = tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None
    p_patch = match.group(4)
    if p_patch is not None:
        parts = (*parts, int(p_patch))
    pre_label = match.group(2)
    pre_number = int(match.group(3) or 0)
    prerelease = (pre_label.lower(), pre_number) if pre_label else None
    return Version(parts=parts, prerelease=prerelease)


def _pad_parts(first: tuple[int, ...], second: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    length = max(len(first), len(second))
    return (
        first + (0,) * (length - len(first)),
        second + (0,) * (length - len(second)),
    )


def compare_versions(first: Version | str, second: Version | str) -> int:
    left = first if isinstance(first, Version) else parse_version(first)
    right = second if isinstance(second, Version) else parse_version(second)
    if left is None or right is None:
        raise ValueError(f"cannot compare versions {first!r} and {second!r}")
    left_parts, right_parts = _pad_parts(left.parts, right.parts)
    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    if left.prerelease is None and right.prerelease is None:
        return 0
    if left.prerelease is None:
        return 1
    if right.prerelease is None:
        return -1
    left_rank = (_PRE_RANK.get(left.prerelease[0], 9), left.prerelease[1])
    right_rank = (_PRE_RANK.get(right.prerelease[0], 9), right.prerelease[1])
    return (left_rank > right_rank) - (left_rank < right_rank)


def version_in_constraint(version: Version | str, constraint: dict[str, Any]) -> bool:
    """Evaluate one {ge, gt, lt, le, eq} constraint object."""
    parsed = version if isinstance(version, Version) else parse_version(version)
    if parsed is None:
        return False
    for operator, raw in constraint.items():
        if operator not in {"ge", "gt", "lt", "le", "eq"}:
            continue
        target = parse_version(str(raw))
        if target is None:
            return False
        comparison = compare_versions(parsed, target)
        if operator == "ge" and comparison < 0:
            return False
        if operator == "gt" and comparison <= 0:
            return False
        if operator == "lt" and comparison >= 0:
            return False
        if operator == "le" and comparison > 0:
            return False
        if operator == "eq" and comparison != 0:
            return False
    return True


def version_matches(version: Version | str | None, constraints: list[dict[str, Any]] | None) -> bool:
    if version is None or not constraints:
        return False
    parsed = version if isinstance(version, Version) else parse_version(version)
    if parsed is None:
        return False
    return any(version_in_constraint(parsed, constraint) for constraint in constraints)


def extract_version(text: str) -> str:
    if not text:
        return ""
    normalized = str(text).replace("_", ".")
    match = _VERSION_RE.search(normalized)
    if not match:
        return ""
    value = match.group(1)
    if match.group(2):
        value += f"-{match.group(2).lower()}{match.group(3) or 0}"
    if match.group(4):
        value += f"p{match.group(4)}"
    return value


def tokenize(value: str) -> list[str]:
    return _TOKEN_RE.findall((value or "").lower())


def normalize_product_name(value: str) -> str:
    return " ".join(tokenize(value))


def alias_matches(product_name: str, alias: str) -> bool:
    """True when the alias tokens appear contiguously in the product name."""
    name_tokens = tokenize(product_name)
    alias_tokens = tokenize(alias)
    if not alias_tokens or not name_tokens:
        return False
    length = len(alias_tokens)
    for index in range(0, len(name_tokens) - length + 1):
        if name_tokens[index : index + length] == alias_tokens:
            return True
    return False


def match_product_aliases(product_name: str, aliases: list[str]) -> int:
    """Return the length of the longest matching alias (0 = no match)."""
    best = 0
    for alias in aliases:
        if alias_matches(product_name, alias):
            best = max(best, len(" ".join(tokenize(alias))))
    return best


def describe_constraints(constraints: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for constraint in constraints:
        joined = " and ".join(f"{op} {value}" for op, value in constraint.items())
        chunks.append(joined)
    return " or ".join(chunks)
