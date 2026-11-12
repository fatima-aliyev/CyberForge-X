from __future__ import annotations

import pytest

from cyberforge.core.config import ScanConfig
from cyberforge.core.exceptions import ConfigurationError


def test_minimal_config_validates() -> None:
    config = ScanConfig(targets=["https://example.test"])
    config.validate()
    assert config.max_pages == 40
    assert config.formats == ["json", "md", "html"]


def test_targets_are_required() -> None:
    with pytest.raises(ConfigurationError, match="target"):
        ScanConfig().validate()


def test_unknown_module_rejected() -> None:
    config = ScanConfig(targets=["example.test"], modules=["recon", "nope"])
    with pytest.raises(ConfigurationError, match="unknown modules"):
        config.validate()


def test_bad_report_format_rejected() -> None:
    config = ScanConfig(targets=["example.test"], formats=["pdf"])
    with pytest.raises(ConfigurationError, match="report formats"):
        config.validate()


def test_stored_xss_requires_form_submissions() -> None:
    config = ScanConfig(targets=["example.test"], allow_stored_xss=True)
    with pytest.raises(ConfigurationError, match="allow-form-submissions"):
        config.validate()


def test_jwt_active_tests_require_url() -> None:
    config = ScanConfig(targets=["example.test"], jwt_active_tests=True)
    with pytest.raises(ConfigurationError, match="jwt-test-url"):
        config.validate()


def test_values_are_clamped() -> None:
    config = ScanConfig(
        targets=["example.test"],
        workers=999,
        max_requests=1,
        crawl_depth=99,
        brute_max_attempts=999,
    )
    config.validate()
    assert config.workers == 32
    assert config.max_requests == 10
    assert config.crawl_depth == 8
    assert config.brute_max_attempts == 50


def test_empty_formats_rejected() -> None:
    with pytest.raises(ConfigurationError, match="report format"):
        ScanConfig(targets=["example.test"], formats=[]).validate()
