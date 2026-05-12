import logging
from unittest.mock import MagicMock

import pytest


def test_sync_is_private_or_loopback_basic() -> None:
    from guard_core.sync.utils import _is_private_or_loopback

    assert _is_private_or_loopback("10.0.0.1") is True
    assert _is_private_or_loopback("8.8.8.8") is False


def test_sync_no_geolocation_logs_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    from guard_core.sync.utils import _log_country_check_result

    caplog.set_level(logging.DEBUG, logger="root")
    _log_country_check_result("192.168.1.1", None, "no_geolocation")
    geo_records = [r for r in caplog.records if "not geolocated" in r.message]
    assert geo_records
    assert all(r.levelno == logging.DEBUG for r in geo_records)


def test_sync_no_rules_logs_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    from guard_core.sync.utils import _log_country_check_result

    caplog.set_level(logging.DEBUG, logger="root")
    _log_country_check_result("192.168.1.1", None, "no_rules")
    no_rules = [r for r in caplog.records if "No countries blocked" in r.message]
    assert no_rules
    assert all(r.levelno == logging.DEBUG for r in no_rules)


def test_sync_spoof_warning_at_debug_for_private_source(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import extract_client_ip

    request = MagicMock()
    request.state = MagicMock()
    request.state.client_ip = None
    request.client_host = "192.168.65.1"
    request.headers = {"X-Forwarded-For": "192.168.65.1"}

    config = MagicMock()
    config.trusted_proxies = ["10.0.0.1"]
    config.trusted_proxy_depth = 1

    caplog.set_level(logging.DEBUG, logger="root")
    extract_client_ip(request, config, agent_handler=None)
    spoof_records = [r for r in caplog.records if "Potential IP spoof" in r.message]
    assert spoof_records
    assert all(r.levelno == logging.DEBUG for r in spoof_records)


def test_sync_spoof_warning_at_warning_for_public_source(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import extract_client_ip

    request = MagicMock()
    request.state = MagicMock()
    request.state.client_ip = None
    request.client_host = "8.8.8.8"
    request.headers = {"X-Forwarded-For": "1.2.3.4"}

    config = MagicMock()
    config.trusted_proxies = ["10.0.0.1"]
    config.trusted_proxy_depth = 1

    caplog.set_level(logging.DEBUG, logger="root")
    extract_client_ip(request, config, agent_handler=None)
    spoof_records = [r for r in caplog.records if "Potential IP spoof" in r.message]
    assert spoof_records
    assert all(r.levelno == logging.WARNING for r in spoof_records)
