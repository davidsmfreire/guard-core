import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.models import SecurityConfig
from guard_core.utils import (
    _extract_from_forwarded_header,
    _extract_request_context,
    _is_trusted_proxy,
    _sanitize_for_log,
    extract_client_ip,
    is_user_agent_allowed,
    setup_custom_logging,
)
from tests.conftest import MockGuardRequest


def test_sanitize_for_log() -> None:
    assert _sanitize_for_log("normal text") == "normal text"
    assert _sanitize_for_log("line\nbreak") == "line\\nbreak"
    assert _sanitize_for_log("carriage\rreturn") == "carriage\\rreturn"
    assert _sanitize_for_log("") == ""


def test_is_trusted_proxy() -> None:
    assert _is_trusted_proxy("10.0.0.1", ["10.0.0.1"]) is True
    assert _is_trusted_proxy("10.0.0.2", ["10.0.0.1"]) is False
    assert _is_trusted_proxy("10.0.0.5", ["10.0.0.0/24"]) is True
    assert _is_trusted_proxy("invalid", ["10.0.0.1"]) is False


def test_extract_from_forwarded_header() -> None:
    assert _extract_from_forwarded_header("1.2.3.4, 5.6.7.8", 1) == "1.2.3.4"
    assert _extract_from_forwarded_header("1.2.3.4", 1) == "1.2.3.4"
    assert _extract_from_forwarded_header("", 1) is None


async def test_extract_client_ip_no_client() -> None:
    request = MockGuardRequest(client_host=None)
    config = SecurityConfig(enable_redis=False)
    result = await extract_client_ip(request, config)
    assert result == "unknown"


async def test_extract_client_ip_direct() -> None:
    request = MockGuardRequest(client_host="192.168.1.100")
    config = SecurityConfig(enable_redis=False)
    result = await extract_client_ip(request, config)
    assert result == "192.168.1.100"


async def test_extract_client_ip_trusted_proxy() -> None:
    request = MockGuardRequest(
        client_host="10.0.0.1",
        headers={"X-Forwarded-For": "203.0.113.50, 10.0.0.1"},
    )
    config = SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.1"])
    result = await extract_client_ip(request, config)
    assert result == "203.0.113.50"


async def test_extract_client_ip_untrusted_proxy() -> None:
    request = MockGuardRequest(
        client_host="192.168.1.100",
        headers={"X-Forwarded-For": "10.10.10.10"},
    )
    config = SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.1"])
    result = await extract_client_ip(request, config)
    assert result == "192.168.1.100"


def test_extract_request_context() -> None:
    request = MockGuardRequest(path="/api/test", method="POST", client_host="1.2.3.4")
    context = _extract_request_context(request)
    assert context["client_ip"] == "1.2.3.4"
    assert context["method"] == "POST"
    assert "/api/test" in context["url"]


def test_extract_request_context_no_client() -> None:
    request = MockGuardRequest(client_host=None)
    context = _extract_request_context(request)
    assert context["client_ip"] == "unknown"


async def test_is_user_agent_allowed() -> None:
    config = SecurityConfig(
        enable_redis=False, blocked_user_agents=["BadBot", "scrapy"]
    )
    assert await is_user_agent_allowed("Mozilla/5.0", config) is True
    assert await is_user_agent_allowed("BadBot/1.0", config) is False
    assert await is_user_agent_allowed("Scrapy/2.0", config) is False


def test_setup_custom_logging() -> None:
    logger = setup_custom_logging()
    assert logger.name == "guard_core"
    assert len(logger.handlers) > 0


def test_setup_custom_logging_json() -> None:
    logger = setup_custom_logging(log_format="json")
    assert logger.name == "guard_core"


def test_setup_custom_logging_with_file(tmp_path: Path) -> None:
    log_file = str(tmp_path / "test.log")
    logger = setup_custom_logging(log_file=log_file)
    assert len(logger.handlers) == 2


async def test_detect_penetration_attempt_clean() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/api/users",
        query_params={"name": "john"},
        headers={"X-Custom": "safe-value"},
        body_content=b"normal body",
    )
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(return_value={"is_threat": False, "threats": []})
        result, trigger = await detect_penetration_attempt(request)
    assert result is False


async def test_detect_penetration_attempt_query_param_threat() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/api",
        query_params={"q": "'; DROP TABLE users;--"},
    )
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            return_value={
                "is_threat": True,
                "threats": [{"type": "regex", "pattern": "DROP TABLE"}],
            }
        )
        result, trigger = await detect_penetration_attempt(request)
    assert result is True
    assert "Query param" in trigger


async def test_detect_penetration_attempt_url_path_threat() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/../../etc/passwd",
        query_params={},
    )
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            side_effect=[
                {"is_threat": False, "threats": []},
                {
                    "is_threat": True,
                    "threats": [{"type": "regex", "pattern": "etc/passwd"}],
                },
            ]
        )

        async def detect_side_effect(**kwargs: Any) -> dict[str, Any]:
            context = kwargs.get("context", "")
            if "url_path" in context:
                return {
                    "is_threat": True,
                    "threats": [{"type": "regex", "pattern": "traversal"}],
                }
            return {"is_threat": False, "threats": []}

        mock_sus.detect = AsyncMock(side_effect=detect_side_effect)
        result, trigger = await detect_penetration_attempt(request)
    assert result is True
    assert "URL path" in trigger


async def test_detect_penetration_attempt_header_threat() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/api",
        query_params={},
        headers={"X-Evil": "<script>alert(1)</script>"},
    )
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:

        async def detect_side_effect(**kwargs: Any) -> dict[str, Any]:
            context = kwargs.get("context", "")
            if "header" in context:
                return {
                    "is_threat": True,
                    "threats": [{"type": "regex", "pattern": "script"}],
                }
            return {"is_threat": False, "threats": []}

        mock_sus.detect = AsyncMock(side_effect=detect_side_effect)
        result, trigger = await detect_penetration_attempt(request)
    assert result is True
    assert "Header" in trigger


async def test_detect_penetration_attempt_body_threat() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/api",
        query_params={},
        headers={},
        body_content=b"<script>alert(1)</script>",
    )
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:

        async def detect_side_effect(**kwargs: Any) -> dict[str, Any]:
            context = kwargs.get("context", "")
            if "request_body" in context:
                return {
                    "is_threat": True,
                    "threats": [{"type": "regex", "pattern": "script"}],
                }
            return {"is_threat": False, "threats": []}

        mock_sus.detect = AsyncMock(side_effect=detect_side_effect)
        result, trigger = await detect_penetration_attempt(request)
    assert result is True
    assert "Request body" in trigger


async def test_detect_penetration_attempt_body_decode_error() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/api",
        query_params={},
        headers={},
    )

    async def bad_body() -> Any:
        raise Exception("decode error")

    request.body = bad_body

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(return_value={"is_threat": False, "threats": []})
        result, trigger = await detect_penetration_attempt(request)
    assert result is False


async def test_detect_penetration_attempt_no_client() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/api",
        client_host=None,
        query_params={},
        headers={},
    )
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(return_value={"is_threat": False, "threats": []})
        result, trigger = await detect_penetration_attempt(request)
    assert result is False


async def test_is_ip_allowed_basic() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False)
    result = await is_ip_allowed("1.2.3.4", config)
    assert result is True


async def test_is_ip_allowed_blacklisted() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, blacklist=["1.2.3.4"])
    result = await is_ip_allowed("1.2.3.4", config)
    assert result is False


async def test_is_ip_allowed_whitelisted() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, whitelist=["1.2.3.4"])
    result = await is_ip_allowed("1.2.3.4", config)
    assert result is True


async def test_is_ip_allowed_not_in_whitelist() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, whitelist=["5.6.7.8"])
    result = await is_ip_allowed("1.2.3.4", config)
    assert result is False


async def test_is_ip_allowed_invalid_ip() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False)
    result = await is_ip_allowed("invalid", config)
    assert result is False


async def test_is_ip_allowed_cidr_blacklist() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, blacklist=["10.0.0.0/8"])
    result = await is_ip_allowed("10.0.0.1", config)
    assert result is False


async def test_is_ip_allowed_cidr_whitelist() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, whitelist=["10.0.0.0/8"])
    result = await is_ip_allowed("10.0.0.1", config)
    assert result is True


async def test_check_ip_country() -> None:
    from unittest.mock import MagicMock

    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country.return_value = "CN"
    result = await check_ip_country("1.2.3.4", config, geo)
    assert result is True


async def test_check_ip_country_no_rules() -> None:
    from unittest.mock import MagicMock

    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = []
    config.whitelist_countries = []
    geo = MagicMock()
    result = await check_ip_country("1.2.3.4", config, geo)
    assert result is False


async def test_check_ip_country_whitelisted() -> None:
    from unittest.mock import MagicMock

    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = []
    config.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country.return_value = "US"
    result = await check_ip_country("1.2.3.4", config, geo)
    assert result is False


async def test_log_activity_levels() -> None:
    import logging

    from guard_core.utils import log_activity

    request = MockGuardRequest()
    logger = logging.getLogger("test_log")

    await log_activity(request, logger, log_type="request", level="INFO")
    await log_activity(
        request, logger, log_type="suspicious", reason="test", level="WARNING"
    )
    await log_activity(request, logger, log_type="custom", reason="test", level="ERROR")
    await log_activity(
        request,
        logger,
        log_type="suspicious",
        reason="test",
        passive_mode=True,
        trigger_info="xss",
        level="DEBUG",
    )
    await log_activity(
        request,
        logger,
        log_type="suspicious",
        reason="test",
        passive_mode=True,
        trigger_info="",
        level="CRITICAL",
    )
    await log_activity(request, logger, level=None)


async def test_send_agent_event_no_agent() -> None:
    from guard_core.utils import send_agent_event

    await send_agent_event(None, "test", "1.2.3.4", "action", "reason")


async def test_send_agent_event_with_request() -> None:
    from unittest.mock import MagicMock, patch

    from guard_core.utils import send_agent_event

    agent = AsyncMock()
    request = MockGuardRequest()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await send_agent_event(agent, "test", "1.2.3.4", "action", "reason", request)
    agent.send_event.assert_called_once()


async def test_send_agent_event_error() -> None:
    from unittest.mock import MagicMock

    from guard_core.utils import send_agent_event

    agent = AsyncMock()
    agent.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await send_agent_event(agent, "test", "1.2.3.4", "action", "reason")


def test_build_threat_message() -> None:
    from guard_core.utils import _build_threat_message

    assert "pattern" in _build_threat_message({"type": "regex", "pattern": "test"})
    assert "Semantic" in _build_threat_message(
        {"type": "semantic", "attack_type": "xss", "probability": 0.9}
    )
    assert "Threat" in _build_threat_message({"type": "unknown"})


async def test_check_value_enhanced_json() -> None:
    from guard_core.utils import _check_value_enhanced

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            return_value={
                "is_threat": True,
                "threats": [{"type": "regex", "pattern": "evil"}],
            }
        )
        result, trigger = await _check_value_enhanced(
            '{"key": "evil"}', "test", "1.2.3.4", "corr-id"
        )
    assert result is True


async def test_check_value_enhanced_fallback() -> None:
    from guard_core.utils import _check_value_enhanced

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(side_effect=Exception("fail"))
        mock_sus.get_all_compiled_patterns = AsyncMock(return_value=[])
        result, trigger = await _check_value_enhanced(
            "test value", "test", "1.2.3.4", "corr-id"
        )
    assert result is False


async def test_check_ip_spoofing_with_forwarded_no_proxies() -> None:
    from guard_core.utils import _check_ip_spoofing

    config = MagicMock()
    config.trusted_proxies = []
    request = MockGuardRequest(headers={"X-Forwarded-For": "1.2.3.4"})
    agent = AsyncMock()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await _check_ip_spoofing("5.6.7.8", "1.2.3.4", config, request, agent)


async def test_extract_client_ip_forwarded_but_untrusted() -> None:
    config = SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.1"])
    request = MockGuardRequest(
        client_host="5.5.5.5",
        headers={"X-Forwarded-For": "1.2.3.4"},
    )
    result = await extract_client_ip(request, config)
    assert result == "5.5.5.5"


async def test_extract_client_ip_trusted_no_forwarded() -> None:
    config = SecurityConfig(enable_redis=False, trusted_proxies=["127.0.0.1"])
    request = MockGuardRequest(client_host="127.0.0.1")
    result = await extract_client_ip(request, config)
    assert result == "127.0.0.1"


async def test_is_ip_allowed_blocked_country() -> None:
    from guard_core.utils import is_ip_allowed

    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country.return_value = "CN"

    config = MagicMock()
    config.blacklist = []
    config.whitelist = []
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    config.block_cloud_providers = set()

    result = await is_ip_allowed("1.2.3.4", config, geo)
    assert result is False


async def test_is_ip_allowed_cloud_blocked() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, block_cloud_providers={"AWS"})
    with patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud:
        mock_cloud.is_cloud_ip.return_value = True
        result = await is_ip_allowed("1.2.3.4", config)
    assert result is False


async def test_is_ip_allowed_cloud_not_blocked() -> None:
    from guard_core.utils import is_ip_allowed

    config = SecurityConfig(enable_redis=False, block_cloud_providers={"AWS"})
    with patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud:
        mock_cloud.is_cloud_ip.return_value = False
        result = await is_ip_allowed("1.2.3.4", config)
    assert result is True


async def test_check_ip_country_no_geolocation() -> None:
    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country.return_value = None
    result = await check_ip_country("1.2.3.4", config, geo)
    assert result is False


async def test_check_ip_country_not_initialized() -> None:
    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = False
    geo.initialize = AsyncMock()
    geo.get_country.return_value = "US"
    await check_ip_country("1.2.3.4", config, geo)
    geo.initialize.assert_called_once()


async def test_check_ip_country_not_affected() -> None:
    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country.return_value = "US"
    result = await check_ip_country("1.2.3.4", config, geo)
    assert result is False


async def test_check_ip_country_with_request_object() -> None:
    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country.return_value = "US"
    request = MockGuardRequest(client_host="1.2.3.4")
    result = await check_ip_country(request, config, geo)
    assert result is False


async def test_check_json_fields() -> None:
    from guard_core.utils import _check_json_fields

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            return_value={
                "is_threat": True,
                "threats": [{"type": "regex", "pattern": "evil"}],
            }
        )
        result, trigger = await _check_json_fields(
            {"key": "evil_val"}, "test", "1.2.3.4", "corr"
        )
    assert result is True
    assert "JSON field" in trigger


async def test_check_json_fields_semantic_threat() -> None:
    from guard_core.utils import _check_json_fields

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            return_value={
                "is_threat": True,
                "threats": [{"type": "semantic", "attack_type": "xss"}],
            }
        )
        result, trigger = await _check_json_fields(
            {"key": "value"}, "test", "1.2.3.4", "corr"
        )
    assert result is True


async def test_check_json_fields_no_specific_threats() -> None:
    from guard_core.utils import _check_json_fields

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            return_value={
                "is_threat": True,
                "threats": [],
            }
        )
        result, trigger = await _check_json_fields(
            {"key": "value"}, "test", "1.2.3.4", "corr"
        )
    assert result is True
    assert "contains threat" in trigger


async def test_fallback_pattern_check() -> None:
    import re

    from guard_core.utils import _fallback_pattern_check

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.get_all_compiled_patterns = AsyncMock(
            return_value=[
                (re.compile(r"evil"), {"unknown"}),
            ]
        )
        result, trigger = await _fallback_pattern_check("this is evil content")
    assert result is True


async def test_fallback_pattern_check_no_match() -> None:
    import re

    from guard_core.utils import _fallback_pattern_check

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.get_all_compiled_patterns = AsyncMock(
            return_value=[
                (re.compile(r"evil"), {"unknown"}),
            ]
        )
        result, trigger = await _fallback_pattern_check("safe content")
    assert result is False


async def test_check_value_enhanced_no_threat() -> None:
    from guard_core.utils import _check_value_enhanced

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(return_value={"is_threat": False, "threats": []})
        result, trigger = await _check_value_enhanced("safe", "test", "1.2.3.4", "corr")
    assert result is False


async def test_check_value_enhanced_threat_no_details() -> None:
    from guard_core.utils import _check_value_enhanced

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(return_value={"is_threat": True, "threats": []})
        result, trigger = await _check_value_enhanced("evil", "test", "1.2.3.4", "corr")
    assert result is True
    assert trigger == "Threat detected"


async def test_check_request_component_long_value() -> None:
    from guard_core.utils import _check_request_component

    long_value = "x" * 200
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(
            return_value={
                "is_threat": True,
                "threats": [{"type": "regex", "pattern": "test"}],
            }
        )
        result, trigger = await _check_request_component(
            long_value, "test", "component", "1.2.3.4", "corr"
        )
    assert result is True


def test_log_at_level() -> None:
    from guard_core.utils import _log_at_level

    logger = logging.getLogger("test_levels")
    _log_at_level(logger, "INFO", "info msg")
    _log_at_level(logger, "DEBUG", "debug msg")
    _log_at_level(logger, "WARNING", "warning msg")
    _log_at_level(logger, "ERROR", "error msg")
    _log_at_level(logger, "CRITICAL", "critical msg")


def test_extract_ip_from_request() -> None:
    from guard_core.utils import _extract_ip_from_request

    assert _extract_ip_from_request("1.2.3.4") == "1.2.3.4"
    assert (
        _extract_ip_from_request(MockGuardRequest(client_host="5.6.7.8")) == "5.6.7.8"
    )
    assert _extract_ip_from_request(MockGuardRequest(client_host=None)) == "unknown"


def test_evaluate_country_access() -> None:
    from guard_core.utils import _evaluate_country_access

    config = MagicMock()
    config.whitelist_countries = ["US"]
    config.blocked_countries = ["CN"]

    is_blocked, result_type = _evaluate_country_access("US", config)
    assert is_blocked is False
    assert result_type == "whitelisted"

    is_blocked, result_type = _evaluate_country_access("CN", config)
    assert is_blocked is True
    assert result_type == "blocked"

    is_blocked, result_type = _evaluate_country_access("DE", config)
    assert is_blocked is False
    assert result_type == "not_affected"


def test_build_threat_message_semantic_with_threat_score() -> None:
    from guard_core.utils import _build_threat_message

    msg = _build_threat_message(
        {"type": "semantic", "attack_type": "xss", "threat_score": 0.85}
    )
    assert "0.85" in msg


def test_json_formatter() -> None:
    import json

    from guard_core.utils import JsonFormatter

    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="test message",
        args=None,
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["message"] == "test message"
    assert parsed["level"] == "INFO"
    assert "timestamp" in parsed


def test_setup_custom_logging_file_error() -> None:
    logger = setup_custom_logging(log_file="/nonexistent/path/to/file.log")
    assert len(logger.handlers) == 1


def test_extract_from_forwarded_header_insufficient_depth() -> None:
    result = _extract_from_forwarded_header("1.2.3.4", 5)
    assert result is None


async def test_extract_client_ip_trusted_proxy_value_error() -> None:
    class BadConfig:
        trusted_proxies = ["10.0.0.1"]

        @property
        def trusted_proxy_depth(self) -> int:
            raise ValueError("bad depth")

    request = MockGuardRequest(
        client_host="10.0.0.1",
        headers={"X-Forwarded-For": "1.2.3.4"},
    )
    result = await extract_client_ip(request, BadConfig())
    assert result == "10.0.0.1"


async def test_is_ip_allowed_generic_exception() -> None:
    from guard_core.utils import is_ip_allowed

    config = MagicMock()
    config.blacklist = None
    config.whitelist = None
    config.blocked_countries = None
    config.whitelist_countries = None
    config.block_cloud_providers = set()

    with patch("guard_core.utils._check_blacklist", new_callable=AsyncMock) as mock_bl:
        mock_bl.side_effect = RuntimeError("unexpected")
        result = await is_ip_allowed("1.2.3.4", config)
    assert result is True


async def test_check_json_fields_no_string_values() -> None:
    from guard_core.utils import _check_json_fields

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.detect = AsyncMock(return_value={"is_threat": False, "threats": []})
        result, trigger = await _check_json_fields(
            {"key": 123, "other": True}, "test", "1.2.3.4", "corr"
        )
    assert result is False
    assert trigger == ""


async def test_fallback_pattern_check_exception() -> None:

    from guard_core.utils import _fallback_pattern_check

    bad_pattern = MagicMock()
    bad_pattern.search = MagicMock(side_effect=Exception("regex error"))

    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_sus:
        mock_sus.get_all_compiled_patterns = AsyncMock(
            return_value=[
                (bad_pattern, {"unknown"}),
            ]
        )
        result, trigger = await _fallback_pattern_check("content")
    assert result is False
