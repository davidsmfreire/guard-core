from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.checks.helpers import (
    _get_detection_disabled_reason,
    _get_effective_penetration_setting,
    check_country_access,
    check_route_ip_access,
    check_user_agent_allowed,
    detect_penetration_patterns,
    is_ip_in_blacklist,
    is_ip_in_whitelist,
    is_referrer_domain_allowed,
    validate_auth_header,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


def test_is_ip_in_blacklist_exact():
    assert is_ip_in_blacklist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True
    assert is_ip_in_blacklist("1.2.3.5", ip_address("1.2.3.5"), ["1.2.3.4"]) is False


def test_is_ip_in_blacklist_cidr():
    assert (
        is_ip_in_blacklist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )
    assert (
        is_ip_in_blacklist("11.0.0.1", ip_address("11.0.0.1"), ["10.0.0.0/8"]) is False
    )


def test_is_ip_in_whitelist_empty():
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), []) is None


def test_is_ip_in_whitelist_exact():
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True
    assert is_ip_in_whitelist("1.2.3.5", ip_address("1.2.3.5"), ["1.2.3.4"]) is False


def test_is_ip_in_whitelist_cidr():
    assert (
        is_ip_in_whitelist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


def test_check_country_access_no_handler():
    rc = RouteConfig()
    rc.blocked_countries = ["US"]
    assert check_country_access("1.2.3.4", rc, None) is None


def test_check_country_access_blocked():
    rc = RouteConfig()
    rc.blocked_countries = ["US"]
    geo = MagicMock()
    geo.get_country.return_value = "US"
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_not_blocked():
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country.return_value = "US"
    assert check_country_access("1.2.3.4", rc, geo) is None


def test_check_country_access_whitelist():
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country.return_value = "US"
    assert check_country_access("1.2.3.4", rc, geo) is True


def test_check_country_access_whitelist_denied():
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country.return_value = "CN"
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_whitelist_no_country():
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country.return_value = None
    assert check_country_access("1.2.3.4", rc, geo) is False


async def test_check_route_ip_access_blacklisted():
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    middleware = MagicMock()
    middleware.geo_ip_handler = None
    result = await check_route_ip_access("1.2.3.4", rc, middleware)
    assert result is False


async def test_check_route_ip_access_whitelisted():
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    middleware = MagicMock()
    middleware.geo_ip_handler = None
    result = await check_route_ip_access("1.2.3.4", rc, middleware)
    assert result is True


async def test_check_route_ip_access_invalid_ip():
    rc = RouteConfig()
    middleware = MagicMock()
    result = await check_route_ip_access("invalid", rc, middleware)
    assert result is False


async def test_check_route_ip_access_no_rules():
    rc = RouteConfig()
    middleware = MagicMock()
    middleware.geo_ip_handler = None
    result = await check_route_ip_access("1.2.3.4", rc, middleware)
    assert result is None


async def test_check_user_agent_allowed_route_blocked():
    config = MagicMock()
    config.blocked_user_agents = []
    rc = RouteConfig()
    rc.blocked_user_agents = ["BadBot"]
    with patch(
        "guard_core.utils.is_user_agent_allowed",
        new_callable=AsyncMock,
        return_value=True,
    ):
        result = await check_user_agent_allowed("BadBot/1.0", rc, config)
    assert result is False


async def test_check_user_agent_allowed_global():
    config = MagicMock()
    with patch(
        "guard_core.utils.is_user_agent_allowed",
        new_callable=AsyncMock,
        return_value=True,
    ):
        result = await check_user_agent_allowed("Mozilla/5.0", None, config)
    assert result is True


def test_validate_auth_header_bearer():
    ok, msg = validate_auth_header("Bearer token123", "bearer")
    assert ok is True

    ok, msg = validate_auth_header("Basic abc", "bearer")
    assert ok is False


def test_validate_auth_header_basic():
    ok, msg = validate_auth_header("Basic abc", "basic")
    assert ok is True

    ok, msg = validate_auth_header("Bearer abc", "basic")
    assert ok is False


def test_validate_auth_header_custom():
    ok, msg = validate_auth_header("", "custom")
    assert ok is False

    ok, msg = validate_auth_header("CustomVal", "custom")
    assert ok is True


def test_is_referrer_domain_allowed():
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["example.com"]) is True
    )
    assert (
        is_referrer_domain_allowed("https://sub.example.com/page", ["example.com"])
        is True
    )
    assert is_referrer_domain_allowed("https://evil.com/page", ["example.com"]) is False
    assert is_referrer_domain_allowed("", ["example.com"]) is False


def test_get_effective_penetration_setting():
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    rc = RouteConfig()
    rc.enable_suspicious_detection = False
    enabled, route_specific = _get_effective_penetration_setting(config, rc)
    assert enabled is False
    assert route_specific is False


def test_get_detection_disabled_reason():
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    reason = _get_detection_disabled_reason(config, False)
    assert reason == "disabled_by_decorator"

    reason = _get_detection_disabled_reason(config, None)
    assert reason == "not_enabled"


async def test_detect_penetration_patterns_enabled():
    request = MockGuardRequest(query_params={"q": "normal"})
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    rc = RouteConfig()
    rc.enable_suspicious_detection = True

    def should_bypass(check_name, route_config):
        return False

    with patch(
        "guard_core.core.checks.helpers.detect_penetration_attempt",
        new_callable=AsyncMock,
        return_value=(False, ""),
    ):
        result, trigger = await detect_penetration_patterns(
            request, rc, config, should_bypass
        )
    assert result is False


async def test_detect_penetration_patterns_disabled():
    request = MockGuardRequest()
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)

    def should_bypass(check_name, route_config):
        return False

    result, trigger = await detect_penetration_patterns(
        request, None, config, should_bypass
    )
    assert result is False
    assert trigger == "not_enabled"


async def test_detect_penetration_patterns_bypassed():
    request = MockGuardRequest()
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    rc = RouteConfig()

    def should_bypass(check_name, route_config):
        return True

    result, trigger = await detect_penetration_patterns(
        request, rc, config, should_bypass
    )
    assert result is False


async def test_check_route_ip_access_country_blocked():
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    middleware = MagicMock()
    geo = MagicMock()
    geo.get_country.return_value = "CN"
    middleware.geo_ip_handler = geo
    result = await check_route_ip_access("1.2.3.4", rc, middleware)
    assert result is False


def test_is_referrer_domain_allowed_exception():
    result = is_referrer_domain_allowed(None, ["example.com"])
    assert result is False
