import pytest

from guard_core.models import DynamicRules, SecurityConfig


def test_security_config_defaults() -> None:
    config = SecurityConfig(enable_redis=False)
    assert config.rate_limit == 10
    assert config.rate_limit_window == 60
    assert config.passive_mode is False
    assert config.enforce_https is False
    assert config.redis_prefix == "guard_core:"
    assert config.enable_ip_banning is True
    assert config.enable_rate_limiting is True
    assert config.enable_penetration_detection is True


def test_security_config_ip_validation() -> None:
    config = SecurityConfig(
        enable_redis=False,
        whitelist=["192.168.1.1", "10.0.0.0/8"],
        blacklist=["172.16.0.0/12"],
    )
    assert "192.168.1.1" in config.whitelist
    assert "10.0.0.0/8" in config.whitelist
    assert "172.16.0.0/12" in config.blacklist


def test_security_config_invalid_ip() -> None:
    with pytest.raises(ValueError, match="Invalid IP"):
        SecurityConfig(enable_redis=False, whitelist=["not-an-ip"])


def test_security_config_cloud_providers() -> None:
    config = SecurityConfig(
        enable_redis=False,
        block_cloud_providers={"AWS", "GCP", "InvalidProvider"},
    )
    assert config.block_cloud_providers == {"AWS", "GCP"}


def test_security_config_agent_requires_api_key() -> None:
    with pytest.raises(ValueError, match="agent_api_key"):
        SecurityConfig(enable_redis=False, enable_agent=True)


def test_security_config_dynamic_rules_require_agent() -> None:
    with pytest.raises(ValueError, match="enable_agent must be True"):
        SecurityConfig(
            enable_redis=False,
            enable_dynamic_rules=True,
            enable_agent=False,
        )


def test_security_config_trusted_proxy_validation() -> None:
    config = SecurityConfig(
        enable_redis=False,
        trusted_proxies=["10.0.0.1", "172.16.0.0/16"],
    )
    assert "10.0.0.1" in config.trusted_proxies
    assert "172.16.0.0/16" in config.trusted_proxies


def test_security_config_proxy_depth_validation() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        SecurityConfig(enable_redis=False, trusted_proxy_depth=0)


def test_dynamic_rules_defaults() -> None:
    from datetime import datetime, timezone

    rules = DynamicRules(
        rule_id="test-1",
        version=1,
        timestamp=datetime.now(timezone.utc),
    )
    assert rules.ttl == 300
    assert rules.ip_blacklist == []
    assert rules.emergency_mode is False


def test_to_agent_config_disabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    result = config.to_agent_config()
    assert result is None


def test_to_agent_config_no_api_key() -> None:
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    result = config.to_agent_config()
    assert result is None


def test_to_agent_config_import_error() -> None:
    from unittest.mock import patch

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-key",
    )
    with patch.dict("sys.modules", {"guard_agent": None}):
        result = config.to_agent_config()
    assert result is None


def test_to_agent_config_success() -> None:
    from unittest.mock import MagicMock, patch

    mock_module = MagicMock()
    mock_agent_config = MagicMock()
    mock_module.AgentConfig = MagicMock(return_value=mock_agent_config)

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-key",
    )
    with patch.dict("sys.modules", {"guard_agent": mock_module}):
        result = config.to_agent_config()
    assert result is mock_agent_config


def test_security_config_invalid_trusted_proxy() -> None:
    with pytest.raises(ValueError, match="Invalid"):
        SecurityConfig(enable_redis=False, trusted_proxies=["not-an-ip"])


def test_security_config_custom_error_responses() -> None:
    config = SecurityConfig(
        enable_redis=False,
        custom_error_responses={403: "Custom Forbidden", 429: "Slow down"},
    )
    assert config.custom_error_responses[403] == "Custom Forbidden"


def test_security_config_exclude_paths() -> None:
    config = SecurityConfig(
        enable_redis=False,
        exclude_paths=["/health", "/metrics"],
    )
    assert "/health" in config.exclude_paths


def test_security_config_blocked_user_agents() -> None:
    config = SecurityConfig(
        enable_redis=False,
        blocked_user_agents=["bot", "spider"],
    )
    assert "bot" in config.blocked_user_agents


def test_dynamic_rules_with_ip_rules() -> None:
    from datetime import datetime, timezone

    rules = DynamicRules(
        rule_id="test",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["1.2.3.4"],
        ip_whitelist=["5.6.7.8"],
        ip_ban_duration=7200,
        blocked_countries=["CN"],
        whitelist_countries=["US"],
        blocked_user_agents=["BadBot"],
        global_rate_limit=100,
        global_rate_window=60,
        endpoint_rate_limits={"/api": (50, 30)},
        emergency_mode=True,
        emergency_whitelist=["10.0.0.1"],
    )
    assert rules.ip_blacklist == ["1.2.3.4"]
    assert rules.emergency_mode is True


def test_validate_ip_lists_none() -> None:
    config = SecurityConfig(enable_redis=False, whitelist=None)
    assert config.whitelist is None


def test_validate_trusted_proxies_empty() -> None:
    config = SecurityConfig(enable_redis=False, trusted_proxies=[])
    assert config.trusted_proxies == []


def test_validate_proxy_depth_valid() -> None:
    config = SecurityConfig(enable_redis=False, trusted_proxy_depth=3)
    assert config.trusted_proxy_depth == 3


def test_validate_cloud_providers_none() -> None:
    config = SecurityConfig(enable_redis=False, block_cloud_providers=None)
    assert config.block_cloud_providers == set()


def test_geo_ip_handler_auto_creation() -> None:
    from unittest.mock import patch

    with patch("guard_core.handlers.ipinfo_handler.IPInfoManager") as mock_ipinfo:
        mock_ipinfo.return_value = mock_ipinfo
        config = SecurityConfig(
            enable_redis=False,
            blocked_countries=["CN"],
            ipinfo_token="test-token",
        )
    assert config.geo_ip_handler is not None


def test_geo_ip_handler_missing_token() -> None:
    with pytest.raises(ValueError, match="geo_ip_handler is required"):
        SecurityConfig(
            enable_redis=False,
            blocked_countries=["CN"],
        )
