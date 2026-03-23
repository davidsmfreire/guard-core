from unittest.mock import Mock

import pytest

from guard_core.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    RouteConfig,
    get_route_decorator_config,
)
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


async def test_route_config_initialization() -> None:
    config = RouteConfig()

    assert config.rate_limit is None
    assert config.rate_limit_window is None
    assert config.ip_whitelist is None
    assert config.ip_blacklist is None
    assert config.blocked_countries is None
    assert config.whitelist_countries is None
    assert config.bypassed_checks == set()
    assert config.require_https is False
    assert config.auth_required is None
    assert config.custom_validators == []
    assert config.blocked_user_agents == []
    assert config.required_headers == {}
    assert config.behavior_rules == []
    assert config.block_cloud_providers == set()
    assert config.max_request_size is None
    assert config.allowed_content_types is None
    assert config.time_restrictions is None
    assert config.enable_suspicious_detection is True
    assert config.require_referrer is None
    assert config.api_key_required is False
    assert config.session_limits is None


async def test_base_security_mixin_not_implemented() -> None:
    mixin = BaseSecurityMixin()

    mock_func = Mock()

    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._ensure_route_config(mock_func)

    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._apply_route_config(mock_func)


async def test_base_security_decorator(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)

    assert decorator.config == security_config
    assert decorator._route_configs == {}
    assert decorator.behavior_tracker is not None

    mock_func = Mock()
    mock_func.__module__ = "test_module"
    mock_func.__qualname__ = "test_function"

    route_id = decorator._get_route_id(mock_func)
    assert route_id == "test_module.test_function"

    route_config = decorator._ensure_route_config(mock_func)
    assert isinstance(route_config, RouteConfig)
    assert (
        route_config.enable_suspicious_detection
        == security_config.enable_penetration_detection
    )

    route_config2 = decorator._ensure_route_config(mock_func)
    assert route_config is route_config2

    retrieved_config = decorator.get_route_config(route_id)
    assert retrieved_config is route_config

    non_existent_config = decorator.get_route_config("non.existent.route")
    assert non_existent_config is None

    decorated_func = decorator._apply_route_config(mock_func)
    assert decorated_func is mock_func
    assert hasattr(decorated_func, "_guard_route_id")
    assert decorated_func._guard_route_id == route_id


async def test_get_route_decorator_config() -> None:
    security_config = SecurityConfig(enable_redis=False)
    decorator = BaseSecurityDecorator(security_config)

    mock_request = MockGuardRequest(scope={})
    result = get_route_decorator_config(mock_request, decorator)
    assert result is None

    route_mock = Mock()
    route_mock.endpoint = None
    mock_request2 = MockGuardRequest(scope={"route": route_mock})
    result = get_route_decorator_config(mock_request2, decorator)
    assert result is None

    mock_endpoint = Mock()
    route_mock.endpoint = mock_endpoint
    mock_request3 = MockGuardRequest(scope={"route": route_mock})
    result = get_route_decorator_config(mock_request3, decorator)
    assert result is None

    route_id = "test.route.id"
    mock_endpoint._guard_route_id = route_id

    route_config = decorator._ensure_route_config(
        Mock(__module__="test", __qualname__="route")
    )
    decorator._route_configs[route_id] = route_config

    mock_request4 = MockGuardRequest(scope={"route": route_mock})
    result = get_route_decorator_config(mock_request4, decorator)
    assert result is route_config


async def test_initialize_behavior_tracking(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)

    await decorator.initialize_behavior_tracking()

    mock_redis_handler = Mock()
    await decorator.initialize_behavior_tracking(mock_redis_handler)


async def test_initialize_agent(security_config: SecurityConfig) -> None:
    from unittest.mock import AsyncMock

    decorator = BaseSecurityDecorator(security_config)
    agent = AsyncMock()
    await decorator.initialize_agent(agent)
    assert decorator.agent_handler is agent


async def test_send_decorator_event_no_agent(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)
    request = MockGuardRequest()
    await decorator.send_decorator_event("test", request, "action", "reason", "type")


async def test_send_decorator_event_with_agent(security_config: SecurityConfig) -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    decorator = BaseSecurityDecorator(security_config)
    decorator.agent_handler = AsyncMock()
    request = MockGuardRequest()
    with (
        patch(
            "guard_core.utils.extract_client_ip",
            new_callable=AsyncMock,
            return_value="1.2.3.4",
        ),
        patch.dict("sys.modules", {"guard_agent": MagicMock()}),
    ):
        await decorator.send_decorator_event(
            "test", request, "action", "reason", "type"
        )
    decorator.agent_handler.send_event.assert_called_once()


async def test_send_decorator_event_error(security_config: SecurityConfig) -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    decorator = BaseSecurityDecorator(security_config)
    decorator.agent_handler = AsyncMock()
    decorator.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    request = MockGuardRequest()
    with (
        patch(
            "guard_core.utils.extract_client_ip",
            new_callable=AsyncMock,
            return_value="1.2.3.4",
        ),
        patch.dict("sys.modules", {"guard_agent": MagicMock()}),
    ):
        await decorator.send_decorator_event(
            "test", request, "action", "reason", "type"
        )


async def test_send_access_denied_event(security_config: SecurityConfig) -> None:
    from unittest.mock import AsyncMock, patch

    decorator = BaseSecurityDecorator(security_config)
    request = MockGuardRequest()
    with patch.object(
        decorator, "send_decorator_event", new_callable=AsyncMock
    ) as mock:
        await decorator.send_access_denied_event(request, "reason", "type")
        mock.assert_called_once()


async def test_send_authentication_failed_event(
    security_config: SecurityConfig,
) -> None:
    from unittest.mock import AsyncMock, patch

    decorator = BaseSecurityDecorator(security_config)
    request = MockGuardRequest()
    with patch.object(
        decorator, "send_decorator_event", new_callable=AsyncMock
    ) as mock:
        await decorator.send_authentication_failed_event(request, "reason", "bearer")
        mock.assert_called_once()


async def test_send_rate_limit_event(security_config: SecurityConfig) -> None:
    from unittest.mock import AsyncMock, patch

    decorator = BaseSecurityDecorator(security_config)
    request = MockGuardRequest()
    with patch.object(
        decorator, "send_decorator_event", new_callable=AsyncMock
    ) as mock:
        await decorator.send_rate_limit_event(request, 100, 60)
        mock.assert_called_once()


async def test_send_decorator_violation_event(security_config: SecurityConfig) -> None:
    from unittest.mock import AsyncMock, patch

    decorator = BaseSecurityDecorator(security_config)
    request = MockGuardRequest()
    with patch.object(
        decorator, "send_decorator_event", new_callable=AsyncMock
    ) as mock:
        await decorator.send_decorator_violation_event(request, "type", "reason")
        mock.assert_called_once()
