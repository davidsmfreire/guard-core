from unittest.mock import AsyncMock, patch

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(enable_redis=True)


@pytest.fixture
def mock_redis() -> AsyncMock:
    redis = AsyncMock()
    redis.initialize = AsyncMock()
    return redis


@pytest.fixture
def mock_agent() -> AsyncMock:
    agent = AsyncMock()
    agent.start = AsyncMock()
    agent.initialize_redis = AsyncMock()
    return agent


async def test_initialize_redis_disabled():
    config = SecurityConfig(enable_redis=False)
    initializer = HandlerInitializer(config=config)
    await initializer.initialize_redis_handlers()


async def test_initialize_redis_no_handler(config):
    initializer = HandlerInitializer(config=config, redis_handler=None)
    await initializer.initialize_redis_handlers()


async def test_initialize_redis_handlers(config, mock_redis):
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = AsyncMock()
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        initializer = HandlerInitializer(config=config, redis_handler=mock_redis)
        await initializer.initialize_redis_handlers()

        mock_redis.initialize.assert_awaited_once()
        mock_ipban.initialize_redis.assert_awaited_once_with(mock_redis)
        mock_sus.initialize_redis.assert_awaited_once_with(mock_redis)


async def test_initialize_redis_with_cloud_providers(mock_redis):
    config = SecurityConfig(enable_redis=True, block_cloud_providers={"AWS"})
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = AsyncMock()
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        initializer = HandlerInitializer(config=config, redis_handler=mock_redis)
        await initializer.initialize_redis_handlers()

        mock_cloud.initialize_redis.assert_awaited_once()


async def test_initialize_redis_with_geo_ip(config, mock_redis):
    geo = AsyncMock()
    geo.initialize_redis = AsyncMock()
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler"),
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        initializer = HandlerInitializer(
            config=config, redis_handler=mock_redis, geo_ip_handler=geo
        )
        await initializer.initialize_redis_handlers()

        geo.initialize_redis.assert_awaited_once_with(mock_redis)


async def test_initialize_redis_with_rate_limit(config, mock_redis):
    rate_limiter = AsyncMock()
    rate_limiter.initialize_redis = AsyncMock()
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler"),
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ipban.initialize_redis = AsyncMock()
        mock_sus.initialize_redis = AsyncMock()

        initializer = HandlerInitializer(
            config=config,
            redis_handler=mock_redis,
            rate_limit_handler=rate_limiter,
        )
        await initializer.initialize_redis_handlers()

        rate_limiter.initialize_redis.assert_awaited_once_with(mock_redis)


async def test_initialize_agent_integrations_no_agent(config):
    initializer = HandlerInitializer(config=config)
    await initializer.initialize_agent_integrations()


async def test_initialize_agent_integrations(config, mock_redis, mock_agent):
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler"),
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        initializer = HandlerInitializer(
            config=config,
            redis_handler=mock_redis,
            agent_handler=mock_agent,
        )
        await initializer.initialize_agent_integrations()

        mock_agent.start.assert_awaited_once()
        mock_agent.initialize_redis.assert_awaited_once_with(mock_redis)


async def test_initialize_agent_for_handlers_no_agent(config):
    initializer = HandlerInitializer(config=config)
    await initializer.initialize_agent_for_handlers()


async def test_initialize_dynamic_rule_manager_disabled(config):
    initializer = HandlerInitializer(config=config, agent_handler=AsyncMock())
    await initializer.initialize_dynamic_rule_manager()


async def test_initialize_dynamic_rule_manager_enabled(mock_agent, mock_redis):
    config = SecurityConfig(
        enable_redis=True,
        enable_agent=True,
        enable_dynamic_rules=True,
        agent_api_key="test-key",
    )
    with patch(
        "guard_core.handlers.dynamic_rule_handler.DynamicRuleManager"
    ) as mock_drm_cls:
        mock_drm = AsyncMock()
        mock_drm.initialize_agent = AsyncMock()
        mock_drm.initialize_redis = AsyncMock()
        mock_drm_cls.return_value = mock_drm

        initializer = HandlerInitializer(
            config=config,
            redis_handler=mock_redis,
            agent_handler=mock_agent,
        )
        await initializer.initialize_dynamic_rule_manager()

        mock_drm.initialize_agent.assert_awaited_once_with(mock_agent)
        mock_drm.initialize_redis.assert_awaited_once_with(mock_redis)


async def test_initialize_agent_integrations_with_guard_decorator(
    config, mock_redis, mock_agent
):
    guard_decorator = AsyncMock()
    guard_decorator.initialize_agent = AsyncMock()
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler"),
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        initializer = HandlerInitializer(
            config=config,
            redis_handler=mock_redis,
            agent_handler=mock_agent,
            guard_decorator=guard_decorator,
        )
        await initializer.initialize_agent_integrations()

        guard_decorator.initialize_agent.assert_awaited_once_with(mock_agent)


async def test_initialize_agent_for_handlers_with_cloud(mock_agent):
    config = SecurityConfig(enable_redis=True, block_cloud_providers={"AWS"})
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_agent = AsyncMock()
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        initializer = HandlerInitializer(
            config=config,
            agent_handler=mock_agent,
        )
        await initializer.initialize_agent_for_handlers()
        mock_cloud.initialize_agent.assert_awaited_once()


async def test_initialize_agent_for_handlers_with_geo_ip(mock_agent):
    config = SecurityConfig(enable_redis=True)
    geo = AsyncMock()
    geo.initialize_agent = AsyncMock()
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler"),
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        initializer = HandlerInitializer(
            config=config,
            agent_handler=mock_agent,
            geo_ip_handler=geo,
        )
        await initializer.initialize_agent_for_handlers()
        geo.initialize_agent.assert_awaited_once()


async def test_initialize_agent_for_handlers_with_rate_limiter(mock_agent):
    config = SecurityConfig(enable_redis=True)
    rate_limiter = AsyncMock()
    rate_limiter.initialize_agent = AsyncMock()
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler"),
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ipban.initialize_agent = AsyncMock()
        mock_sus.initialize_agent = AsyncMock()

        initializer = HandlerInitializer(
            config=config,
            agent_handler=mock_agent,
            rate_limit_handler=rate_limiter,
        )
        await initializer.initialize_agent_for_handlers()
        rate_limiter.initialize_agent.assert_awaited_once_with(mock_agent)
