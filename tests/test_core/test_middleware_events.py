from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


@pytest.fixture
def config():
    return SecurityConfig(enable_redis=False, agent_enable_events=True)


@pytest.fixture
def config_events_disabled():
    return SecurityConfig(enable_redis=False, agent_enable_events=False)


class TestSendMiddlewareEvent:
    @pytest.mark.asyncio
    async def test_no_agent(self, config):
        bus = SecurityEventBus(agent_handler=None, config=config)
        await bus.send_middleware_event("test", MockGuardRequest(), "action", "reason")

    @pytest.mark.asyncio
    async def test_events_disabled(self, config_events_disabled):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config_events_disabled)
        await bus.send_middleware_event("test", MockGuardRequest(), "action", "reason")
        agent.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_with_agent(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        with (
            patch(
                "guard_core.core.events.middleware_events.extract_client_ip",
                new_callable=AsyncMock,
                return_value="1.2.3.4",
            ),
            patch.dict("sys.modules", {"guard_agent": MagicMock()}),
        ):
            await bus.send_middleware_event(
                "test", MockGuardRequest(), "action", "reason"
            )
        agent.send_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_with_geo_handler(self, config):
        agent = AsyncMock()
        geo = MagicMock()
        geo.get_country.return_value = "US"
        bus = SecurityEventBus(agent_handler=agent, config=config, geo_ip_handler=geo)
        with (
            patch(
                "guard_core.core.events.middleware_events.extract_client_ip",
                new_callable=AsyncMock,
                return_value="1.2.3.4",
            ),
            patch.dict("sys.modules", {"guard_agent": MagicMock()}),
        ):
            await bus.send_middleware_event(
                "test", MockGuardRequest(), "action", "reason"
            )

    @pytest.mark.asyncio
    async def test_geo_handler_error(self, config):
        agent = AsyncMock()
        geo = MagicMock()
        geo.get_country.side_effect = Exception("geo fail")
        bus = SecurityEventBus(agent_handler=agent, config=config, geo_ip_handler=geo)
        with (
            patch(
                "guard_core.core.events.middleware_events.extract_client_ip",
                new_callable=AsyncMock,
                return_value="1.2.3.4",
            ),
            patch.dict("sys.modules", {"guard_agent": MagicMock()}),
        ):
            await bus.send_middleware_event(
                "test", MockGuardRequest(), "action", "reason"
            )

    @pytest.mark.asyncio
    async def test_exception_logged(self, config):
        agent = AsyncMock()
        agent.send_event = AsyncMock(side_effect=Exception("fail"))
        bus = SecurityEventBus(agent_handler=agent, config=config)
        with patch(
            "guard_core.core.events.middleware_events.extract_client_ip",
            new_callable=AsyncMock,
            return_value="1.2.3.4",
        ):
            await bus.send_middleware_event(
                "test", MockGuardRequest(), "action", "reason"
            )


class TestSendHttpsViolationEvent:
    @pytest.mark.asyncio
    async def test_route_config_requires_https(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        rc = RouteConfig()
        rc.require_https = True
        with patch.object(bus, "send_middleware_event", new_callable=AsyncMock):
            await bus.send_https_violation_event(MockGuardRequest(scheme="http"), rc)
            bus.send_middleware_event.assert_called_once()
            kwargs = bus.send_middleware_event.call_args.kwargs
            assert kwargs["event_type"] == "decorator_violation"

    @pytest.mark.asyncio
    async def test_global_https_enforcement(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        with patch.object(bus, "send_middleware_event", new_callable=AsyncMock):
            await bus.send_https_violation_event(MockGuardRequest(scheme="http"), None)
            kwargs = bus.send_middleware_event.call_args.kwargs
            assert kwargs["event_type"] == "https_enforced"


class TestSendCloudDetectionEvents:
    @pytest.mark.asyncio
    async def test_with_cloud_details_and_agent(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        cloud = MagicMock()
        cloud.get_cloud_provider_details.return_value = ("AWS", "192.168.0.0/24")
        cloud.agent_handler = AsyncMock()
        cloud.send_cloud_detection_event = AsyncMock()

        with patch.object(bus, "send_middleware_event", new_callable=AsyncMock):
            await bus.send_cloud_detection_events(
                MockGuardRequest(), "1.2.3.4", ["AWS"], None, cloud, False
            )
        cloud.send_cloud_detection_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_cloud_details(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        cloud = MagicMock()
        cloud.get_cloud_provider_details.return_value = None

        with patch.object(bus, "send_middleware_event", new_callable=AsyncMock):
            await bus.send_cloud_detection_events(
                MockGuardRequest(), "1.2.3.4", ["AWS"], None, cloud, False
            )

    @pytest.mark.asyncio
    async def test_with_route_config(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        cloud = MagicMock()
        cloud.get_cloud_provider_details.return_value = None
        rc = RouteConfig()
        rc.block_cloud_providers = {"AWS"}

        with patch.object(bus, "send_middleware_event", new_callable=AsyncMock):
            await bus.send_cloud_detection_events(
                MockGuardRequest(), "1.2.3.4", ["AWS"], rc, cloud, False
            )
            bus.send_middleware_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_passive_mode(self, config):
        agent = AsyncMock()
        bus = SecurityEventBus(agent_handler=agent, config=config)
        cloud = MagicMock()
        cloud.get_cloud_provider_details.return_value = ("AWS", "192.168.0.0/24")
        cloud.agent_handler = AsyncMock()
        cloud.send_cloud_detection_event = AsyncMock()

        with patch.object(bus, "send_middleware_event", new_callable=AsyncMock):
            await bus.send_cloud_detection_events(
                MockGuardRequest(), "1.2.3.4", ["AWS"], None, cloud, True
            )
        call_args = cloud.send_cloud_detection_event.call_args
        assert call_args[0][3] == "logged_only"
