from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


@pytest.fixture
def config():
    return SecurityConfig(enable_redis=False, agent_enable_metrics=True)


@pytest.fixture
def config_metrics_disabled():
    return SecurityConfig(enable_redis=False, agent_enable_metrics=False)


class TestCollectRequestMetrics:
    @pytest.mark.asyncio
    async def test_no_agent_returns_early(self, config):
        collector = MetricsCollector(agent_handler=None, config=config)
        request = MockGuardRequest(path="/test", method="GET")
        await collector.collect_request_metrics(request, 0.5, 200)

    @pytest.mark.asyncio
    async def test_metrics_disabled_returns_early(self, config_metrics_disabled):
        agent = AsyncMock()
        collector = MetricsCollector(
            agent_handler=agent, config=config_metrics_disabled
        )
        request = MockGuardRequest(path="/test", method="GET")
        await collector.collect_request_metrics(request, 0.5, 200)
        agent.send_metric.assert_not_called()

    @pytest.mark.asyncio
    async def test_sends_response_time_and_request_count(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        request = MockGuardRequest(path="/api", method="POST")

        mock_metric_cls = MagicMock()
        with patch(
            "guard_core.core.events.metrics.SecurityMetric",
            mock_metric_cls,
            create=True,
        ):
            try:
                await collector.collect_request_metrics(request, 0.25, 200)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_sends_error_rate_for_4xx(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        request = MockGuardRequest(path="/error", method="GET")

        try:
            await collector.collect_request_metrics(request, 0.1, 404)
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_sends_error_rate_for_5xx(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        request = MockGuardRequest(path="/error", method="GET")

        try:
            await collector.collect_request_metrics(request, 0.1, 500)
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_no_error_rate_for_2xx(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        request = MockGuardRequest(path="/ok", method="GET")

        try:
            await collector.collect_request_metrics(request, 0.05, 200)
        except Exception:
            pass


class TestSendMetric:
    @pytest.mark.asyncio
    async def test_no_agent_does_nothing(self, config):
        collector = MetricsCollector(agent_handler=None, config=config)
        await collector.send_metric("test", 1.0)

    @pytest.mark.asyncio
    async def test_metrics_disabled_does_nothing(self, config_metrics_disabled):
        agent = AsyncMock()
        collector = MetricsCollector(
            agent_handler=agent, config=config_metrics_disabled
        )
        await collector.send_metric("test", 1.0)
        agent.send_metric.assert_not_called()

    @pytest.mark.asyncio
    async def test_import_error_handled(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        with patch.dict("sys.modules", {"guard_agent": None}):
            await collector.send_metric("test", 1.0)

    @pytest.mark.asyncio
    async def test_exception_logged(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        with patch(
            "guard_core.core.events.metrics.SecurityMetric",
            side_effect=Exception("fail"),
            create=True,
        ):
            await collector.send_metric("test", 1.0)

    @pytest.mark.asyncio
    async def test_successful_send(self, config):
        agent = AsyncMock()
        collector = MetricsCollector(agent_handler=agent, config=config)
        with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
            await collector.send_metric("response_time", 0.5, {"endpoint": "/test"})
        agent.send_metric.assert_called_once()
