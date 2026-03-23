from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.behavior_handler import BehaviorRule
from tests.conftest import MockGuardRequest, MockGuardResponse


def create_route_config_with_rules(rules: list[BehaviorRule]) -> RouteConfig:
    config = RouteConfig()
    config.behavior_rules = rules
    return config


@pytest.fixture
def mock_event_bus() -> Mock:
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def mock_guard_decorator() -> Mock:
    decorator = Mock()
    decorator.behavior_tracker = Mock()
    decorator.behavior_tracker.track_endpoint_usage = AsyncMock(return_value=False)
    decorator.behavior_tracker.track_return_pattern = AsyncMock(return_value=False)
    decorator.behavior_tracker.apply_action = AsyncMock()
    return decorator


@pytest.fixture
def behavioral_context(
    mock_event_bus: Mock, mock_guard_decorator: Mock
) -> BehavioralContext:
    context = BehavioralContext(
        config=Mock(),
        logger=Mock(),
        event_bus=mock_event_bus,
        guard_decorator=mock_guard_decorator,
    )
    return context


@pytest.fixture
def processor(behavioral_context: BehavioralContext) -> BehavioralProcessor:
    return BehavioralProcessor(behavioral_context)


@pytest.fixture
def mock_req() -> MockGuardRequest:
    def endpoint() -> None:
        pass

    endpoint.__module__ = "test_module"
    endpoint.__qualname__ = "test_function"
    route = Mock(endpoint=endpoint)
    return MockGuardRequest(
        path="/test",
        method="GET",
        scope={"route": route},
    )


@pytest.fixture
def mock_resp() -> MockGuardResponse:
    return MockGuardResponse(status_code=200)


class TestBehavioralProcessor:
    def test_init(self, behavioral_context: BehavioralContext) -> None:
        processor = BehavioralProcessor(behavioral_context)
        assert processor.context == behavioral_context

    @pytest.mark.asyncio
    async def test_process_usage_rules_no_decorator(
        self, processor: BehavioralProcessor, mock_req: MockGuardRequest
    ) -> None:
        processor.context.guard_decorator = None
        route_config = RouteConfig()

        await processor.process_usage_rules(mock_req, "1.2.3.4", route_config)

    @pytest.mark.asyncio
    async def test_process_usage_rules_no_threshold_exceeded(
        self, processor: BehavioralProcessor, mock_req: MockGuardRequest
    ) -> None:
        rule = BehaviorRule(rule_type="usage", threshold=10, window=60, action="log")
        route_config = create_route_config_with_rules([rule])

        await processor.process_usage_rules(mock_req, "1.2.3.4", route_config)

        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_usage_rules_threshold_exceeded(
        self,
        processor: BehavioralProcessor,
        mock_req: MockGuardRequest,
        mock_event_bus: Mock,
    ) -> None:
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = (
            AsyncMock(return_value=True)
        )

        rule = BehaviorRule(rule_type="usage", threshold=5, window=60, action="ban")
        route_config = create_route_config_with_rules([rule])

        await processor.process_usage_rules(mock_req, "1.2.3.4", route_config)

        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "decorator_violation"
        assert call_kwargs["action_taken"] == "behavioral_action_triggered"
        assert "threshold exceeded" in call_kwargs["reason"]
        assert call_kwargs["threshold"] == 5
        assert call_kwargs["window"] == 60

        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_return_rules_no_decorator(
        self,
        processor: BehavioralProcessor,
        mock_req: MockGuardRequest,
        mock_resp: MockGuardResponse,
    ) -> None:
        processor.context.guard_decorator = None
        route_config = create_route_config_with_rules([])

        await processor.process_return_rules(
            mock_req, mock_resp, "1.2.3.4", route_config
        )

    @pytest.mark.asyncio
    async def test_process_return_rules_no_pattern_detected(
        self,
        processor: BehavioralProcessor,
        mock_req: MockGuardRequest,
        mock_resp: MockGuardResponse,
    ) -> None:
        rule = BehaviorRule(
            rule_type="return_pattern",
            pattern="error",
            threshold=3,
            window=60,
            action="log",
        )
        route_config = create_route_config_with_rules([rule])

        await processor.process_return_rules(
            mock_req, mock_resp, "1.2.3.4", route_config
        )

        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_return_rules_pattern_detected(
        self,
        processor: BehavioralProcessor,
        mock_req: MockGuardRequest,
        mock_resp: MockGuardResponse,
        mock_event_bus: Mock,
    ) -> None:
        processor.context.guard_decorator.behavior_tracker.track_return_pattern = (
            AsyncMock(return_value=True)
        )

        rule = BehaviorRule(
            rule_type="return_pattern",
            pattern="error",
            threshold=3,
            window=60,
            action="ban",
        )
        route_config = create_route_config_with_rules([rule])

        await processor.process_return_rules(
            mock_req, mock_resp, "1.2.3.4", route_config
        )

        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "decorator_violation"
        assert call_kwargs["violation_type"] == "return_pattern"
        assert call_kwargs["pattern"] == "error"
        assert "Return pattern threshold exceeded" in call_kwargs["reason"]

        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_return_rules_ignores_non_return_pattern(
        self,
        processor: BehavioralProcessor,
        mock_req: MockGuardRequest,
        mock_resp: MockGuardResponse,
    ) -> None:
        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            window=60,
            action="log",
        )
        route_config = create_route_config_with_rules([rule])

        await processor.process_return_rules(
            mock_req, mock_resp, "1.2.3.4", route_config
        )

        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_not_called()

    def test_get_endpoint_id_with_route(
        self, processor: BehavioralProcessor, mock_req: MockGuardRequest
    ) -> None:
        endpoint_id = processor.get_endpoint_id(mock_req)
        assert endpoint_id == "test_module.test_function"

    def test_get_endpoint_id_no_route(self, processor: BehavioralProcessor) -> None:
        req = MockGuardRequest(path="/api/test", method="POST", scope={})
        endpoint_id = processor.get_endpoint_id(req)
        assert endpoint_id == "POST:/api/test"
