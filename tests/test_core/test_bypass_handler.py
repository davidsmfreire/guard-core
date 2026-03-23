from collections.abc import Awaitable, Callable
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.bypass.context import BypassContext
from guard_core.core.bypass.handler import BypassHandler
from guard_core.decorators.base import RouteConfig
from tests.conftest import MockGuardRequest, MockGuardResponse


@pytest.fixture
def mock_response_factory() -> Mock:
    factory = Mock()
    factory.apply_modifier = AsyncMock(return_value=MockGuardResponse(status_code=200))
    return factory


@pytest.fixture
def mock_validator() -> Mock:
    validator = Mock()
    validator.is_path_excluded = AsyncMock(return_value=False)
    return validator


@pytest.fixture
def mock_route_resolver() -> Mock:
    resolver = Mock()
    resolver.should_bypass_check = Mock(return_value=False)
    return resolver


@pytest.fixture
def mock_event_bus() -> Mock:
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def mock_config() -> Mock:
    config = Mock()
    config.passive_mode = False
    return config


@pytest.fixture
def bypass_context(
    mock_config: Mock,
    mock_response_factory: Mock,
    mock_validator: Mock,
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
) -> BypassContext:
    return BypassContext(
        config=mock_config,
        logger=Mock(),
        response_factory=mock_response_factory,
        validator=mock_validator,
        route_resolver=mock_route_resolver,
        event_bus=mock_event_bus,
    )


@pytest.fixture
def bypass_handler(bypass_context: BypassContext) -> BypassHandler:
    return BypassHandler(bypass_context)


@pytest.fixture
def mock_req() -> MockGuardRequest:
    return MockGuardRequest(path="/test", client_host="127.0.0.1")


@pytest.fixture
def call_next() -> Callable[[MockGuardRequest], Awaitable[MockGuardResponse]]:
    async def _call_next(request: MockGuardRequest) -> MockGuardResponse:
        return MockGuardResponse(status_code=200, content="OK")

    return _call_next


class TestBypassHandler:
    def test_init(self, bypass_context: BypassContext) -> None:
        handler = BypassHandler(bypass_context)
        assert handler.context == bypass_context

    @pytest.mark.asyncio
    async def test_handle_passthrough_no_client(
        self,
        bypass_handler: BypassHandler,
        call_next: Callable,
        mock_response_factory: Mock,
    ) -> None:
        req = MockGuardRequest(path="/test", client_host=None)

        response = await bypass_handler.handle_passthrough(req, call_next)

        assert response is not None
        assert response.status_code == 200
        mock_response_factory.apply_modifier.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_passthrough_excluded_path(
        self,
        bypass_handler: BypassHandler,
        mock_req: MockGuardRequest,
        call_next: Callable,
        mock_validator: Mock,
        mock_response_factory: Mock,
    ) -> None:
        mock_validator.is_path_excluded.return_value = True

        response = await bypass_handler.handle_passthrough(mock_req, call_next)

        assert response is not None
        assert response.status_code == 200
        mock_validator.is_path_excluded.assert_called_once_with(mock_req)
        mock_response_factory.apply_modifier.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_passthrough_no_bypass(
        self,
        bypass_handler: BypassHandler,
        mock_req: MockGuardRequest,
        call_next: Callable,
        mock_validator: Mock,
    ) -> None:
        mock_validator.is_path_excluded.return_value = False

        response = await bypass_handler.handle_passthrough(mock_req, call_next)

        assert response is None
        mock_validator.is_path_excluded.assert_called_once_with(mock_req)

    @pytest.mark.asyncio
    async def test_handle_security_bypass_no_route_config(
        self,
        bypass_handler: BypassHandler,
        mock_req: MockGuardRequest,
        call_next: Callable,
    ) -> None:
        response = await bypass_handler.handle_security_bypass(
            mock_req, call_next, None
        )

        assert response is None

    @pytest.mark.asyncio
    async def test_handle_security_bypass_should_not_bypass(
        self,
        bypass_handler: BypassHandler,
        mock_req: MockGuardRequest,
        call_next: Callable,
        mock_route_resolver: Mock,
    ) -> None:
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}
        mock_route_resolver.should_bypass_check.return_value = False

        response = await bypass_handler.handle_security_bypass(
            mock_req, call_next, route_config
        )

        assert response is None
        mock_route_resolver.should_bypass_check.assert_called_once_with(
            "all", route_config
        )

    @pytest.mark.asyncio
    async def test_handle_security_bypass_active_mode(
        self,
        bypass_handler: BypassHandler,
        mock_req: MockGuardRequest,
        call_next: Callable,
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        mock_response_factory: Mock,
        bypass_context: BypassContext,
    ) -> None:
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = False

        response = await bypass_handler.handle_security_bypass(
            mock_req, call_next, route_config
        )

        assert response is not None
        assert response.status_code == 200
        mock_event_bus.send_middleware_event.assert_called_once()
        call_args = mock_event_bus.send_middleware_event.call_args[1]
        assert call_args["event_type"] == "security_bypass"
        assert call_args["action_taken"] == "all_checks_bypassed"
        assert call_args["endpoint"] == "/test"
        mock_response_factory.apply_modifier.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_security_bypass_passive_mode(
        self,
        bypass_handler: BypassHandler,
        mock_req: MockGuardRequest,
        call_next: Callable,
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        mock_response_factory: Mock,
        bypass_context: BypassContext,
    ) -> None:
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = True

        response = await bypass_handler.handle_security_bypass(
            mock_req, call_next, route_config
        )

        assert response is None
        mock_event_bus.send_middleware_event.assert_called_once()
        mock_response_factory.apply_modifier.assert_not_called()
