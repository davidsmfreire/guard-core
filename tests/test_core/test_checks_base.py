from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.base import SecurityCheck
from tests.conftest import MockGuardRequest, MockGuardResponse


class ConcreteSecurityCheck(SecurityCheck):
    async def check(self, request):
        return None

    @property
    def check_name(self) -> str:
        return "test_check"


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        return_value=MockGuardResponse(status_code=403)
    )
    return middleware


@pytest.fixture
def security_check(mock_middleware: Mock) -> ConcreteSecurityCheck:
    return ConcreteSecurityCheck(mock_middleware)


@pytest.fixture
def mock_req() -> MockGuardRequest:
    return MockGuardRequest(path="/test", client_host="127.0.0.1")


class TestSecurityCheck:
    def test_cannot_instantiate_abstract_class(self, mock_middleware: Mock) -> None:
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            SecurityCheck(mock_middleware)

    def test_init(self, mock_middleware: Mock) -> None:
        check = ConcreteSecurityCheck(mock_middleware)
        assert check.middleware == mock_middleware
        assert check.config == mock_middleware.config
        assert check.logger == mock_middleware.logger

    @pytest.mark.asyncio
    async def test_check_abstract_method(
        self, security_check: ConcreteSecurityCheck, mock_req: MockGuardRequest
    ) -> None:
        result = await security_check.check(mock_req)
        assert result is None

    def test_check_name_abstract_property(
        self, security_check: ConcreteSecurityCheck
    ) -> None:
        assert security_check.check_name == "test_check"

    @pytest.mark.asyncio
    async def test_send_event(
        self,
        security_check: ConcreteSecurityCheck,
        mock_req: MockGuardRequest,
        mock_middleware: Mock,
    ) -> None:
        await security_check.send_event(
            event_type="test_event",
            request=mock_req,
            action_taken="blocked",
            reason="test reason",
            extra_data="test",
        )

        mock_middleware.event_bus.send_middleware_event.assert_called_once_with(
            event_type="test_event",
            request=mock_req,
            action_taken="blocked",
            reason="test reason",
            extra_data="test",
        )

    @pytest.mark.asyncio
    async def test_send_event_no_extra_kwargs(
        self,
        security_check: ConcreteSecurityCheck,
        mock_req: MockGuardRequest,
        mock_middleware: Mock,
    ) -> None:
        await security_check.send_event(
            event_type="test_event",
            request=mock_req,
            action_taken="allowed",
            reason="passed checks",
        )

        mock_middleware.event_bus.send_middleware_event.assert_called_once_with(
            event_type="test_event",
            request=mock_req,
            action_taken="allowed",
            reason="passed checks",
        )

    @pytest.mark.asyncio
    async def test_create_error_response(
        self, security_check: ConcreteSecurityCheck, mock_middleware: Mock
    ) -> None:
        response = await security_check.create_error_response(403, "Forbidden")

        assert response.status_code == 403
        mock_middleware.create_error_response.assert_called_once_with(403, "Forbidden")

    @pytest.mark.asyncio
    async def test_create_error_response_different_codes(
        self, security_check: ConcreteSecurityCheck, mock_middleware: Mock
    ) -> None:
        mock_middleware.create_error_response.reset_mock()
        mock_middleware.create_error_response.return_value = MockGuardResponse(
            status_code=429
        )

        response = await security_check.create_error_response(429, "Too Many Requests")

        assert response.status_code == 429
        mock_middleware.create_error_response.assert_called_once_with(
            429, "Too Many Requests"
        )

    def test_is_passive_mode_false(self, security_check: ConcreteSecurityCheck) -> None:
        result = security_check.is_passive_mode()
        assert result is False

    def test_is_passive_mode_true(
        self, security_check: ConcreteSecurityCheck, mock_middleware: Mock
    ) -> None:
        mock_middleware.config.passive_mode = True
        result = security_check.is_passive_mode()
        assert result is True
