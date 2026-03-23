from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from tests.conftest import MockGuardRequest


@pytest.fixture
def mock_config() -> Any:
    config = Mock()
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ["192.168.1.1", "10.0.0.0/8"]
    config.exclude_paths = ["/health", "/metrics"]
    return config


@pytest.fixture
def mock_event_bus() -> Any:
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def validation_context(mock_config: Any, mock_event_bus: Any) -> ValidationContext:
    return ValidationContext(
        config=mock_config,
        logger=Mock(),
        event_bus=mock_event_bus,
    )


@pytest.fixture
def validator(validation_context: ValidationContext) -> RequestValidator:
    return RequestValidator(validation_context)


class TestRequestValidator:
    def test_init(self, validation_context: ValidationContext) -> None:
        validator = RequestValidator(validation_context)
        assert validator.context == validation_context

    def test_is_request_https_direct_https(self, validator: RequestValidator) -> None:
        req = MockGuardRequest(scheme="https")
        result = validator.is_request_https(req)
        assert result is True

    def test_is_request_https_direct_http(self, validator: RequestValidator) -> None:
        req = MockGuardRequest(scheme="http")
        result = validator.is_request_https(req)
        assert result is False

    def test_is_request_https_forwarded_proto_trusted_proxy(
        self, validator: RequestValidator
    ) -> None:
        req = MockGuardRequest(
            scheme="http",
            headers={"X-Forwarded-Proto": "https"},
            client_host="192.168.1.1",
        )
        result = validator.is_request_https(req)
        assert result is True

    def test_is_request_https_forwarded_proto_untrusted_proxy(
        self, validator: RequestValidator
    ) -> None:
        req = MockGuardRequest(
            scheme="http",
            headers={"X-Forwarded-Proto": "https"},
            client_host="1.2.3.4",
        )
        result = validator.is_request_https(req)
        assert result is False

    def test_is_request_https_no_client(self, validator: RequestValidator) -> None:
        req = MockGuardRequest(scheme="http", client_host=None)
        result = validator.is_request_https(req)
        assert result is False

    def test_is_request_https_trust_disabled(self, validator: RequestValidator) -> None:
        validator.context.config.trust_x_forwarded_proto = False
        req = MockGuardRequest(
            scheme="http",
            headers={"X-Forwarded-Proto": "https"},
        )
        result = validator.is_request_https(req)
        assert result is False

    def test_is_request_https_no_trusted_proxies(
        self, validator: RequestValidator
    ) -> None:
        validator.context.config.trusted_proxies = []
        req = MockGuardRequest(
            scheme="http",
            headers={"X-Forwarded-Proto": "https"},
        )
        result = validator.is_request_https(req)
        assert result is False

    def test_is_trusted_proxy_single_ip_match(
        self, validator: RequestValidator
    ) -> None:
        result = validator.is_trusted_proxy("192.168.1.1")
        assert result is True

    def test_is_trusted_proxy_single_ip_no_match(
        self, validator: RequestValidator
    ) -> None:
        result = validator.is_trusted_proxy("192.168.1.2")
        assert result is False

    def test_is_trusted_proxy_cidr_match(self, validator: RequestValidator) -> None:
        result = validator.is_trusted_proxy("10.0.5.10")
        assert result is True

    def test_is_trusted_proxy_cidr_no_match(self, validator: RequestValidator) -> None:
        result = validator.is_trusted_proxy("11.0.0.1")
        assert result is False

    @pytest.mark.asyncio
    async def test_check_time_window_within_range(
        self, validator: RequestValidator
    ) -> None:
        current = datetime.now(timezone.utc)
        hour = current.hour
        start_hour = (hour - 1) % 24
        end_hour = (hour + 1) % 24

        time_restrictions = {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:59",
        }

        result = await validator.check_time_window(time_restrictions)
        assert result is True

    @pytest.mark.asyncio
    async def test_check_time_window_outside_range(
        self, validator: RequestValidator
    ) -> None:
        current = datetime.now(timezone.utc)
        hour = current.hour
        start_hour = (hour + 6) % 24
        end_hour = (hour + 8) % 24

        time_restrictions = {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:00",
        }

        result = await validator.check_time_window(time_restrictions)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_time_window_error_handling(
        self, validator: RequestValidator
    ) -> None:
        time_restrictions = {"invalid": "data"}
        result = await validator.check_time_window(time_restrictions)
        assert result is True

    @pytest.mark.asyncio
    async def test_is_path_excluded_matching_path(
        self, validator: RequestValidator, mock_event_bus: Any
    ) -> None:
        req = MockGuardRequest(path="/health")
        result = await validator.is_path_excluded(req)

        assert result is True
        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "path_excluded"
        assert call_kwargs["excluded_path"] == "/health"

    @pytest.mark.asyncio
    async def test_is_path_excluded_prefix_match(
        self, validator: RequestValidator, mock_event_bus: Any
    ) -> None:
        req = MockGuardRequest(path="/health/check")
        result = await validator.is_path_excluded(req)

        assert result is True
        mock_event_bus.send_middleware_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_path_excluded_no_match(
        self, validator: RequestValidator, mock_event_bus: Any
    ) -> None:
        req = MockGuardRequest(path="/api/endpoint")
        result = await validator.is_path_excluded(req)

        assert result is False
        mock_event_bus.send_middleware_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_time_window_overnight_wrap(
        self, validator: RequestValidator
    ) -> None:
        time_restrictions = {"start": "23:00", "end": "01:00"}
        from datetime import datetime, timezone

        current = datetime.now(timezone.utc)
        if 23 <= current.hour or current.hour <= 1:
            result = await validator.check_time_window(time_restrictions)
            assert result is True
        else:
            result = await validator.check_time_window(time_restrictions)
            assert result is False
