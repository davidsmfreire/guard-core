import logging
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.checks.implementations.authentication import AuthenticationCheck
from guard_core.core.checks.implementations.cloud_ip_refresh import CloudIpRefreshCheck
from guard_core.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard_core.core.checks.implementations.custom_request import CustomRequestCheck
from guard_core.core.checks.implementations.custom_validators import (
    CustomValidatorsCheck,
)
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.checks.implementations.referrer import ReferrerCheck
from guard_core.core.checks.implementations.request_logging import RequestLoggingCheck
from guard_core.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard_core.core.checks.implementations.required_headers import RequiredHeadersCheck
from guard_core.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.checks.implementations.time_window import TimeWindowCheck
from guard_core.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from tests.conftest import MockGuardRequest, MockGuardResponse


def _make_middleware(**config_overrides: Any) -> MagicMock:
    config = SecurityConfig(enable_redis=False, **config_overrides)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_checks")
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.event_bus.send_https_violation_event = AsyncMock()
    middleware.event_bus.send_cloud_detection_events = AsyncMock()
    middleware.route_resolver = MagicMock()
    middleware.response_factory = MagicMock()
    middleware.response_factory.create_https_redirect = AsyncMock(
        return_value=MockGuardResponse("Redirect", 301, {"Location": "https://test/"})
    )
    middleware.response_factory.apply_modifier = AsyncMock(side_effect=lambda r: r)
    middleware.agent_handler = None
    middleware.geo_ip_handler = None
    middleware.guard_response_factory = MagicMock()
    middleware.rate_limit_handler = MagicMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()
    middleware.suspicious_request_counts = {}
    return middleware


class TestEmergencyModeCheck:
    async def test_disabled_returns_none(self) -> None:
        middleware = _make_middleware(emergency_mode=False)
        check = EmergencyModeCheck(middleware)
        result = await check.check(MockGuardRequest())
        assert result is None

    async def test_whitelisted_ip_returns_none(self) -> None:
        middleware = _make_middleware(
            emergency_mode=True, emergency_whitelist=["127.0.0.1"]
        )
        check = EmergencyModeCheck(middleware)
        request = MockGuardRequest(client_host="127.0.0.1")
        request.state.client_ip = "127.0.0.1"
        result = await check.check(request)
        assert result is None

    async def test_non_whitelisted_ip_blocks(self) -> None:
        middleware = _make_middleware(
            emergency_mode=True, emergency_whitelist=["10.0.0.1"]
        )
        check = EmergencyModeCheck(middleware)
        request = MockGuardRequest(client_host="192.168.1.1")
        request.state.client_ip = "192.168.1.1"
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 503

    async def test_non_whitelisted_ip_passive_mode(self) -> None:
        middleware = _make_middleware(
            emergency_mode=True,
            emergency_whitelist=["10.0.0.1"],
            passive_mode=True,
        )
        check = EmergencyModeCheck(middleware)
        request = MockGuardRequest(client_host="192.168.1.1")
        request.state.client_ip = "192.168.1.1"
        result = await check.check(request)
        assert result is None

    async def test_extracts_client_ip_when_not_on_state(self) -> None:
        middleware = _make_middleware(
            emergency_mode=True, emergency_whitelist=["127.0.0.1"]
        )
        check = EmergencyModeCheck(middleware)
        request = MockGuardRequest(client_host="127.0.0.1")
        with patch(
            "guard_core.core.checks.implementations.emergency_mode.extract_client_ip",
            new_callable=AsyncMock,
            return_value="127.0.0.1",
        ):
            result = await check.check(request)
        assert result is None


class TestHttpsEnforcementCheck:
    async def test_not_enforced_returns_none(self) -> None:
        middleware = _make_middleware(enforce_https=False)
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(scheme="http")
        result = await check.check(request)
        assert result is None

    async def test_https_request_passes(self) -> None:
        middleware = _make_middleware(enforce_https=True)
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(scheme="https")
        result = await check.check(request)
        assert result is None

    async def test_http_request_redirects(self) -> None:
        middleware = _make_middleware(enforce_https=True)
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(scheme="http")
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 301

    async def test_http_request_passive_mode(self) -> None:
        middleware = _make_middleware(enforce_https=True, passive_mode=True)
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(scheme="http")
        result = await check.check(request)
        assert result is None

    async def test_route_config_overrides_global(self) -> None:
        middleware = _make_middleware(enforce_https=False)
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(scheme="http")
        rc = RouteConfig()
        rc.require_https = True
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 301

    async def test_trusted_proxy_x_forwarded_proto(self) -> None:
        middleware = _make_middleware(
            enforce_https=True,
            trust_x_forwarded_proto=True,
            trusted_proxies=["127.0.0.1"],
        )
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(
            scheme="http",
            client_host="127.0.0.1",
            headers={"X-Forwarded-Proto": "https"},
        )
        result = await check.check(request)
        assert result is None

    async def test_untrusted_proxy_x_forwarded_proto_ignored(self) -> None:
        middleware = _make_middleware(
            enforce_https=True,
            trust_x_forwarded_proto=True,
            trusted_proxies=["10.0.0.1"],
        )
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(
            scheme="http",
            client_host="192.168.1.1",
            headers={"X-Forwarded-Proto": "https"},
        )
        result = await check.check(request)
        assert result is not None

    async def test_trusted_proxy_cidr(self) -> None:
        middleware = _make_middleware(
            enforce_https=True,
            trust_x_forwarded_proto=True,
            trusted_proxies=["10.0.0.0/8"],
        )
        check = HttpsEnforcementCheck(middleware)
        request = MockGuardRequest(
            scheme="http",
            client_host="10.0.0.5",
            headers={"X-Forwarded-Proto": "https"},
        )
        result = await check.check(request)
        assert result is None


class TestRequiredHeadersCheck:
    async def test_no_route_config_returns_none(self) -> None:
        middleware = _make_middleware()
        check = RequiredHeadersCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_no_required_headers_returns_none(self) -> None:
        middleware = _make_middleware()
        check = RequiredHeadersCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_required_header_present_passes(self) -> None:
        middleware = _make_middleware()
        check = RequiredHeadersCheck(middleware)
        request = MockGuardRequest(headers={"X-Api-Key": "my-key"})
        rc = RouteConfig()
        rc.required_headers = {"X-Api-Key": "required"}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_required_header_missing_blocks(self) -> None:
        middleware = _make_middleware()
        check = RequiredHeadersCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.required_headers = {"X-Api-Key": "required"}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 400

    async def test_required_header_missing_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = RequiredHeadersCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.required_headers = {"Authorization": "required"}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None


class TestAuthenticationCheck:
    async def test_no_route_config_returns_none(self) -> None:
        middleware = _make_middleware()
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_no_auth_required_returns_none(self) -> None:
        middleware = _make_middleware()
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_valid_bearer_passes(self) -> None:
        middleware = _make_middleware()
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest(headers={"authorization": "Bearer mytoken123"})
        rc = RouteConfig()
        rc.auth_required = "bearer"
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_missing_bearer_blocks(self) -> None:
        middleware = _make_middleware()
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.auth_required = "bearer"
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 401

    async def test_invalid_bearer_blocks(self) -> None:
        middleware = _make_middleware()
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest(headers={"authorization": "Basic abc"})
        rc = RouteConfig()
        rc.auth_required = "bearer"
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 401

    async def test_valid_basic_passes(self) -> None:
        middleware = _make_middleware()
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest(headers={"authorization": "Basic dXNlcjpwYXNz"})
        rc = RouteConfig()
        rc.auth_required = "basic"
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_auth_failure_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = AuthenticationCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.auth_required = "bearer"
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None


class TestUserAgentCheck:
    async def test_whitelisted_ip_returns_none(self) -> None:
        middleware = _make_middleware()
        check = UserAgentCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = True
        result = await check.check(request)
        assert result is None

    async def test_allowed_user_agent_passes(self) -> None:
        middleware = _make_middleware()
        check = UserAgentCheck(middleware)
        request = MockGuardRequest(headers={"User-Agent": "Mozilla/5.0"})
        with patch(
            "guard_core.utils.is_user_agent_allowed",
            new_callable=AsyncMock,
            return_value=True,
        ):
            result = await check.check(request)
        assert result is None

    async def test_blocked_user_agent_blocks(self) -> None:
        middleware = _make_middleware()
        check = UserAgentCheck(middleware)
        request = MockGuardRequest(headers={"User-Agent": "BadBot"})
        with patch(
            "guard_core.core.checks.implementations.user_agent.check_user_agent_allowed",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_blocked_user_agent_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = UserAgentCheck(middleware)
        request = MockGuardRequest(headers={"User-Agent": "BadBot"})
        with patch(
            "guard_core.core.checks.implementations.user_agent.check_user_agent_allowed",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check.check(request)
        assert result is None

    async def test_blocked_by_route_config_sends_decorator_event(self) -> None:
        middleware = _make_middleware()
        check = UserAgentCheck(middleware)
        request = MockGuardRequest(headers={"User-Agent": "BadBot"})
        rc = RouteConfig()
        rc.blocked_user_agents = ["BadBot"]
        request.state.route_config = rc
        with patch(
            "guard_core.core.checks.implementations.user_agent.check_user_agent_allowed",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check.check(request)
        assert result is not None
        middleware.event_bus.send_middleware_event.assert_called()
        call_kwargs = middleware.event_bus.send_middleware_event.call_args.kwargs
        assert call_kwargs["event_type"] == "decorator_violation"

    async def test_blocked_globally_sends_global_event(self) -> None:
        middleware = _make_middleware()
        check = UserAgentCheck(middleware)
        request = MockGuardRequest(headers={"User-Agent": "BadBot"})
        request.state.route_config = None
        with patch(
            "guard_core.core.checks.implementations.user_agent.check_user_agent_allowed",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check.check(request)
        assert result is not None
        call_kwargs = middleware.event_bus.send_middleware_event.call_args.kwargs
        assert call_kwargs["event_type"] == "user_agent_blocked"


class TestCloudProviderCheck:
    async def test_whitelisted_ip_returns_none(self) -> None:
        middleware = _make_middleware()
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = True
        result = await check.check(request)
        assert result is None

    async def test_no_client_ip_returns_none(self) -> None:
        middleware = _make_middleware()
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = None
        result = await check.check(request)
        assert result is None

    async def test_bypass_check_returns_none(self) -> None:
        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = True
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        result = await check.check(request)
        assert result is None

    async def test_no_providers_to_check_returns_none(self) -> None:
        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.route_resolver.get_cloud_providers_to_check.return_value = []
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        result = await check.check(request)
        assert result is None

    async def test_non_cloud_ip_passes(self) -> None:
        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.route_resolver.get_cloud_providers_to_check.return_value = ["AWS"]
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        with patch(
            "guard_core.core.checks.implementations.cloud_provider.cloud_handler"
        ) as mock_cloud:
            mock_cloud.is_cloud_ip.return_value = False
            result = await check.check(request)
        assert result is None

    async def test_cloud_ip_blocks(self) -> None:
        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.route_resolver.get_cloud_providers_to_check.return_value = ["AWS"]
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        with patch(
            "guard_core.core.checks.implementations.cloud_provider.cloud_handler"
        ) as mock_cloud:
            mock_cloud.is_cloud_ip.return_value = True
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_cloud_ip_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.route_resolver.get_cloud_providers_to_check.return_value = ["AWS"]
        check = CloudProviderCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        with patch(
            "guard_core.core.checks.implementations.cloud_provider.cloud_handler"
        ) as mock_cloud:
            mock_cloud.is_cloud_ip.return_value = True
            result = await check.check(request)
        assert result is None


class TestCustomRequestCheck:
    async def test_no_custom_check_returns_none(self) -> None:
        middleware = _make_middleware()
        check = CustomRequestCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_custom_check_passes(self) -> None:
        async def my_check(req: GuardRequest) -> None:
            return None

        middleware = _make_middleware(custom_request_check=my_check)
        check = CustomRequestCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_custom_check_blocks(self) -> None:
        blocking_response = MockGuardResponse("Blocked", 429)

        async def my_check(req: GuardRequest) -> GuardResponse:
            return blocking_response

        middleware = _make_middleware(custom_request_check=my_check)
        check = CustomRequestCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 429

    async def test_custom_check_passive_mode(self) -> None:
        blocking_response = MockGuardResponse("Blocked", 429)

        async def my_check(req: GuardRequest) -> GuardResponse:
            return blocking_response

        middleware = _make_middleware(custom_request_check=my_check, passive_mode=True)
        check = CustomRequestCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None


class TestCustomValidatorsCheck:
    async def test_no_route_config_returns_none(self) -> None:
        middleware = _make_middleware()
        check = CustomValidatorsCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_no_validators_returns_none(self) -> None:
        middleware = _make_middleware()
        check = CustomValidatorsCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_validator_passes(self) -> None:
        async def good_validator(req: GuardRequest) -> None:
            return None

        middleware = _make_middleware()
        check = CustomValidatorsCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.custom_validators = [good_validator]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_validator_blocks(self) -> None:
        response = MockGuardResponse("Validation failed", 422)

        async def bad_validator(req: GuardRequest) -> GuardResponse:
            return response

        middleware = _make_middleware()
        check = CustomValidatorsCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.custom_validators = [bad_validator]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 422

    async def test_validator_blocks_passive_mode(self) -> None:
        response = MockGuardResponse("Validation failed", 422)

        async def bad_validator(req: GuardRequest) -> GuardResponse:
            return response

        middleware = _make_middleware(passive_mode=True)
        check = CustomValidatorsCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.custom_validators = [bad_validator]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_first_failing_validator_stops_chain(self) -> None:
        response = MockGuardResponse("First failed", 400)
        call_order = []

        async def first_validator(req: GuardRequest) -> GuardResponse:
            call_order.append("first")
            return response

        async def second_validator(req: GuardRequest) -> None:
            call_order.append("second")
            return None

        middleware = _make_middleware()
        check = CustomValidatorsCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.custom_validators = [first_validator, second_validator]
        request.state.route_config = rc
        await check.check(request)
        assert call_order == ["first"]


class TestTimeWindowCheck:
    async def test_no_route_config_returns_none(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_no_time_restrictions_returns_none(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_within_time_window_passes(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.time_restrictions = {"start": "00:00", "end": "23:59", "timezone": "UTC"}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_outside_time_window_blocks(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.time_restrictions = {"start": "00:00", "end": "00:01", "timezone": "UTC"}
        request.state.route_config = rc
        with patch(
            "guard_core.core.checks.implementations.time_window.datetime"
        ) as mock_dt:
            mock_now = MagicMock()
            mock_now.strftime.return_value = "12:00"
            mock_dt.now.return_value = mock_now
            mock_dt.side_effect = lambda *a, **kw: MagicMock()
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_outside_time_window_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.time_restrictions = {"start": "00:00", "end": "00:01", "timezone": "UTC"}
        request.state.route_config = rc
        with patch(
            "guard_core.core.checks.implementations.time_window.datetime"
        ) as mock_dt:
            mock_now = MagicMock()
            mock_now.strftime.return_value = "12:00"
            mock_dt.now.return_value = mock_now
            result = await check.check(request)
        assert result is None

    async def test_overnight_window_wraps(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.time_restrictions = {"start": "22:00", "end": "06:00", "timezone": "UTC"}
        request.state.route_config = rc
        with patch(
            "guard_core.core.checks.implementations.time_window.datetime"
        ) as mock_dt:
            mock_now = MagicMock()
            mock_now.strftime.return_value = "23:00"
            mock_dt.now.return_value = mock_now
            result = await check.check(request)
        assert result is None

    async def test_invalid_timezone_falls_back_to_utc(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.time_restrictions = {
            "start": "00:00",
            "end": "23:59",
            "timezone": "Invalid/Timezone",
        }
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_missing_keys_returns_none_via_error_handling(self) -> None:
        middleware = _make_middleware()
        check = TimeWindowCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.time_restrictions = {"timezone": "UTC"}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None


class TestRouteConfigCheck:
    async def test_sets_route_config_on_state(self) -> None:
        middleware = _make_middleware()
        mock_rc = RouteConfig()
        middleware.route_resolver.get_route_config.return_value = mock_rc
        check = RouteConfigCheck(middleware)
        request = MockGuardRequest(client_host="127.0.0.1")
        with patch(
            "guard_core.core.checks.implementations.route_config.extract_client_ip",
            new_callable=AsyncMock,
            return_value="127.0.0.1",
        ):
            result = await check.check(request)
        assert result is None
        assert request.state.route_config is mock_rc
        assert request.state.client_ip == "127.0.0.1"

    async def test_always_returns_none(self) -> None:
        middleware = _make_middleware()
        middleware.route_resolver.get_route_config.return_value = None
        check = RouteConfigCheck(middleware)
        request = MockGuardRequest()
        with patch(
            "guard_core.core.checks.implementations.route_config.extract_client_ip",
            new_callable=AsyncMock,
            return_value="127.0.0.1",
        ):
            result = await check.check(request)
        assert result is None


class TestRequestLoggingCheck:
    async def test_always_returns_none(self) -> None:
        middleware = _make_middleware()
        check = RequestLoggingCheck(middleware)
        request = MockGuardRequest()
        with patch(
            "guard_core.core.checks.implementations.request_logging.log_activity",
            new_callable=AsyncMock,
        ) as mock_log:
            result = await check.check(request)
        assert result is None
        mock_log.assert_called_once()


class TestCloudIpRefreshCheck:
    async def test_no_cloud_providers_returns_none(self) -> None:
        middleware = _make_middleware()
        check = CloudIpRefreshCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None
        middleware.refresh_cloud_ip_ranges.assert_not_called()

    async def test_refresh_not_needed_returns_none(self) -> None:
        middleware = _make_middleware(block_cloud_providers={"AWS"})
        middleware.last_cloud_ip_refresh = time.time()
        check = CloudIpRefreshCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None
        middleware.refresh_cloud_ip_ranges.assert_not_called()

    async def test_refresh_triggered_when_stale(self) -> None:
        middleware = _make_middleware(block_cloud_providers={"AWS"})
        middleware.last_cloud_ip_refresh = 0
        check = CloudIpRefreshCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None
        middleware.refresh_cloud_ip_ranges.assert_called_once()

    async def test_always_returns_none(self) -> None:
        middleware = _make_middleware(block_cloud_providers={"AWS"})
        middleware.last_cloud_ip_refresh = 0
        check = CloudIpRefreshCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None


class TestIpSecurityCheck:
    async def test_no_client_ip_returns_none(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware()
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_banned_ip_blocks(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with patch(
            "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban:
            mock_ban.is_ip_banned = AsyncMock(return_value=True)
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_banned_ip_passive_mode(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware(passive_mode=True)
        middleware.route_resolver.should_bypass_check.return_value = False
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with patch(
            "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban:
            mock_ban.is_ip_banned = AsyncMock(return_value=True)
            result = await check.check(request)
        assert result is None

    async def test_bypass_ip_check(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.side_effect = lambda name, rc: (
            name == "ip"
        )
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = RouteConfig()

        with patch(
            "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban:
            mock_ban.is_ip_banned = AsyncMock(return_value=False)
            result = await check.check(request)
        assert result is None

    async def test_route_ip_restriction_denied(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        rc = RouteConfig()
        rc.ip_blacklist = ["1.2.3.4"]
        request.state.route_config = rc

        with patch(
            "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban:
            mock_ban.is_ip_banned = AsyncMock(return_value=False)
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_global_ip_restriction_denied(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware(blacklist=["1.2.3.4"])
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.geo_ip_handler = None
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with (
            patch(
                "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
            ) as mock_ban,
            patch(
                "guard_core.core.checks.implementations.ip_security.is_ip_allowed",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            mock_ban.is_ip_banned = AsyncMock(return_value=False)
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_global_ip_allowed(self) -> None:
        from guard_core.core.checks.implementations.ip_security import IpSecurityCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.geo_ip_handler = None
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with (
            patch(
                "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
            ) as mock_ban,
            patch(
                "guard_core.core.checks.implementations.ip_security.is_ip_allowed",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            mock_ban.is_ip_banned = AsyncMock(return_value=False)
            result = await check.check(request)
        assert result is None


class TestRateLimitCheck:
    async def test_whitelisted_returns_none(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware()
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = True
        result = await check.check(request)
        assert result is None

    async def test_no_client_ip_returns_none(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware()
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        result = await check.check(request)
        assert result is None

    async def test_bypass_rate_limit(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = True
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        rc = RouteConfig()
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_endpoint_rate_limit_exceeded(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware(endpoint_rate_limits={"/api/test": (1, 60)})
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Rate limited", 429)
        )
        check = RateLimitCheck(middleware)
        request = MockGuardRequest(path="/api/test")
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 429

    async def test_route_rate_limit(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Rate limited", 429)
        )
        check = RateLimitCheck(middleware)
        request = MockGuardRequest(path="/test")
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        rc = RouteConfig()
        rc.rate_limit = 5
        rc.rate_limit_window = 60
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None

    async def test_geo_rate_limit(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Rate limited", 429)
        )
        geo = MagicMock()
        geo.get_country.return_value = "US"
        middleware.config.geo_ip_handler = geo
        check = RateLimitCheck(middleware)
        request = MockGuardRequest(path="/test")
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        rc = RouteConfig()
        rc.geo_rate_limits = {"US": (5, 60)}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None

    async def test_geo_rate_limit_wildcard(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Rate limited", 429)
        )
        geo = MagicMock()
        geo.get_country.return_value = "FR"
        middleware.config.geo_ip_handler = geo
        check = RateLimitCheck(middleware)
        request = MockGuardRequest(path="/test")
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        rc = RouteConfig()
        rc.geo_rate_limits = {"*": (10, 60)}
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None

    async def test_global_rate_limit_passive_mode(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware(passive_mode=True)
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Rate limited", 429)
        )
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None
        result = await check.check(request)
        assert result is None

    async def test_endpoint_rate_limit_passive_mode(self) -> None:
        from guard_core.core.checks.implementations.rate_limit import RateLimitCheck

        middleware = _make_middleware(
            passive_mode=True, endpoint_rate_limits={"/api": (1, 60)}
        )
        middleware.route_resolver.should_bypass_check.return_value = False
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Rate limited", 429)
        )
        check = RateLimitCheck(middleware)
        request = MockGuardRequest(path="/api")
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None
        result = await check.check(request)
        assert result is None


class TestSuspiciousActivityCheck:
    async def test_whitelisted_returns_none(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware()
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = True
        result = await check.check(request)
        assert result is None

    async def test_no_client_ip_returns_none(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware()
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        result = await check.check(request)
        assert result is None

    async def test_disabled_by_decorator(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware()
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with patch(
            "guard_core.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            new_callable=AsyncMock,
            return_value=(False, "disabled_by_decorator"),
        ):
            result = await check.check(request)
        assert result is None

    async def test_no_detection(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware()
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with patch(
            "guard_core.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            new_callable=AsyncMock,
            return_value=(False, "not_enabled"),
        ):
            result = await check.check(request)
        assert result is None

    async def test_detection_active_mode(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware()
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with patch(
            "guard_core.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            new_callable=AsyncMock,
            return_value=(True, "SQL injection"),
        ):
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 400

    async def test_detection_passive_mode(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware(passive_mode=True)
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with patch(
            "guard_core.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            new_callable=AsyncMock,
            return_value=(True, "XSS attempt"),
        ):
            result = await check.check(request)
        assert result is None

    async def test_detection_auto_ban(self) -> None:
        from guard_core.core.checks.implementations.suspicious_activity import (
            SuspiciousActivityCheck,
        )

        middleware = _make_middleware(enable_ip_banning=True, auto_ban_threshold=1)
        middleware.suspicious_request_counts = {"1.2.3.4": 1}
        check = SuspiciousActivityCheck(middleware)
        request = MockGuardRequest()
        request.state.is_whitelisted = False
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = None

        with (
            patch(
                "guard_core.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
                new_callable=AsyncMock,
                return_value=(True, "SQL injection"),
            ),
            patch(
                "guard_core.core.checks.implementations.suspicious_activity.ip_ban_manager"
            ) as mock_ban,
        ):
            mock_ban.ban_ip = AsyncMock()
            result = await check.check(request)
        assert result is not None
        assert result.status_code == 403


class TestReferrerCheck:
    async def test_no_route_config(self) -> None:
        from guard_core.core.checks.implementations.referrer import ReferrerCheck

        middleware = _make_middleware()
        check = ReferrerCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_no_require_referrer(self) -> None:
        from guard_core.core.checks.implementations.referrer import ReferrerCheck

        middleware = _make_middleware()
        check = ReferrerCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_missing_referrer(self) -> None:
        from guard_core.core.checks.implementations.referrer import ReferrerCheck

        middleware = _make_middleware()
        check = ReferrerCheck(middleware)
        request = MockGuardRequest(headers={})
        rc = RouteConfig()
        rc.require_referrer = ["example.com"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_invalid_referrer(self) -> None:
        from guard_core.core.checks.implementations.referrer import ReferrerCheck

        middleware = _make_middleware()
        check = ReferrerCheck(middleware)
        request = MockGuardRequest(headers={"referer": "https://evil.com/page"})
        rc = RouteConfig()
        rc.require_referrer = ["example.com"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 403

    async def test_valid_referrer(self) -> None:
        from guard_core.core.checks.implementations.referrer import ReferrerCheck

        middleware = _make_middleware()
        check = ReferrerCheck(middleware)
        request = MockGuardRequest(headers={"referer": "https://example.com/page"})
        rc = RouteConfig()
        rc.require_referrer = ["example.com"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_missing_referrer_passive(self) -> None:
        from guard_core.core.checks.implementations.referrer import ReferrerCheck

        middleware = _make_middleware(passive_mode=True)
        check = ReferrerCheck(middleware)
        request = MockGuardRequest(headers={})
        rc = RouteConfig()
        rc.require_referrer = ["example.com"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None


class TestRequestSizeContentCheck:
    async def test_no_route_config(self) -> None:
        from guard_core.core.checks.implementations.request_size_content import (
            RequestSizeContentCheck,
        )

        middleware = _make_middleware()
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest()
        result = await check.check(request)
        assert result is None

    async def test_size_exceeded(self) -> None:
        from guard_core.core.checks.implementations.request_size_content import (
            RequestSizeContentCheck,
        )

        middleware = _make_middleware()
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest(headers={"content-length": "5000"})
        rc = RouteConfig()
        rc.max_request_size = 1000
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 413

    async def test_size_ok(self) -> None:
        from guard_core.core.checks.implementations.request_size_content import (
            RequestSizeContentCheck,
        )

        middleware = _make_middleware()
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest(headers={"content-length": "500"})
        rc = RouteConfig()
        rc.max_request_size = 1000
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_content_type_blocked(self) -> None:
        from guard_core.core.checks.implementations.request_size_content import (
            RequestSizeContentCheck,
        )

        middleware = _make_middleware()
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest(headers={"content-type": "text/plain"})
        rc = RouteConfig()
        rc.allowed_content_types = ["application/json"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is not None
        assert result.status_code == 415

    async def test_content_type_allowed(self) -> None:
        from guard_core.core.checks.implementations.request_size_content import (
            RequestSizeContentCheck,
        )

        middleware = _make_middleware()
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest(headers={"content-type": "application/json"})
        rc = RouteConfig()
        rc.allowed_content_types = ["application/json"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None

    async def test_size_exceeded_passive(self) -> None:
        from guard_core.core.checks.implementations.request_size_content import (
            RequestSizeContentCheck,
        )

        middleware = _make_middleware(passive_mode=True)
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest(headers={"content-length": "5000"})
        rc = RouteConfig()
        rc.max_request_size = 1000
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None


class TestCheckNames:
    def test_all_check_names(self) -> None:
        middleware = _make_middleware()
        checks = [
            (EmergencyModeCheck, "emergency_mode"),
            (HttpsEnforcementCheck, "https_enforcement"),
            (RequiredHeadersCheck, "required_headers"),
            (AuthenticationCheck, "authentication"),
            (UserAgentCheck, "user_agent"),
            (CloudProviderCheck, "cloud_provider"),
            (CustomRequestCheck, "custom_request"),
            (CustomValidatorsCheck, "custom_validators"),
            (TimeWindowCheck, "time_window"),
            (RouteConfigCheck, "route_config"),
            (RequestLoggingCheck, "request_logging"),
            (CloudIpRefreshCheck, "cloud_ip_refresh"),
            (ReferrerCheck, "referrer"),
            (RequestSizeContentCheck, "request_size_content"),
            (RateLimitCheck, "rate_limit"),
            (SuspiciousActivityCheck, "suspicious_activity"),
            (IpSecurityCheck, "ip_security"),
        ]
        for check_cls, expected_name in checks:
            check = check_cls(middleware)
            assert check.check_name == expected_name


class TestIpSecurityCheckPassiveModeLines:
    async def test_bypass_ip_ban_check(self) -> None:
        middleware = _make_middleware()
        middleware.route_resolver.should_bypass_check.return_value = True
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        request.state.route_config = RouteConfig()
        result = await check._check_banned_ip(request, "1.2.3.4", RouteConfig())
        assert result is None

    async def test_route_ip_restriction_allowed(self) -> None:
        middleware = _make_middleware()
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"

        with patch(
            "guard_core.core.checks.implementations.ip_security.check_route_ip_access",
            new_callable=AsyncMock,
            return_value=True,
        ):
            result = await check._check_route_ip_restrictions(
                request, "1.2.3.4", RouteConfig()
            )
        assert result is None

    async def test_route_ip_restriction_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"
        rc = RouteConfig()
        rc.ip_blacklist = ["1.2.3.4"]

        with patch(
            "guard_core.core.checks.implementations.ip_security.check_route_ip_access",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check._check_route_ip_restrictions(request, "1.2.3.4", rc)
        assert result is None

    async def test_global_ip_restriction_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        middleware.geo_ip_handler = None
        check = IpSecurityCheck(middleware)
        request = MockGuardRequest()
        request.state.client_ip = "1.2.3.4"

        with patch(
            "guard_core.core.checks.implementations.ip_security.is_ip_allowed",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check._check_global_ip_restrictions(request, "1.2.3.4")
        assert result is None


class TestRateLimitCheckLines:
    async def test_geo_rate_limit_no_geo_handler(self) -> None:
        middleware = _make_middleware()
        middleware.config.geo_ip_handler = None
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.geo_rate_limits = {"US": (10, 60)}
        result = await check._check_geo_rate_limit(request, "1.2.3.4", rc)
        assert result is None

    async def test_geo_rate_limit_wildcard(self) -> None:
        middleware = _make_middleware()
        geo = MagicMock()
        geo.get_country.return_value = "FR"
        middleware.config.geo_ip_handler = geo
        middleware.rate_limit_handler = MagicMock()
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(return_value=None)
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.geo_rate_limits = {"*": (10, 60)}
        result = await check._check_geo_rate_limit(request, "1.2.3.4", rc)
        assert result is None

    async def test_global_rate_limit_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        middleware.rate_limit_handler = MagicMock()
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Too many", 429)
        )
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        result = await check._check_global_rate_limit(request, "1.2.3.4")
        assert result is None


class TestRateLimitCheckGeoNoMatch:
    async def test_geo_rate_limit_country_not_in_limits(self) -> None:
        middleware = _make_middleware()
        geo = MagicMock()
        geo.get_country.return_value = "FR"
        middleware.config.geo_ip_handler = geo
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        rc = RouteConfig()
        rc.geo_rate_limits = {"US": (10, 60)}
        result = await check._check_geo_rate_limit(request, "1.2.3.4", rc)
        assert result is None

    async def test_global_rate_limit_active_mode_exceeded(self) -> None:
        middleware = _make_middleware(passive_mode=False)
        middleware.rate_limit_handler = MagicMock()
        middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=MockGuardResponse("Too many", 429)
        )
        check = RateLimitCheck(middleware)
        request = MockGuardRequest()
        result = await check._check_global_rate_limit(request, "1.2.3.4")
        assert result is not None
        assert result.status_code == 429


class TestReferrerCheckPassiveMode:
    async def test_referrer_not_allowed_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = ReferrerCheck(middleware)
        request = MockGuardRequest(headers={"referer": "https://evil.com/page"})
        rc = RouteConfig()
        rc.require_referrer = True
        rc.allowed_referrers = ["trusted.com"]
        request.state.route_config = rc
        result = await check.check(request)
        assert result is None


class TestRequestSizeContentPassiveMode:
    async def test_content_type_not_allowed_passive_mode(self) -> None:
        middleware = _make_middleware(passive_mode=True)
        check = RequestSizeContentCheck(middleware)
        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "text/xml"},
        )
        rc = RouteConfig()
        rc.allowed_content_types = ["application/json"]
        request.state.route_config = rc
        result = await check._check_content_type_allowed(request, rc)
        assert result is None


class TestRequiredHeadersClassifyViolation:
    def test_classify_other_header(self) -> None:
        from guard_core.core.checks.implementations.required_headers import (
            _classify_header_violation,
        )

        header_type, violation = _classify_header_violation("X-Custom-Header")
        assert header_type == "advanced"
        assert violation == "required_header"
