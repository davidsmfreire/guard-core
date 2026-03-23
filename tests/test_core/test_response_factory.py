import logging
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.models import SecurityConfig
from tests.conftest import (
    MockGuardRequest,
    MockGuardResponse,
    MockGuardResponseFactory,
)


@pytest.fixture
def config():
    return SecurityConfig(enable_redis=False)


@pytest.fixture
def response_context(config):
    metrics = MetricsCollector(agent_handler=None, config=config)
    ctx = ResponseContext(
        config=config,
        logger=logging.getLogger("test"),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ctx


@pytest.fixture
def factory(response_context):
    return ErrorResponseFactory(response_context)


class TestCreateErrorResponse:
    @pytest.mark.asyncio
    async def test_default_message(self, factory):
        response = await factory.create_error_response(403, "Forbidden")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_custom_error_response(self, factory):
        factory.context.config.custom_error_responses[403] = "Custom Forbidden"
        response = await factory.create_error_response(403, "Forbidden")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_with_response_modifier(self, factory):
        async def modifier(resp):
            resp._headers["X-Modified"] = "true"
            return resp

        factory.context.config.custom_response_modifier = modifier
        response = await factory.create_error_response(403, "Forbidden")
        assert response.headers["X-Modified"] == "true"


class TestCreateHttpsRedirect:
    @pytest.mark.asyncio
    async def test_redirect(self, factory):
        request = MockGuardRequest(path="/secure", scheme="http")
        response = await factory.create_https_redirect(request)
        assert response.status_code == 301
        assert "https" in response.headers["Location"]

    @pytest.mark.asyncio
    async def test_redirect_with_modifier(self, factory):
        async def modifier(resp):
            resp._headers["X-Redirected"] = "yes"
            return resp

        factory.context.config.custom_response_modifier = modifier
        request = MockGuardRequest(path="/page", scheme="http")
        response = await factory.create_https_redirect(request)
        assert response.headers["X-Redirected"] == "yes"


class TestApplySecurityHeaders:
    @pytest.mark.asyncio
    async def test_headers_applied_when_enabled(self, factory):
        response = MockGuardResponse()
        result = await factory.apply_security_headers(response)
        assert isinstance(result, MockGuardResponse)

    @pytest.mark.asyncio
    async def test_headers_skipped_when_disabled(self, factory):
        factory.context.config.security_headers = {"enabled": False}
        response = MockGuardResponse()
        result = await factory.apply_security_headers(response)
        assert len(result.headers) == 0

    @pytest.mark.asyncio
    async def test_headers_skipped_when_none(self, factory):
        factory.context.config.security_headers = None
        response = MockGuardResponse()
        result = await factory.apply_security_headers(response)
        assert len(result.headers) == 0


class TestApplyCorsHeaders:
    @pytest.mark.asyncio
    async def test_cors_headers_applied(self, factory):
        response = MockGuardResponse()
        result = await factory.apply_cors_headers(response, "https://example.com")
        assert isinstance(result, MockGuardResponse)

    @pytest.mark.asyncio
    async def test_cors_headers_actually_set(self, factory):
        from guard_core.handlers.security_headers_handler import (
            security_headers_manager,
        )

        security_headers_manager.configure(
            enabled=True,
            cors_origins=["https://example.com"],
        )
        response = MockGuardResponse()
        result = await factory.apply_cors_headers(response, "https://example.com")
        assert "Access-Control-Allow-Origin" in result.headers
        await security_headers_manager.reset()

    @pytest.mark.asyncio
    async def test_cors_headers_skipped_when_disabled(self, factory):
        factory.context.config.security_headers = {"enabled": False}
        response = MockGuardResponse()
        result = await factory.apply_cors_headers(response, "https://example.com")
        assert len(result.headers) == 0

    @pytest.mark.asyncio
    async def test_cors_headers_skipped_when_none(self, factory):
        factory.context.config.security_headers = None
        response = MockGuardResponse()
        result = await factory.apply_cors_headers(response, "https://example.com")
        assert len(result.headers) == 0


class TestApplyModifier:
    @pytest.mark.asyncio
    async def test_no_modifier(self, factory):
        response = MockGuardResponse()
        result = await factory.apply_modifier(response)
        assert result is response

    @pytest.mark.asyncio
    async def test_with_modifier(self, factory):
        async def modifier(resp):
            resp._headers["X-Custom"] = "value"
            return resp

        factory.context.config.custom_response_modifier = modifier
        response = MockGuardResponse()
        result = await factory.apply_modifier(response)
        assert result.headers["X-Custom"] == "value"


class TestProcessResponse:
    @pytest.mark.asyncio
    async def test_basic_process(self, factory):
        request = MockGuardRequest()
        response = MockGuardResponse()
        result = await factory.process_response(
            request, response, 0.1, route_config=None
        )
        assert isinstance(result, MockGuardResponse)

    @pytest.mark.asyncio
    async def test_process_with_origin_header(self, factory):
        request = MockGuardRequest(headers={"origin": "https://example.com"})
        response = MockGuardResponse()
        result = await factory.process_response(
            request, response, 0.05, route_config=None
        )
        assert isinstance(result, MockGuardResponse)

    @pytest.mark.asyncio
    async def test_process_with_behavioral_rules(self, factory):
        from guard_core.decorators.base import RouteConfig
        from guard_core.handlers.behavior_handler import BehaviorRule

        rc = RouteConfig()
        rc.behavior_rules.append(BehaviorRule(rule_type="usage", threshold=10))

        callback = AsyncMock()

        request = MockGuardRequest()
        response = MockGuardResponse()

        with patch(
            "guard_core.core.responses.factory.extract_client_ip",
            new_callable=AsyncMock,
            return_value="127.0.0.1",
        ):
            await factory.process_response(
                request,
                response,
                0.1,
                route_config=rc,
                process_behavioral_rules=callback,
            )

        callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_no_behavioral_callback(self, factory):
        from guard_core.decorators.base import RouteConfig
        from guard_core.handlers.behavior_handler import BehaviorRule

        rc = RouteConfig()
        rc.behavior_rules.append(BehaviorRule(rule_type="usage", threshold=10))

        request = MockGuardRequest()
        response = MockGuardResponse()
        result = await factory.process_response(
            request,
            response,
            0.1,
            route_config=rc,
            process_behavioral_rules=None,
        )
        assert isinstance(result, MockGuardResponse)


class TestApplyModifierEdge:
    @pytest.mark.asyncio
    async def test_modifier_raises_propagates(self, factory):
        async def bad_modifier(resp):
            raise ValueError("bad modifier")

        factory.context.config.custom_response_modifier = bad_modifier
        response = MockGuardResponse()
        with pytest.raises(ValueError):
            await factory.apply_modifier(response)
