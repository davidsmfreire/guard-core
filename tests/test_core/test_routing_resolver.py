from unittest.mock import Mock

import pytest

from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from tests.conftest import MockGuardRequest


@pytest.fixture
def mock_config() -> Mock:
    config = Mock()
    config.block_cloud_providers = {"aws", "gcp"}
    return config


@pytest.fixture
def mock_guard_decorator() -> BaseSecurityDecorator:
    decorator = Mock(spec=BaseSecurityDecorator)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit"}
    decorator.get_route_config = Mock(return_value=route_config)
    return decorator


@pytest.fixture
def routing_context(
    mock_config: Mock, mock_guard_decorator: BaseSecurityDecorator
) -> RoutingContext:
    return RoutingContext(
        config=mock_config,
        logger=Mock(),
        guard_decorator=mock_guard_decorator,
    )


@pytest.fixture
def resolver(routing_context: RoutingContext) -> RouteConfigResolver:
    return RouteConfigResolver(routing_context)


@pytest.fixture
def mock_req() -> MockGuardRequest:
    return MockGuardRequest(
        path="/api/test",
        method="GET",
        scope={"app": None},
    )


class TestRouteConfigResolver:
    def test_init(self, routing_context: RoutingContext) -> None:
        resolver = RouteConfigResolver(routing_context)
        assert resolver.context == routing_context

    def test_get_guard_decorator_from_app_state(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = mock_guard_decorator

        result = resolver.get_guard_decorator(app)
        assert result == mock_guard_decorator

    def test_get_guard_decorator_from_context(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        app = Mock()
        app.state = Mock(spec=[])

        result = resolver.get_guard_decorator(app)
        assert result == mock_guard_decorator

    def test_get_guard_decorator_none_when_not_base_security_decorator(
        self, resolver: RouteConfigResolver
    ) -> None:
        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = "not a decorator"

        result = resolver.get_guard_decorator(app)
        assert result == resolver.context.guard_decorator

    def test_get_guard_decorator_none_when_no_app(
        self, resolver: RouteConfigResolver
    ) -> None:
        result = resolver.get_guard_decorator(None)
        assert result == resolver.context.guard_decorator

    def test_get_guard_decorator_none_when_context_has_none(self) -> None:
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_guard_decorator(None)
        assert result is None

    def test_is_matching_route_success(self, resolver: RouteConfigResolver) -> None:
        route = Mock()
        route.path = "/api/test"
        route.methods = {"GET", "POST"}
        route.endpoint = Mock()
        route.endpoint._guard_route_id = "test_route_id"

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is True
        assert route_id == "test_route_id"

    def test_is_matching_route_no_path_attribute(
        self, resolver: RouteConfigResolver
    ) -> None:
        route = Mock(spec=[])

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_path_mismatch(
        self, resolver: RouteConfigResolver
    ) -> None:
        route = Mock()
        route.path = "/api/other"
        route.methods = {"GET"}

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_method_mismatch(
        self, resolver: RouteConfigResolver
    ) -> None:
        route = Mock()
        route.path = "/api/test"
        route.methods = {"POST"}

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_no_endpoint(self, resolver: RouteConfigResolver) -> None:
        route = Mock(spec=["path", "methods"])
        route.path = "/api/test"
        route.methods = {"GET"}

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_no_guard_route_id(
        self, resolver: RouteConfigResolver
    ) -> None:
        route = Mock()
        route.path = "/api/test"
        route.methods = {"GET"}
        route.endpoint = Mock(spec=[])

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_get_route_config_no_decorator(self) -> None:
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)
        req = MockGuardRequest(path="/test", method="GET", scope={})

        result = resolver.get_route_config(req)
        assert result is None

    def test_get_route_config_no_app(self, resolver: RouteConfigResolver) -> None:
        req = MockGuardRequest(path="/test", method="GET", scope={"app": None})

        result = resolver.get_route_config(req)
        assert result is None

    def test_should_bypass_check_no_config(self, resolver: RouteConfigResolver) -> None:
        result = resolver.should_bypass_check("rate_limit", None)
        assert result is False

    def test_should_bypass_check_specific_check(
        self, resolver: RouteConfigResolver
    ) -> None:
        route_config = RouteConfig()
        route_config.bypassed_checks = {"rate_limit", "ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is True

    def test_should_bypass_check_all_checks(
        self, resolver: RouteConfigResolver
    ) -> None:
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}

        result = resolver.should_bypass_check("any_check", route_config)
        assert result is True

    def test_should_bypass_check_not_bypassed(
        self, resolver: RouteConfigResolver
    ) -> None:
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is False

    def test_get_cloud_providers_from_route_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        route_config = RouteConfig()
        route_config.block_cloud_providers = {"azure", "digitalocean"}

        result = resolver.get_cloud_providers_to_check(route_config)
        assert set(result) == {"azure", "digitalocean"}

    def test_get_cloud_providers_from_global_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        route_config = RouteConfig()

        result = resolver.get_cloud_providers_to_check(route_config)
        assert set(result) == {"aws", "gcp"}

    def test_get_cloud_providers_none_when_no_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        result = resolver.get_cloud_providers_to_check(None)
        assert set(result) == {"aws", "gcp"}

    def test_get_cloud_providers_none_when_empty(self) -> None:
        config = Mock()
        config.block_cloud_providers = set()
        context = RoutingContext(config=config, logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_cloud_providers_to_check(None)
        assert result is None

    def test_get_route_config_with_matching_route(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        route = Mock()
        route.path = "/api/test"
        route.methods = {"GET"}
        route.endpoint = Mock()
        route.endpoint._guard_route_id = "test_id"

        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = mock_guard_decorator
        app.routes = [route]

        req = MockGuardRequest(path="/api/test", method="GET", scope={"app": app})
        result = resolver.get_route_config(req)
        assert result is not None

    def test_get_route_config_no_matching_route(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        route = Mock()
        route.path = "/api/other"
        route.methods = {"GET"}

        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = mock_guard_decorator
        app.routes = [route]

        req = MockGuardRequest(path="/api/test", method="GET", scope={"app": app})
        result = resolver.get_route_config(req)
        assert result is None
