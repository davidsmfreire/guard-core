from unittest.mock import Mock

import pytest

from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig


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
def mock_request() -> Mock:
    request = Mock()
    request.url_path = "/api/test"
    request.method = "GET"
    request.scope = {"app": None}
    return request


def test_init(routing_context: RoutingContext) -> None:
    resolver = RouteConfigResolver(routing_context)
    assert resolver.context == routing_context


def test_get_guard_decorator_from_app_state(
    resolver: RouteConfigResolver, mock_guard_decorator: BaseSecurityDecorator
) -> None:
    app = Mock()
    app.state = Mock()
    app.state.guard_decorator = mock_guard_decorator

    result = resolver.get_guard_decorator(app)
    assert result == mock_guard_decorator


def test_get_guard_decorator_from_context(
    resolver: RouteConfigResolver, mock_guard_decorator: BaseSecurityDecorator
) -> None:
    app = Mock()
    app.state = Mock(spec=[])

    result = resolver.get_guard_decorator(app)
    assert result == mock_guard_decorator


def test_get_guard_decorator_none_when_not_base_security_decorator(
    resolver: RouteConfigResolver,
) -> None:
    app = Mock()
    app.state = Mock()
    app.state.guard_decorator = "not a decorator"

    result = resolver.get_guard_decorator(app)
    assert result == resolver.context.guard_decorator


def test_get_guard_decorator_none_when_no_app(
    resolver: RouteConfigResolver,
) -> None:
    result = resolver.get_guard_decorator(None)
    assert result == resolver.context.guard_decorator


def test_get_guard_decorator_none_when_context_has_none() -> None:
    context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
    resolver = RouteConfigResolver(context)

    result = resolver.get_guard_decorator(None)
    assert result is None


def test_is_matching_route_success(resolver: RouteConfigResolver) -> None:
    route = Mock()
    route.path = "/api/test"
    route.methods = {"GET", "POST"}
    route.endpoint = Mock()
    route.endpoint._guard_route_id = "test_route_id"

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is True
    assert route_id == "test_route_id"


def test_is_matching_route_no_path_attribute(
    resolver: RouteConfigResolver,
) -> None:
    route = Mock(spec=[])

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is False
    assert route_id is None


def test_is_matching_route_no_methods_attribute(
    resolver: RouteConfigResolver,
) -> None:
    route = Mock(spec=["path"])
    route.path = "/api/test"

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is False
    assert route_id is None


def test_is_matching_route_path_mismatch(
    resolver: RouteConfigResolver,
) -> None:
    route = Mock()
    route.path = "/api/other"
    route.methods = {"GET"}

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is False
    assert route_id is None


def test_is_matching_route_method_mismatch(
    resolver: RouteConfigResolver,
) -> None:
    route = Mock()
    route.path = "/api/test"
    route.methods = {"POST"}

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is False
    assert route_id is None


def test_is_matching_route_no_endpoint(resolver: RouteConfigResolver) -> None:
    route = Mock(spec=["path", "methods"])
    route.path = "/api/test"
    route.methods = {"GET"}

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is False
    assert route_id is None


def test_is_matching_route_no_guard_route_id(
    resolver: RouteConfigResolver,
) -> None:
    route = Mock()
    route.path = "/api/test"
    route.methods = {"GET"}
    route.endpoint = Mock(spec=[])

    is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
    assert is_match is False
    assert route_id is None


def test_get_route_config_success(
    resolver: RouteConfigResolver,
    mock_request: Mock,
    mock_guard_decorator: BaseSecurityDecorator,
) -> None:
    app = Mock()
    app.state = Mock()
    app.state.guard_decorator = mock_guard_decorator
    mock_request.scope = {"app": app}

    route = Mock()
    route.path = "/api/test"
    route.methods = {"GET"}
    route.endpoint = Mock()
    route.endpoint._guard_route_id = "test_route_id"
    app.routes = [route]

    result = resolver.get_route_config(mock_request)
    assert result is not None
    assert "rate_limit" in result.bypassed_checks


def test_get_route_config_no_decorator(mock_request: Mock) -> None:
    context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
    resolver = RouteConfigResolver(context)

    result = resolver.get_route_config(mock_request)
    assert result is None


def test_get_route_config_no_app(
    resolver: RouteConfigResolver, mock_request: Mock
) -> None:
    mock_request.scope = {"app": None}

    result = resolver.get_route_config(mock_request)
    assert result is None


def test_get_route_config_no_matching_route(
    resolver: RouteConfigResolver,
    mock_request: Mock,
    mock_guard_decorator: BaseSecurityDecorator,
) -> None:
    app = Mock()
    app.state = Mock()
    app.state.guard_decorator = mock_guard_decorator
    mock_request.scope = {"app": app}

    route = Mock()
    route.path = "/api/other"
    route.methods = {"GET"}
    app.routes = [route]

    result = resolver.get_route_config(mock_request)
    assert result is None


def test_should_bypass_check_no_config(resolver: RouteConfigResolver) -> None:
    result = resolver.should_bypass_check("rate_limit", None)
    assert result is False


def test_should_bypass_check_specific_check(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit", "ip_check"}

    result = resolver.should_bypass_check("rate_limit", route_config)
    assert result is True


def test_should_bypass_check_all_checks(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}

    result = resolver.should_bypass_check("any_check", route_config)
    assert result is True


def test_should_bypass_check_not_bypassed(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"ip_check"}

    result = resolver.should_bypass_check("rate_limit", route_config)
    assert result is False


def test_get_cloud_providers_from_route_config(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.block_cloud_providers = {"azure", "digitalocean"}

    result = resolver.get_cloud_providers_to_check(route_config)
    assert result == ["azure", "digitalocean"] or result == [
        "digitalocean",
        "azure",
    ]
    assert set(result) == {"azure", "digitalocean"}


def test_get_cloud_providers_from_global_config(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()

    result = resolver.get_cloud_providers_to_check(route_config)
    assert result == ["aws", "gcp"] or result == ["gcp", "aws"]
    assert set(result) == {"aws", "gcp"}


def test_get_cloud_providers_none_when_no_config(
    resolver: RouteConfigResolver,
) -> None:
    result = resolver.get_cloud_providers_to_check(None)
    assert result == ["aws", "gcp"] or result == ["gcp", "aws"]
    assert set(result) == {"aws", "gcp"}


def test_get_cloud_providers_none_when_empty() -> None:
    config = Mock()
    config.block_cloud_providers = set()
    context = RoutingContext(config=config, logger=Mock(), guard_decorator=None)
    resolver = RouteConfigResolver(context)

    result = resolver.get_cloud_providers_to_check(None)
    assert result is None
