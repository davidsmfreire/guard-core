from typing import Any

from guard_core.core.routing.context import RoutingContext
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.protocols.request_protocol import GuardRequest


class RouteConfigResolver:
    def __init__(self, context: RoutingContext):
        self.context = context

    def get_guard_decorator(self, app: Any) -> BaseSecurityDecorator | None:
        if app and hasattr(app, "state") and hasattr(app.state, "guard_decorator"):
            app_guard_decorator = app.state.guard_decorator
            if isinstance(app_guard_decorator, BaseSecurityDecorator):
                return app_guard_decorator

        return self.context.guard_decorator if self.context.guard_decorator else None

    def is_matching_route(
        self, route: Any, path: str, method: str
    ) -> tuple[bool, str | None]:
        if not hasattr(route, "path") or not hasattr(route, "methods"):
            return False, None

        if route.path != path or method not in route.methods:
            return False, None

        if not hasattr(route, "endpoint") or not hasattr(
            route.endpoint, "_guard_route_id"
        ):
            return False, None

        return True, route.endpoint._guard_route_id

    def get_route_config(self, request: GuardRequest) -> RouteConfig | None:
        app = request.scope.get("app")

        guard_decorator = self.get_guard_decorator(app)
        if not guard_decorator:
            return None

        if not app:
            return None

        path = request.url_path
        method = request.method

        for route in app.routes:
            is_match, route_id = self.is_matching_route(route, path, method)
            if is_match and route_id:
                return guard_decorator.get_route_config(route_id)

        return None

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        if route_config and route_config.block_cloud_providers:
            return list(route_config.block_cloud_providers)
        if self.context.config.block_cloud_providers:
            return list(self.context.config.block_cloud_providers)
        return None
