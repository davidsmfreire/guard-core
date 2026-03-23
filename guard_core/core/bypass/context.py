from dataclasses import dataclass
from logging import Logger

from guard_core.core.events import SecurityEventBus
from guard_core.core.responses import ErrorResponseFactory
from guard_core.core.routing import RouteConfigResolver
from guard_core.core.validation import RequestValidator
from guard_core.models import SecurityConfig


@dataclass
class BypassContext:
    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    route_resolver: RouteConfigResolver
    response_factory: ErrorResponseFactory
    validator: RequestValidator
