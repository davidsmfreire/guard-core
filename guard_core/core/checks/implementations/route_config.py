from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip


class RouteConfigCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "route_config"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = self.middleware.route_resolver.get_route_config(request)
        request.state.route_config = route_config
        request.state.client_ip = await extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        return None
