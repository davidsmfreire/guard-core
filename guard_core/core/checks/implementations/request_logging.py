from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


class RequestLoggingCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "request_logging"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        await log_activity(request, self.logger, level=self.config.log_request_level)
        return None
