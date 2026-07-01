import time

from guard_core.core.checks.base import SecurityCheck
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class CloudIpRefreshCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.block_cloud_providers:
            return None

        if (
            time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            # Bump the timestamp before scheduling so concurrent requests don't all
            # trigger their own refresh, then fetch in the background rather than
            # running it inline on the request path (a slow fetch would otherwise
            # block request handling).
            self.middleware.last_cloud_ip_refresh = int(time.time())
            await cloud_handler.schedule_refresh(
                {str(provider) for provider in self.config.block_cloud_providers},
                ttl=self.config.cloud_ip_refresh_interval,
            )
        return None
