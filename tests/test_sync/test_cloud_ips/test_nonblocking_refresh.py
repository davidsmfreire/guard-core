import ipaddress
import logging
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.cloud_ip_refresh import (
    CloudIpRefreshCheck,
)
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

_AWS_NET = ipaddress.ip_network("192.168.0.0/24")


@pytest.fixture(autouse=True)
def reset_cloud_handler() -> Generator[None, None]:
    cloud_handler.ip_ranges = {provider: set() for provider in cloud_handler.ip_ranges}
    cloud_handler._store = InMemoryCloudIpStore()
    cloud_handler.redis_handler = None
    cloud_handler._refresh_task = None
    cloud_handler._refresh_in_flight = False
    yield
    task = cloud_handler._refresh_task
    if task is not None and not task.done():
        task.join(timeout=1)
    cloud_handler._refresh_task = None
    cloud_handler._refresh_in_flight = False


def _make_check(interval: int = 3600, last_refresh: int = 0) -> CloudIpRefreshCheck:
    middleware = MagicMock()
    middleware.config = SecurityConfig(
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=interval,
    )
    middleware.logger = logging.getLogger("test.cloud_ip_refresh")
    middleware.last_cloud_ip_refresh = last_refresh
    return CloudIpRefreshCheck(middleware)


def _aws_ok() -> set:
    return {_AWS_NET}
