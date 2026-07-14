import asyncio
import contextlib
import ipaddress
import logging
import time
from collections.abc import AsyncGenerator
from unittest.mock import MagicMock, patch

import pytest

from guard_core.core.checks.implementations.cloud_ip_refresh import CloudIpRefreshCheck
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore
from guard_core.models import SecurityConfig

_AWS_NET = ipaddress.ip_network("192.168.0.0/24")


@pytest.fixture(autouse=True)
async def reset_cloud_handler() -> AsyncGenerator[None, None]:
    cloud_handler.ip_ranges = {provider: set() for provider in cloud_handler.ip_ranges}
    cloud_handler._store = InMemoryCloudIpStore()
    cloud_handler.redis_handler = None
    cloud_handler._refresh_task = None
    cloud_handler._refresh_in_flight = False
    yield
    task = cloud_handler._refresh_task
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
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


async def _aws_ok() -> set:
    return {_AWS_NET}


async def test_schedule_refresh_runs_fetch_in_background() -> None:  # async-only
    with patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges", new=_aws_ok):
        started = await cloud_handler.schedule_refresh({"AWS"}, ttl=3600)
        assert started is True
        task = cloud_handler._refresh_task
        assert task is not None
        await task

    assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})


async def test_schedule_refresh_is_single_flight() -> None:  # async-only
    started_evt = asyncio.Event()
    release_evt = asyncio.Event()

    async def slow_aws() -> set:
        started_evt.set()
        await release_evt.wait()
        return {_AWS_NET}

    with patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges", new=slow_aws):
        assert await cloud_handler.schedule_refresh({"AWS"}) is True
        await started_evt.wait()
        first_task = cloud_handler._refresh_task

        # Second call while the first is in flight must NOT start a new task.
        assert await cloud_handler.schedule_refresh({"AWS"}) is False
        assert cloud_handler._refresh_task is first_task

        release_evt.set()
        await first_task


async def test_check_returns_immediately_when_fetch_hangs() -> None:  # async-only
    hang = asyncio.Event()

    async def hanging_aws() -> set:
        await hang.wait()
        return set()

    check = _make_check(last_refresh=0)
    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges", new=hanging_aws
    ):
        # The request path must not block on the fetch.
        result = await asyncio.wait_for(check.check(MagicMock()), timeout=1.0)

    assert result is None
    assert check.middleware.last_cloud_ip_refresh > 0  # debounce bumped up front
    assert cloud_handler._refresh_task is not None  # refresh scheduled in background


async def test_check_skips_refresh_within_interval() -> None:  # async-only
    check = _make_check(last_refresh=int(time.time()))
    with patch.object(cloud_handler, "schedule_refresh") as spy:
        result = await check.check(MagicMock())

    assert result is None
    spy.assert_not_called()


async def test_check_noop_without_block_cloud_providers() -> None:  # async-only
    middleware = MagicMock()
    middleware.config = SecurityConfig(block_cloud_providers=None)
    middleware.logger = logging.getLogger("test.cloud_ip_refresh")
    middleware.last_cloud_ip_refresh = 0
    check = CloudIpRefreshCheck(middleware)

    with patch.object(cloud_handler, "schedule_refresh") as spy:
        result = await check.check(MagicMock())

    assert result is None
    spy.assert_not_called()
    assert middleware.last_cloud_ip_refresh == 0


async def test_schedule_refresh_logs_and_recovers_on_failure(  # async-only
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def boom() -> set:
        raise RuntimeError("azure down")

    with patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges", new=boom):
        with caplog.at_level(logging.ERROR, logger="guard_core.handlers.cloud"):
            assert await cloud_handler.schedule_refresh({"AWS"}) is True
            task = cloud_handler._refresh_task
            assert task is not None
            await task

        assert "Failed to refresh AWS IP ranges" in caplog.text
        # Failure is swallowed (never propagates to the request) and the slot frees.
        assert cloud_handler._refresh_in_flight is False
        assert await cloud_handler.schedule_refresh({"AWS"}) is True
        second = cloud_handler._refresh_task
        if second is not None:
            second.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await second


async def test_run_refresh_logs_when_refresh_async_itself_raises(  # async-only
    caplog: pytest.LogCaptureFixture,
) -> None:
    from unittest.mock import AsyncMock

    with patch.object(
        cloud_handler, "refresh_async", new=AsyncMock(side_effect=RuntimeError("boom"))
    ):
        with caplog.at_level(logging.ERROR, logger="guard_core.handlers.cloud"):
            assert await cloud_handler.schedule_refresh({"AWS"}) is True
            task = cloud_handler._refresh_task
            assert task is not None
            await task

    assert "Background cloud IP refresh failed" in caplog.text
    # The background task swallowed the error and freed the slot.
    assert cloud_handler._refresh_in_flight is False


async def test_schedule_refresh_recovers_when_task_creation_fails(  # async-only
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _reject(coro: object) -> None:
        coro.close()  # type: ignore[attr-defined]  # don't leak the coroutine
        raise RuntimeError("no running loop")

    with patch(
        "guard_core.handlers.cloud_handler.asyncio.create_task", side_effect=_reject
    ):
        with caplog.at_level(logging.ERROR, logger="guard_core.handlers.cloud"):
            started = await cloud_handler.schedule_refresh({"AWS"})

    assert started is False
    assert "Could not schedule cloud IP refresh" in caplog.text
    # The in-flight flag must be reset so a later call can retry.
    assert cloud_handler._refresh_in_flight is False
