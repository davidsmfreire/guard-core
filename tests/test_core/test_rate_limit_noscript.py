from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.exceptions import NoScriptError, RedisError

from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig


@pytest.fixture
def manager() -> RateLimitManager:
    config = SecurityConfig(enable_redis=True, rate_limit=100, rate_limit_window=60)
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "deadbeef"
    return mgr


def _make_redis_handler(conn: AsyncMock) -> MagicMock:
    redis_handler = MagicMock()
    redis_handler.config = MagicMock(redis_prefix="test:")
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=None)
    redis_handler.get_connection = MagicMock(return_value=cm)
    return redis_handler


@pytest.mark.asyncio
async def test_noscript_triggers_reload_and_retry_succeeds(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), 1])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    result = await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert result == 1
    assert conn.script_load.await_count == 1
    assert conn.evalsha.await_count == 2
    assert manager.rate_limit_script_sha == "newsha"


@pytest.mark.asyncio
async def test_noscript_reload_failure_falls_through(
    manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=NoScriptError("NOSCRIPT"))
    conn.script_load = AsyncMock(side_effect=RedisError("connection lost"))
    manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.ERROR)
    result = await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert result is None
    assert any("Redis rate limiting error" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_double_noscript_falls_through(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(
        side_effect=[NoScriptError("first"), NoScriptError("second")]
    )
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    result = await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert result is None


@pytest.mark.asyncio
async def test_generic_redis_error_unchanged(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=RedisError("connection refused"))
    manager.redis_handler = _make_redis_handler(conn)

    result = await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert result is None
    assert conn.script_load.await_count == 0


@pytest.mark.asyncio
async def test_script_reloaded_emits_agent_event(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), 1])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    agent = AsyncMock()
    manager.agent_handler = agent

    await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert agent.send_event.await_count == 1
    sent_event = agent.send_event.await_args.args[0]
    assert sent_event.event_type == "rate_limit_script_reloaded"


@pytest.mark.asyncio
async def test_script_reloaded_without_agent_handler_no_error(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), 1])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)
    manager.agent_handler = None

    result = await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert result == 1


@pytest.mark.asyncio
async def test_script_reload_event_emission_failure_swallowed(
    manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), 1])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    agent = AsyncMock()
    agent.send_event = AsyncMock(side_effect=RuntimeError("agent down"))
    manager.agent_handler = agent

    caplog.set_level(logging.ERROR)
    result = await manager._get_redis_request_count(
        client_ip="1.1.1.1",
        current_time=100.0,
        window_start=40.0,
    )

    assert result == 1
    assert any(
        "Failed to send script-reload event" in r.message for r in caplog.records
    )
