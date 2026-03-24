from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def reset_ratelimit_singleton() -> Generator:
    RateLimitManager._instance = None
    yield
    RateLimitManager._instance = None


@pytest.fixture
def rate_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        rate_limit=10,
        rate_limit_window=60,
    )


@pytest.fixture
def rate_limiter(rate_config: SecurityConfig) -> RateLimitManager:
    return RateLimitManager(rate_config)


def test_singleton_behavior() -> None:
    config = SecurityConfig(enable_redis=False)
    m1 = RateLimitManager(config)
    m2 = RateLimitManager(config)
    assert m1 is m2


def test_initialization(
    rate_limiter: RateLimitManager, rate_config: SecurityConfig
) -> None:
    assert rate_limiter.config == rate_config
    assert rate_limiter.redis_handler is None
    assert rate_limiter.agent_handler is None


@pytest.mark.asyncio
async def test_initialize_redis(rate_limiter: RateLimitManager) -> None:
    from contextlib import asynccontextmanager

    class FakeConn:
        async def script_load(self, script: str) -> str:
            return "sha123"

    mock_redis = MagicMock()

    @asynccontextmanager
    async def fake_connection():
        yield FakeConn()

    mock_redis.get_connection = fake_connection
    rate_limiter.config.enable_redis = True

    await rate_limiter.initialize_redis(mock_redis)
    assert rate_limiter.redis_handler is mock_redis


@pytest.mark.asyncio
async def test_initialize_agent(rate_limiter: RateLimitManager) -> None:
    mock_agent = MagicMock()
    await rate_limiter.initialize_agent(mock_agent)
    assert rate_limiter.agent_handler is mock_agent


@pytest.mark.asyncio
async def test_reset(rate_limiter: RateLimitManager) -> None:
    rate_limiter.request_timestamps["127.0.0.1"].append(1.0)
    await rate_limiter.reset()
    assert len(rate_limiter.request_timestamps) == 0


@pytest.mark.asyncio
async def test_reset_with_redis(rate_limiter: RateLimitManager) -> None:
    rate_limiter.config.enable_redis = True
    rate_limiter.redis_handler = AsyncMock()
    rate_limiter.redis_handler.keys = AsyncMock(return_value=["key1"])
    rate_limiter.redis_handler.delete_pattern = AsyncMock()

    rate_limiter.request_timestamps["127.0.0.1"].append(1.0)
    await rate_limiter.reset()
    assert len(rate_limiter.request_timestamps) == 0
    rate_limiter.redis_handler.delete_pattern.assert_called_once()


@pytest.mark.asyncio
async def test_reset_with_redis_empty_keys(rate_limiter: RateLimitManager) -> None:
    rate_limiter.config.enable_redis = True
    rate_limiter.redis_handler = AsyncMock()
    rate_limiter.redis_handler.keys = AsyncMock(return_value=[])
    rate_limiter.redis_handler.delete_pattern = AsyncMock()

    await rate_limiter.reset()
    rate_limiter.redis_handler.delete_pattern.assert_not_called()


@pytest.mark.asyncio
async def test_reset_with_redis_error(rate_limiter: RateLimitManager) -> None:
    rate_limiter.config.enable_redis = True
    rate_limiter.redis_handler = AsyncMock()
    rate_limiter.redis_handler.keys = AsyncMock(side_effect=Exception("redis err"))

    await rate_limiter.reset()
    assert len(rate_limiter.request_timestamps) == 0


@pytest.mark.asyncio
async def test_send_rate_limit_event(rate_limiter: RateLimitManager) -> None:
    rate_limiter.agent_handler = AsyncMock()
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(path="/api/test", method="GET")
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await rate_limiter._send_rate_limit_event(request, "1.2.3.4", 15)
    rate_limiter.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_rate_limit_event_error(rate_limiter: RateLimitManager) -> None:
    rate_limiter.agent_handler = AsyncMock()
    rate_limiter.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await rate_limiter._send_rate_limit_event(request, "1.2.3.4", 15)


@pytest.mark.asyncio
async def test_check_rate_limit_disabled(rate_limiter: RateLimitManager) -> None:
    rate_limiter.config.enable_rate_limiting = False
    from tests.conftest import MockGuardRequest

    result = await rate_limiter.check_rate_limit(
        MockGuardRequest(), "127.0.0.1", AsyncMock()
    )
    assert result is None


@pytest.mark.asyncio
async def test_check_rate_limit_in_memory_exceeded(
    rate_limiter: RateLimitManager,
) -> None:
    from tests.conftest import MockGuardRequest, MockGuardResponse

    rate_limiter.config.enable_rate_limiting = True
    rate_limiter.config.rate_limit = 2

    create_error = AsyncMock(return_value=MockGuardResponse("Too many", 429))

    for _ in range(3):
        await rate_limiter.check_rate_limit(
            MockGuardRequest(), "10.0.0.1", create_error
        )

    result = await rate_limiter.check_rate_limit(
        MockGuardRequest(), "10.0.0.1", create_error
    )
    assert result is not None
    assert result.status_code == 429


@pytest.mark.asyncio
async def test_check_rate_limit_with_endpoint(rate_limiter: RateLimitManager) -> None:
    from tests.conftest import MockGuardRequest, MockGuardResponse

    rate_limiter.config.enable_rate_limiting = True
    rate_limiter.config.rate_limit = 2

    create_error = AsyncMock(return_value=MockGuardResponse("Too many", 429))

    for _ in range(3):
        await rate_limiter.check_rate_limit(
            MockGuardRequest(),
            "10.0.0.2",
            create_error,
            endpoint_path="/api/test",
            rate_limit=2,
            rate_limit_window=60,
        )

    result = await rate_limiter.check_rate_limit(
        MockGuardRequest(),
        "10.0.0.2",
        create_error,
        endpoint_path="/api/test",
        rate_limit=2,
        rate_limit_window=60,
    )
    assert result is not None


@pytest.mark.asyncio
async def test_get_redis_request_count_no_handler(
    rate_limiter: RateLimitManager,
) -> None:
    result = await rate_limiter._get_redis_request_count("127.0.0.1", 1.0, 0.0)
    assert result is None


@pytest.mark.asyncio
async def test_get_redis_request_count_with_script_sha(
    rate_limiter: RateLimitManager,
) -> None:
    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.evalsha = AsyncMock(return_value=5)
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        return_value=mock_conn
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = "sha123"

    result = await rate_limiter._get_redis_request_count("1.2.3.4", 1000.0, 940.0)
    assert result == 5


@pytest.mark.asyncio
async def test_get_redis_request_count_without_script_sha(
    rate_limiter: RateLimitManager,
) -> None:
    mock_redis = AsyncMock()
    mock_conn = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline.zadd = MagicMock()
    mock_pipeline.zremrangebyscore = MagicMock()
    mock_pipeline.zcard = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = AsyncMock(return_value=[None, None, 3, None])
    mock_conn.pipeline = MagicMock(return_value=mock_pipeline)
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        return_value=mock_conn
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = None

    result = await rate_limiter._get_redis_request_count("1.2.3.4", 1000.0, 940.0)
    assert result == 3


@pytest.mark.asyncio
async def test_get_redis_request_count_redis_error(
    rate_limiter: RateLimitManager,
) -> None:
    from redis.exceptions import RedisError

    mock_redis = AsyncMock()
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        side_effect=RedisError("fail")
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = "sha123"

    result = await rate_limiter._get_redis_request_count("1.2.3.4", 1000.0, 940.0)
    assert result is None


@pytest.mark.asyncio
async def test_get_redis_request_count_with_endpoint(
    rate_limiter: RateLimitManager,
) -> None:
    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.evalsha = AsyncMock(return_value=2)
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        return_value=mock_conn
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = "sha123"

    result = await rate_limiter._get_redis_request_count(
        "1.2.3.4", 1000.0, 940.0, endpoint_path="/api/test"
    )
    assert result == 2


@pytest.mark.asyncio
async def test_check_rate_limit_redis_exceeded(rate_limiter: RateLimitManager) -> None:
    from tests.conftest import MockGuardRequest, MockGuardResponse

    rate_limiter.config.enable_rate_limiting = True
    rate_limiter.config.enable_redis = True
    rate_limiter.config.rate_limit = 5

    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.evalsha = AsyncMock(return_value=10)
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        return_value=mock_conn
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = "sha123"

    create_error = AsyncMock(return_value=MockGuardResponse("Too many", 429))
    result = await rate_limiter.check_rate_limit(
        MockGuardRequest(), "1.2.3.4", create_error
    )
    assert result is not None
    assert result.status_code == 429


@pytest.mark.asyncio
async def test_check_rate_limit_redis_not_exceeded(
    rate_limiter: RateLimitManager,
) -> None:
    from tests.conftest import MockGuardRequest, MockGuardResponse

    rate_limiter.config.enable_rate_limiting = True
    rate_limiter.config.enable_redis = True
    rate_limiter.config.rate_limit = 100

    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.evalsha = AsyncMock(return_value=2)
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        return_value=mock_conn
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = "sha123"

    create_error = AsyncMock(return_value=MockGuardResponse("Too many", 429))
    result = await rate_limiter.check_rate_limit(
        MockGuardRequest(), "1.2.3.4", create_error
    )
    assert result is None


@pytest.mark.asyncio
async def test_handle_rate_limit_exceeded_with_agent(
    rate_limiter: RateLimitManager,
) -> None:
    from tests.conftest import MockGuardRequest, MockGuardResponse

    rate_limiter.agent_handler = AsyncMock()
    create_error = AsyncMock(return_value=MockGuardResponse("Too many", 429))

    with patch.object(rate_limiter, "_send_rate_limit_event", new_callable=AsyncMock):
        result = await rate_limiter._handle_rate_limit_exceeded(
            MockGuardRequest(), "1.2.3.4", 15, create_error
        )
    assert result.status_code == 429


@pytest.mark.asyncio
async def test_initialize_redis_script_load_error(
    rate_limiter: RateLimitManager,
) -> None:
    mock_redis = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.script_load = AsyncMock(side_effect=Exception("script error"))
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        return_value=mock_conn
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    rate_limiter.config.enable_redis = True

    await rate_limiter.initialize_redis(mock_redis)
    assert rate_limiter.redis_handler is mock_redis


@pytest.mark.asyncio
async def test_get_redis_request_count_unexpected_error(
    rate_limiter: RateLimitManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_connection = MagicMock()
    mock_redis.get_connection.return_value.__aenter__ = AsyncMock(
        side_effect=RuntimeError("unexpected")
    )
    mock_redis.get_connection.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "guard:"
    rate_limiter.redis_handler = mock_redis
    rate_limiter.rate_limit_script_sha = "sha123"

    result = await rate_limiter._get_redis_request_count("1.2.3.4", 1000.0, 940.0)
    assert result is None


def test_get_in_memory_request_count_with_endpoint(
    rate_limiter: RateLimitManager,
) -> None:
    import time
    from collections import deque

    now = time.time()
    key = "1.2.3.4:/api/test"
    rate_limiter.request_timestamps[key] = deque([now - 120, now - 90, now - 5])
    count = rate_limiter._get_in_memory_request_count(
        "1.2.3.4", now - 60, now, endpoint_path="/api/test"
    )
    assert count == 1
