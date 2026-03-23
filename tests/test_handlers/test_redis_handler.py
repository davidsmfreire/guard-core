from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def reset_redis_singleton() -> Generator:
    RedisManager._instance = None
    yield
    RedisManager._instance = None


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(enable_redis=True)


@pytest.fixture
def config_disabled() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)


@pytest.fixture
def manager(config: SecurityConfig) -> RedisManager:
    return RedisManager(config)


def test_new_creates_instance(config: SecurityConfig) -> None:
    m = RedisManager(config)
    assert m.config is config
    assert m._closed is False
    assert m.agent_handler is None


async def test_initialize_agent(manager: RedisManager) -> None:
    agent = MagicMock()
    await manager.initialize_agent(agent)
    assert manager.agent_handler is agent


async def test_send_redis_event_no_agent(manager: RedisManager) -> None:
    await manager._send_redis_event("test", "action", "reason")


async def test_send_redis_event_with_agent(manager: RedisManager) -> None:
    agent = AsyncMock()
    manager.agent_handler = agent

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_redis_event("test", "action", "reason", extra="data")
    agent.send_event.assert_called_once()


async def test_send_redis_event_import_error(manager: RedisManager) -> None:
    agent = AsyncMock()
    agent.send_event = AsyncMock(side_effect=Exception("import fail"))
    manager.agent_handler = agent
    await manager._send_redis_event("test", "action", "reason")


async def test_initialize_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    await m.initialize()
    assert m._redis is None


async def test_initialize_none_url() -> None:
    config = SecurityConfig(enable_redis=True, redis_url=None)
    m = RedisManager(config)
    await m.initialize()
    assert m._redis is None


async def test_initialize_success(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock()

    with patch("guard_core.handlers.redis_handler.Redis") as MockRedis:
        MockRedis.from_url.return_value = mock_redis
        await m.initialize()
        assert m._redis is mock_redis


async def test_initialize_failure(config: SecurityConfig) -> None:
    m = RedisManager(config)

    with patch("guard_core.handlers.redis_handler.Redis") as MockRedis:
        MockRedis.from_url.side_effect = Exception("connection failed")
        with pytest.raises(GuardRedisError):
            await m.initialize()
    assert m._redis is None


async def test_close_with_connection(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    m._redis = mock_redis

    await m.close()
    mock_redis.aclose.assert_called_once()
    assert m._redis is None
    assert m._closed is True


async def test_close_without_connection(config: SecurityConfig) -> None:
    m = RedisManager(config)
    await m.close()
    assert m._closed is True


async def test_close_sends_event(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    m._redis = mock_redis
    m.agent_handler = AsyncMock()

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await m.close()

    m.agent_handler.send_event.assert_called_once()


async def test_get_connection_closed(config: SecurityConfig) -> None:
    m = RedisManager(config)
    m._closed = True

    with pytest.raises(GuardRedisError):
        async with m.get_connection():
            pass


async def test_get_connection_none_after_init(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    m._closed = False
    m._redis = None

    with pytest.raises(GuardRedisError):
        async with m.get_connection():
            pass


async def test_get_connection_success(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    m._redis = mock_redis
    m._closed = False

    async with m.get_connection() as conn:
        assert conn is mock_redis


async def test_safe_operation_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.safe_operation(AsyncMock())
    assert result is None


async def test_get_key_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.get_key("ns", "key")
    assert result is None


async def test_set_key_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.set_key("ns", "key", "val")
    assert result is None


async def test_set_key_with_ttl(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock(return_value=True)
    m._redis = mock_redis
    m._closed = False

    result = await m.set_key("ns", "key", "val", ttl=60)
    assert result is True


async def test_set_key_without_ttl(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock(return_value=True)
    m._redis = mock_redis
    m._closed = False

    result = await m.set_key("ns", "key", "val")
    assert result is True


async def test_incr_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.incr("ns", "key")
    assert result is None


async def test_incr_with_ttl(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_pipe = AsyncMock()
    mock_pipe.execute = AsyncMock(return_value=[5])
    mock_pipe.incr = AsyncMock()
    mock_pipe.expire = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_pipe)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_redis.pipeline = MagicMock(return_value=mock_ctx)
    m._redis = mock_redis
    m._closed = False

    result = await m.incr("ns", "key", ttl=60)
    assert result == 5


async def test_exists_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.exists("ns", "key")
    assert result is None


async def test_exists_true(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.exists = AsyncMock(return_value=1)
    m._redis = mock_redis
    m._closed = False

    result = await m.exists("ns", "key")
    assert result is True


async def test_delete_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.delete("ns", "key")
    assert result is None


async def test_delete_success(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.delete = AsyncMock(return_value=1)
    m._redis = mock_redis
    m._closed = False

    result = await m.delete("ns", "key")
    assert result == 1


async def test_keys_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.keys("pattern:*")
    assert result is None


async def test_keys_success(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.keys = AsyncMock(return_value=["key1", "key2"])
    m._redis = mock_redis
    m._closed = False

    result = await m.keys("pattern:*")
    assert result == ["key1", "key2"]


async def test_delete_pattern_disabled(config_disabled: SecurityConfig) -> None:
    m = RedisManager(config_disabled)
    result = await m.delete_pattern("pattern:*")
    assert result is None


async def test_delete_pattern_no_keys(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.keys = AsyncMock(return_value=[])
    m._redis = mock_redis
    m._closed = False

    result = await m.delete_pattern("pattern:*")
    assert result == 0


async def test_delete_pattern_with_keys(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.keys = AsyncMock(return_value=["k1", "k2"])
    mock_redis.delete = AsyncMock(return_value=2)
    m._redis = mock_redis
    m._closed = False

    result = await m.delete_pattern("pattern:*")
    assert result == 2


async def test_get_connection_connection_error(config: SecurityConfig) -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError

    m = RedisManager(config)
    mock_redis = AsyncMock()
    m._redis = mock_redis
    m._closed = False

    with pytest.raises(GuardRedisError):
        async with m.get_connection() as _conn:
            raise RedisConnectionError("connection lost")


async def test_safe_operation_error(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    m._redis = mock_redis
    m._closed = False

    async def bad_func(conn: Any) -> None:
        raise RuntimeError("op failed")

    with pytest.raises(GuardRedisError):
        await m.safe_operation(bad_func)


async def test_get_key_success(config: SecurityConfig) -> None:
    m = RedisManager(config)
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="value")
    m._redis = mock_redis
    m._closed = False

    result = await m.get_key("ns", "key")
    assert result == "value"
