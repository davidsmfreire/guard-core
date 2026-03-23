import asyncio
import time

import pytest

from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager


@pytest.mark.asyncio
async def test_ip_ban_manager() -> None:
    ip = "192.168.1.1"

    assert not await ip_ban_manager.is_ip_banned(ip)

    await ip_ban_manager.ban_ip(ip, 1)
    assert await ip_ban_manager.is_ip_banned(ip)

    await asyncio.sleep(1.1)
    assert not await ip_ban_manager.is_ip_banned(ip)


@pytest.mark.asyncio
async def test_reset_ip_ban_manager() -> None:
    await ip_ban_manager.ban_ip("test_ip", 3600)
    await ip_ban_manager.reset()
    assert not await ip_ban_manager.is_ip_banned("test_ip")


@pytest.mark.asyncio
async def test_ban_ip_concurrent_access() -> None:
    ip = "192.168.1.100"
    await asyncio.gather(*[ip_ban_manager.ban_ip(ip, 1) for _ in range(10)])
    assert await ip_ban_manager.is_ip_banned(ip)


@pytest.mark.asyncio
async def test_unban_ip() -> None:
    ip = "192.168.1.200"
    await ip_ban_manager.ban_ip(ip, 3600)
    assert await ip_ban_manager.is_ip_banned(ip)

    await ip_ban_manager.unban_ip(ip)
    assert not await ip_ban_manager.is_ip_banned(ip)


@pytest.mark.asyncio
async def test_ban_expired_ip_check() -> None:
    ip = "192.168.1.50"
    await ip_ban_manager.ban_ip(ip, 3600)
    assert await ip_ban_manager.is_ip_banned(ip)

    ip_ban_manager.banned_ips[ip] = time.time() - 10
    assert not await ip_ban_manager.is_ip_banned(ip)


@pytest.mark.asyncio
async def test_singleton_behavior() -> None:
    m1 = IPBanManager()
    m2 = IPBanManager()
    assert m1 is m2


@pytest.mark.asyncio
async def test_initialize_redis() -> None:
    from unittest.mock import MagicMock

    mock_redis = MagicMock()
    await ip_ban_manager.initialize_redis(mock_redis)
    assert ip_ban_manager.redis_handler is mock_redis
    ip_ban_manager.redis_handler = None


@pytest.mark.asyncio
async def test_initialize_agent() -> None:
    from unittest.mock import MagicMock

    mock_agent = MagicMock()
    await ip_ban_manager.initialize_agent(mock_agent)
    assert ip_ban_manager.agent_handler is mock_agent
    ip_ban_manager.agent_handler = None


@pytest.mark.asyncio
async def test_ban_ip_with_agent() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    ip_ban_manager.agent_handler = AsyncMock()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await ip_ban_manager.ban_ip("10.0.0.1", 3600, "test_reason")
    ip_ban_manager.agent_handler.send_event.assert_called_once()
    ip_ban_manager.agent_handler = None


@pytest.mark.asyncio
async def test_send_ban_event_error() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    ip_ban_manager.agent_handler = AsyncMock()
    ip_ban_manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await ip_ban_manager._send_ban_event("10.0.0.1", 3600, "test")
    ip_ban_manager.agent_handler = None


@pytest.mark.asyncio
async def test_unban_ip_with_agent() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    ip_ban_manager.agent_handler = AsyncMock()
    await ip_ban_manager.ban_ip("10.0.0.2", 3600)
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await ip_ban_manager.unban_ip("10.0.0.2")
    ip_ban_manager.agent_handler.send_event.assert_called()
    ip_ban_manager.agent_handler = None


@pytest.mark.asyncio
async def test_send_unban_event_error() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    ip_ban_manager.agent_handler = AsyncMock()
    ip_ban_manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await ip_ban_manager._send_unban_event("10.0.0.1")
    ip_ban_manager.agent_handler = None


@pytest.mark.asyncio
async def test_is_ip_banned_with_redis() -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=str(time.time() + 3600))
    ip_ban_manager.redis_handler = mock_redis
    result = await ip_ban_manager.is_ip_banned("20.0.0.1")
    assert result is True
    ip_ban_manager.redis_handler = None


@pytest.mark.asyncio
async def test_is_ip_banned_expired_in_redis() -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=str(time.time() - 100))
    mock_redis.delete = AsyncMock()
    ip_ban_manager.redis_handler = mock_redis
    result = await ip_ban_manager.is_ip_banned("30.0.0.1")
    assert result is False
    mock_redis.delete.assert_called_once()
    ip_ban_manager.redis_handler = None


@pytest.mark.asyncio
async def test_reset_global_state() -> None:
    from guard_core.handlers.ipban_handler import reset_global_state

    await reset_global_state()


@pytest.mark.asyncio
async def test_ban_ip_with_redis() -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    ip_ban_manager.redis_handler = mock_redis
    await ip_ban_manager.ban_ip("40.0.0.1", 3600)
    mock_redis.set_key.assert_called_once()
    ip_ban_manager.redis_handler = None


@pytest.mark.asyncio
async def test_unban_ip_with_redis() -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.delete = AsyncMock()
    ip_ban_manager.redis_handler = mock_redis
    ip_ban_manager.banned_ips["50.0.0.1"] = time.time() + 3600
    await ip_ban_manager.unban_ip("50.0.0.1")
    mock_redis.delete.assert_called_once()
    ip_ban_manager.redis_handler = None


@pytest.mark.asyncio
async def test_reset_with_redis() -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(return_value=["key1", "key2"])
    mock_conn.delete = AsyncMock()
    mock_redis.get_connection = lambda: type(
        "ctx",
        (),
        {
            "__aenter__": AsyncMock(return_value=mock_conn),
            "__aexit__": AsyncMock(return_value=None),
        },
    )()
    mock_redis.config = type("cfg", (), {"redis_prefix": "guard:"})()
    ip_ban_manager.redis_handler = mock_redis
    await ip_ban_manager.ban_ip("60.0.0.1", 3600)
    await ip_ban_manager.reset()
    mock_conn.delete.assert_called_once()
    ip_ban_manager.redis_handler = None
