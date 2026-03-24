import time
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager


@pytest.fixture(autouse=True)
def reset_ipinfo_singleton() -> Generator:
    IPInfoManager._instance = None
    yield
    if IPInfoManager._instance:
        IPInfoManager._instance.agent_handler = None
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
    IPInfoManager._instance = None


@pytest.mark.asyncio
async def test_ipinfo_db(tmp_path: Path) -> None:
    db = IPInfoManager(token="test_token", db_path=tmp_path / "test.mmdb")

    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.content = b"test data"

    with (
        patch("httpx.AsyncClient.get", return_value=mock_response),
        patch("maxminddb.open_database"),
        patch("builtins.open", Mock()),
        patch("os.makedirs"),
    ):
        await db.initialize()

        db.reader = Mock()
        db.reader.get.return_value = {"country": "US"}
        assert db.get_country("1.1.1.1") == "US"


def test_ipinfo_missing_token() -> None:
    with pytest.raises(ValueError):
        IPInfoManager(token="")


@pytest.mark.asyncio
async def test_get_country_exception_handling(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")

    assert db.get_country("1.1.1.1") is None


def test_db_age_check(tmp_path: Path) -> None:
    db_path = tmp_path / "test.mmdb"
    db = IPInfoManager(token="test", db_path=db_path)

    db_path.touch()
    import os

    os.utime(db_path, (time.time() - 86401, time.time() - 86401))
    assert db._is_db_outdated() is True

    os.utime(db_path, (time.time() - 100, time.time() - 100))
    assert db._is_db_outdated() is False


def test_db_age_check_missing_db(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "missing.mmdb")
    with patch("pathlib.Path.exists", return_value=False):
        assert db._is_db_outdated() is True


@pytest.mark.asyncio
async def test_get_country_without_init(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    with pytest.raises(RuntimeError, match="Database not initialized"):
        db.get_country("1.1.1.1")


@pytest.mark.asyncio
async def test_close_with_reader(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_reader = Mock()
    db.reader = mock_reader

    db.close()
    mock_reader.close.assert_called_once()


def test_ipinfo_not_initialized() -> None:
    db = IPInfoManager(token="test")
    assert db.is_initialized is False


@pytest.mark.asyncio
async def test_get_country_result_without_country(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()

    db.reader.get.return_value = {"some_other_field": "value"}
    assert db.get_country("1.1.1.1") is None

    db.reader.get.return_value = None
    assert db.get_country("1.1.1.1") is None


@pytest.mark.asyncio
async def test_redis_initialization_flow(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_redis = AsyncMock()

    with patch.object(db, "initialize", new_callable=AsyncMock) as mock_init:
        await db.initialize_redis(mock_redis)

        assert db.redis_handler is mock_redis
        mock_init.assert_awaited_once()


@pytest.mark.asyncio
async def test_database_retry_success(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.content = b"test data"

    call_count = 0

    async def side_effect_function(*args: Any, **kwargs: Any) -> Mock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("First fail")
        return mock_response

    mock_file = Mock()
    mock_file_context = Mock()
    mock_file_context.__enter__ = Mock(return_value=mock_file)
    mock_file_context.__exit__ = Mock(return_value=None)
    mock_open = Mock(return_value=mock_file_context)

    with (
        patch("httpx.AsyncClient.get", side_effect=side_effect_function),
        patch("builtins.open", mock_open),
        patch("os.makedirs"),
        patch("asyncio.sleep") as mock_sleep,
    ):
        await db._download_database()

        assert call_count == 2
        mock_file.write.assert_called_with(b"test data")
        mock_sleep.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_check_country_access_allowed(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = {"country": "US"}

    allowed, country = await db.check_country_access("1.1.1.1", ["CN"], None)
    assert allowed is True
    assert country == "US"


@pytest.mark.asyncio
async def test_check_country_access_blocked(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = {"country": "CN"}

    allowed, country = await db.check_country_access("1.1.1.1", ["CN"], None)
    assert allowed is False
    assert country == "CN"


@pytest.mark.asyncio
async def test_check_country_access_whitelist_allowed(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = {"country": "US"}

    allowed, country = await db.check_country_access("1.1.1.1", [], ["US"])
    assert allowed is True
    assert country == "US"


@pytest.mark.asyncio
async def test_check_country_access_whitelist_blocked(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = {"country": "CN"}

    allowed, country = await db.check_country_access("1.1.1.1", [], ["US"])
    assert allowed is False
    assert country == "CN"


@pytest.mark.asyncio
async def test_check_country_access_no_country(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = None

    allowed, country = await db.check_country_access("1.1.1.1", ["CN"], None)
    assert allowed is True
    assert country is None


@pytest.mark.asyncio
async def test_check_country_access_no_country_with_whitelist(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = None

    allowed, country = await db.check_country_access("1.1.1.1", [], ["US"])
    assert allowed is False
    assert country is None


@pytest.mark.asyncio
async def test_send_geo_event_no_agent(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    await db._send_geo_event("test", "1.1.1.1", "action", "reason")


@pytest.mark.asyncio
async def test_send_geo_event_with_agent(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.agent_handler = AsyncMock()
    with patch.dict("sys.modules", {"guard_agent": Mock()}):
        mock_event_cls = Mock()
        with patch(
            "guard_core.handlers.ipinfo_handler.SecurityEvent",
            mock_event_cls,
            create=True,
        ):
            await db._send_geo_event("test", "1.1.1.1", "action", "reason")
    db.agent_handler = None


@pytest.mark.asyncio
async def test_send_geo_event_error(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.agent_handler = AsyncMock()
    db.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": Mock()}):
        await db._send_geo_event("test", "1.1.1.1", "action", "reason")
    db.agent_handler = None


@pytest.mark.asyncio
async def test_initialize_agent(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    agent = AsyncMock()
    await db.initialize_agent(agent)
    assert db.agent_handler is agent


@pytest.mark.asyncio
async def test_get_country_exception_with_agent(tmp_path: Path) -> None:
    import asyncio

    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")
    db.agent_handler = AsyncMock()
    result = db.get_country("1.1.1.1")
    assert result is None
    await asyncio.sleep(0)
    db.agent_handler = None


@pytest.mark.asyncio
async def test_initialize_download_failure(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    with (
        patch.object(
            db,
            "_download_database",
            new_callable=AsyncMock,
            side_effect=Exception("fail"),
        ),
        patch("os.makedirs"),
    ):
        await db.initialize()
    assert db.reader is None


@pytest.mark.asyncio
async def test_initialize_with_redis_cached(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value="fake_db_data")
    db.redis_handler = mock_redis

    mock_file = Mock()
    mock_file_ctx = Mock()
    mock_file_ctx.__enter__ = Mock(return_value=mock_file)
    mock_file_ctx.__exit__ = Mock(return_value=None)

    with (
        patch("os.makedirs"),
        patch("builtins.open", return_value=mock_file_ctx),
        patch("maxminddb.open_database") as mock_open_db,
    ):
        mock_open_db.return_value = Mock()
        await db.initialize()
    assert db.reader is not None


@pytest.mark.asyncio
async def test_initialize_download_failure_with_agent(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.agent_handler = AsyncMock()

    with (
        patch.object(db, "_is_db_outdated", return_value=True),
        patch.object(
            db,
            "_download_database",
            new_callable=AsyncMock,
            side_effect=Exception("fail"),
        ),
        patch.object(db, "_send_geo_event", new_callable=AsyncMock) as mock_geo_event,
        patch("os.makedirs"),
    ):
        await db.initialize()
    mock_geo_event.assert_called_once()


@pytest.mark.asyncio
async def test_download_database_with_redis(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    db.redis_handler = mock_redis

    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.content = b"test db data"

    with (
        patch("httpx.AsyncClient.get", return_value=mock_response),
    ):
        db_path_parent = tmp_path
        db_path_parent.mkdir(exist_ok=True)
        await db._download_database()

    mock_redis.set_key.assert_called_once()


@pytest.mark.asyncio
async def test_check_country_access_with_agent_events(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = {"country": "CN"}
    db.agent_handler = AsyncMock()

    with patch.object(db, "_send_geo_event", new_callable=AsyncMock) as mock_geo:
        allowed, country = await db.check_country_access("1.1.1.1", ["CN"], None)
    assert allowed is False
    mock_geo.assert_called_once()


@pytest.mark.asyncio
async def test_download_exhausts_retries(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    with (
        patch("httpx.AsyncClient.get", side_effect=Exception("Download failed")),
        patch("asyncio.sleep"),
    ):
        with pytest.raises(Exception, match="Download failed"):
            await db._download_database()


@pytest.mark.asyncio
async def test_initialize_download_failure_unlinks_existing_db(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "test.mmdb"
    db_path.touch()
    db = IPInfoManager(token="test", db_path=db_path)

    with (
        patch.object(db, "_is_db_outdated", return_value=True),
        patch.object(
            db,
            "_download_database",
            new_callable=AsyncMock,
            side_effect=Exception("fail"),
        ),
        patch("os.makedirs"),
    ):
        await db.initialize()
    assert not db_path.exists()
    assert db.reader is None


@pytest.mark.asyncio
async def test_initialize_opens_database_after_download(tmp_path: Path) -> None:
    db_path = tmp_path / "test.mmdb"
    db = IPInfoManager(token="test", db_path=db_path)

    async def fake_download() -> None:
        db_path.write_bytes(b"fake_db")

    with (
        patch.object(db, "_download_database", side_effect=fake_download),
        patch("maxminddb.open_database") as mock_open_db,
        patch("os.makedirs"),
    ):
        mock_open_db.return_value = Mock()
        await db.initialize()
    assert db.reader is not None
    mock_open_db.assert_called_once()


@pytest.mark.asyncio
async def test_get_country_exception_with_agent_task_failure(
    tmp_path: Path,
) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")
    db.agent_handler = AsyncMock()

    with patch.object(db, "_send_geo_event", return_value=None):
        with patch("asyncio.create_task", side_effect=RuntimeError("no loop")):
            result = db.get_country("1.1.1.1")
    assert result is None
    db.agent_handler = None
