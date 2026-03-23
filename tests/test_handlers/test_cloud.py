import ipaddress
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from guard_core.handlers.cloud_handler import (
    CloudManager,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_gcp_ip_ranges,
)


@pytest.fixture(autouse=True)
def reset_cloud_handler() -> Generator[None, None, None]:
    CloudManager._instance = None
    yield
    CloudManager._instance = None


@pytest.fixture
def cloud_handler() -> CloudManager:
    return CloudManager()


@pytest.fixture
def mock_requests_get() -> Generator[Mock, None, None]:
    with patch("guard_core.handlers.cloud_handler.requests.get") as mock_get:
        yield mock_get


def test_fetch_aws_ip_ranges(mock_requests_get: Mock) -> None:
    mock_response = Mock()
    mock_response.json.return_value = {
        "prefixes": [
            {"ip_prefix": "192.168.0.0/24", "service": "AMAZON"},
            {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
        ]
    }
    mock_response.raise_for_status = Mock()
    mock_requests_get.return_value = mock_response

    result = fetch_aws_ip_ranges()
    assert ipaddress.IPv4Network("192.168.0.0/24") in result
    assert ipaddress.IPv4Network("10.0.0.0/8") not in result


def test_fetch_gcp_ip_ranges(mock_requests_get: Mock) -> None:
    mock_response = Mock()
    mock_response.json.return_value = {
        "prefixes": [{"ipv4Prefix": "172.16.0.0/12"}, {"ipv6Prefix": "2001:db8::/32"}]
    }
    mock_response.raise_for_status = Mock()
    mock_requests_get.return_value = mock_response

    result = fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_fetch_azure_ip_ranges(mock_requests_get: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.text = """
    Some HTML content
    manually <a href="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json">
    More HTML content
    """
    mock_html_response.raise_for_status = Mock()
    mock_json_response = Mock()
    mock_json_response.json.return_value = {
        "values": [
            {"properties": {"addressPrefixes": ["192.168.1.0/24", "2001:db8::/32"]}}
        ]
    }
    mock_json_response.raise_for_status = Mock()
    mock_requests_get.side_effect = [mock_html_response, mock_json_response]

    result = fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_cloud_ip_ranges(cloud_handler: CloudManager) -> None:
    with (
        patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("guard_core.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})
        assert not cloud_handler.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})


def test_cloud_ip_ranges_error_handling(cloud_handler: CloudManager) -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            side_effect=Exception("AWS error"),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            side_effect=Exception("GCP error"),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            side_effect=Exception("Azure error"),
        ),
    ):
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert not cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})


def test_cloud_ip_ranges_invalid_ip(cloud_handler: CloudManager) -> None:
    assert not cloud_handler.is_cloud_ip("invalid_ip", {"AWS", "GCP", "Azure"})


def test_fetch_aws_ip_ranges_error(mock_requests_get: Mock) -> None:
    mock_requests_get.side_effect = Exception("API failure")
    result = fetch_aws_ip_ranges()
    assert result == set()


def test_fetch_gcp_ip_ranges_error(mock_requests_get: Mock) -> None:
    mock_response = Mock()
    mock_response.json.side_effect = Exception("Invalid JSON")
    mock_requests_get.return_value = mock_response
    result = fetch_gcp_ip_ranges()
    assert result == set()


def test_is_cloud_ip_ipv6(cloud_handler: CloudManager) -> None:
    assert not cloud_handler.is_cloud_ip("2001:db8::1", {"AWS"})


def test_fetch_azure_ip_ranges_url_not_found(mock_requests_get: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.text = "HTML without download link"
    mock_html_response.raise_for_status = Mock()
    mock_requests_get.return_value = mock_html_response

    result = fetch_azure_ip_ranges()
    assert result == set()


def test_fetch_azure_ip_ranges_download_failure(mock_requests_get: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.text = '<a href="https://download.microsoft.com/valid.json">'
    mock_html_response.raise_for_status = Mock()
    mock_download_response = Mock()
    mock_download_response.raise_for_status.side_effect = Exception("Download failed")

    mock_requests_get.side_effect = [mock_html_response, mock_download_response]

    result = fetch_azure_ip_ranges()
    assert result == set()


def test_get_cloud_provider_details(cloud_handler: CloudManager) -> None:
    with (
        patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("guard_core.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()

        result = cloud_handler.get_cloud_provider_details("192.168.0.1", {"AWS"})
        assert result is not None
        assert result[0] == "AWS"

        result = cloud_handler.get_cloud_provider_details("8.8.8.8", {"AWS"})
        assert result is None


def test_get_cloud_provider_details_invalid_ip(cloud_handler: CloudManager) -> None:
    result = cloud_handler.get_cloud_provider_details("invalid_ip", {"AWS"})
    assert result is None


@pytest.mark.asyncio
async def test_send_cloud_detection_event_no_agent(cloud_handler: CloudManager) -> None:
    await cloud_handler.send_cloud_detection_event("1.2.3.4", "AWS", "192.168.0.0/24")


@pytest.mark.asyncio
async def test_send_cloud_detection_event_with_agent(
    cloud_handler: CloudManager,
) -> None:

    cloud_handler.agent_handler = AsyncMock()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await cloud_handler.send_cloud_detection_event(
            "1.2.3.4", "AWS", "192.168.0.0/24"
        )
    cloud_handler.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_cloud_event_no_agent(cloud_handler: CloudManager) -> None:
    await cloud_handler._send_cloud_event("test", "1.2.3.4", "blocked", "reason")


@pytest.mark.asyncio
async def test_send_cloud_event_error(cloud_handler: CloudManager) -> None:

    cloud_handler.agent_handler = AsyncMock()
    cloud_handler.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await cloud_handler._send_cloud_event("test", "1.2.3.4", "blocked", "reason")


@pytest.mark.asyncio
async def test_initialize_agent(cloud_handler: CloudManager) -> None:

    agent = AsyncMock()
    await cloud_handler.initialize_agent(agent)
    assert cloud_handler.agent_handler is agent


@pytest.mark.asyncio
async def test_refresh_async_with_redis(cloud_handler: CloudManager) -> None:

    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)
    mock_redis.set_key = AsyncMock()
    cloud_handler.redis_handler = mock_redis

    with (
        patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("guard_core.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        await cloud_handler.refresh_async()

    assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
    mock_redis.set_key.assert_called()


@pytest.mark.asyncio
async def test_refresh_async_cached(cloud_handler: CloudManager) -> None:

    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value="192.168.0.0/24")
    cloud_handler.redis_handler = mock_redis

    await cloud_handler.refresh_async({"AWS"})
    assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})


@pytest.mark.asyncio
async def test_refresh_async_error(cloud_handler: CloudManager) -> None:

    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(side_effect=Exception("redis error"))
    cloud_handler.redis_handler = mock_redis

    await cloud_handler.refresh_async({"AWS"})


def test_refresh_raises_with_redis(cloud_handler: CloudManager) -> None:
    from unittest.mock import MagicMock as MM

    cloud_handler.redis_handler = MM()
    with pytest.raises(RuntimeError, match="Use async"):
        cloud_handler.refresh()


@pytest.mark.asyncio
async def test_cloud_ip_refresh(cloud_handler: CloudManager) -> None:
    with (
        patch("guard_core.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("guard_core.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_handler.refresh()

        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})


def test_refresh_sync_exception(cloud_handler: CloudManager) -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            side_effect=Exception("fail"),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            side_effect=Exception("fail"),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            side_effect=Exception("fail"),
        ),
    ):
        cloud_handler._refresh_sync()
    assert cloud_handler.ip_ranges.get("AWS") == set()


@pytest.mark.asyncio
async def test_initialize_redis_calls_refresh_async(
    cloud_handler: CloudManager,
) -> None:
    mock_redis = AsyncMock()
    with patch.object(
        cloud_handler, "refresh_async", new_callable=AsyncMock
    ) as mock_refresh:
        await cloud_handler.initialize_redis(mock_redis)
    assert cloud_handler.redis_handler is mock_redis
    mock_refresh.assert_called_once()


@pytest.mark.asyncio
async def test_refresh_async_no_redis(cloud_handler: CloudManager) -> None:
    cloud_handler.redis_handler = None
    with patch.object(cloud_handler, "_refresh_sync") as mock_sync:
        await cloud_handler.refresh_async()
    mock_sync.assert_called_once()


@pytest.mark.asyncio
async def test_refresh_async_error_new_provider(
    cloud_handler: CloudManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(side_effect=Exception("fail"))
    cloud_handler.redis_handler = mock_redis
    cloud_handler.ip_ranges.pop("AWS", None)

    await cloud_handler.refresh_async({"AWS"})
    assert "AWS" in cloud_handler.ip_ranges
    assert cloud_handler.ip_ranges["AWS"] == set()
