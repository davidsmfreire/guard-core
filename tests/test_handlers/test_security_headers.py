import pytest

from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
)


@pytest.mark.asyncio
async def test_security_headers_manager_singleton() -> None:
    manager1 = SecurityHeadersManager()
    manager2 = SecurityHeadersManager()

    assert manager1 is manager2


@pytest.mark.asyncio
async def test_headers_caching() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"]},
    )

    headers1 = await manager.get_headers("/test")
    assert "Content-Security-Policy" in headers1

    headers2 = await manager.get_headers("/test")
    assert headers1 == headers2

    headers3 = await manager.get_headers("/different")
    assert "Content-Security-Policy" in headers3


@pytest.mark.asyncio
async def test_new_default_security_headers() -> None:
    manager = SecurityHeadersManager()

    headers = await manager.get_headers()

    assert "X-Permitted-Cross-Domain-Policies" in headers
    assert headers["X-Permitted-Cross-Domain-Policies"] == "none"

    assert "X-Download-Options" in headers
    assert headers["X-Download-Options"] == "noopen"

    assert "Cross-Origin-Embedder-Policy" in headers
    assert headers["Cross-Origin-Embedder-Policy"] == "require-corp"

    assert "Cross-Origin-Opener-Policy" in headers
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"

    assert "Cross-Origin-Resource-Policy" in headers
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"


@pytest.mark.asyncio
async def test_original_headers_still_present() -> None:
    manager = SecurityHeadersManager()

    headers = await manager.get_headers()

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"


@pytest.mark.asyncio
async def test_disabled_headers() -> None:
    manager = SecurityHeadersManager()
    manager.configure(enabled=False)

    headers = await manager.get_headers()
    assert headers == {}


@pytest.mark.asyncio
async def test_custom_headers() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        custom_headers={
            "X-Custom-Header": "custom-value",
            "X-Another-Header": "another-value",
        },
    )

    headers = await manager.get_headers()

    assert headers["X-Custom-Header"] == "custom-value"
    assert headers["X-Another-Header"] == "another-value"


@pytest.mark.asyncio
async def test_csp_header() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://trusted.cdn.com"],
        },
    )

    headers = await manager.get_headers()

    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self' https://trusted.cdn.com" in csp


@pytest.mark.asyncio
async def test_hsts_header() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        hsts_preload=True,
    )

    headers = await manager.get_headers()

    hsts = headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts


@pytest.mark.asyncio
async def test_frame_options_deny() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        frame_options="DENY",
    )

    headers = await manager.get_headers()

    assert headers["X-Frame-Options"] == "DENY"


@pytest.mark.asyncio
async def test_custom_referrer_policy() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        referrer_policy="no-referrer",
    )

    headers = await manager.get_headers()

    assert headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.asyncio
async def test_permissions_policy_disabled() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        permissions_policy=None,
    )

    headers = await manager.get_headers()

    assert "Permissions-Policy" not in headers


@pytest.mark.asyncio
async def test_validate_csp_report() -> None:
    manager = SecurityHeadersManager()

    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "https://evil.com/malicious.js",
        }
    }
    result = await manager.validate_csp_report(valid_report)
    assert result is True

    invalid_report = {"csp-report": {"document-uri": "https://example.com"}}
    result = await manager.validate_csp_report(invalid_report)
    assert result is False


@pytest.mark.asyncio
async def test_cors_headers() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        cors_origins=["https://example.com"],
        cors_allow_credentials=True,
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
    )

    cors_headers = await manager.get_cors_headers("https://example.com")
    assert cors_headers["Access-Control-Allow-Origin"] == "https://example.com"

    cors_headers = await manager.get_cors_headers("https://evil.com")
    assert cors_headers == {}


@pytest.mark.asyncio
async def test_header_validation() -> None:
    manager = SecurityHeadersManager()

    with pytest.raises(ValueError):
        manager._validate_header_value("header\r\nInjection")

    with pytest.raises(ValueError):
        manager._validate_header_value("x" * 9000)


@pytest.mark.asyncio
async def test_reset() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"]},
        custom_headers={"X-Test": "test"},
    )

    await manager.reset()

    assert manager.csp_config is None
    assert manager.custom_headers == {}
    assert manager.enabled is True


@pytest.mark.asyncio
async def test_reset_global_state() -> None:
    from guard_core.handlers.security_headers_handler import reset_global_state

    await reset_global_state()


@pytest.mark.asyncio
async def test_initialize_redis() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)
    mock_redis.set_key = AsyncMock()
    await manager.initialize_redis(mock_redis)
    assert manager.redis_handler is mock_redis


@pytest.mark.asyncio
async def test_initialize_agent() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    agent = AsyncMock()
    await manager.initialize_agent(agent)
    assert manager.agent_handler is agent


@pytest.mark.asyncio
async def test_hsts_preload_insufficient_max_age() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        hsts_max_age=1000,
        hsts_include_subdomains=False,
        hsts_preload=True,
    )
    headers = await manager.get_headers()
    hsts = headers.get("Strict-Transport-Security", "")
    assert "includeSubDomains" in hsts


@pytest.mark.asyncio
async def test_cors_wildcard_with_credentials() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        cors_origins=["*"],
        cors_allow_credentials=True,
    )
    assert manager.cors_config["allow_credentials"] is False


@pytest.mark.asyncio
async def test_cors_wildcard_origin() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        cors_origins=["*"],
        cors_allow_credentials=False,
    )
    cors = await manager.get_cors_headers("https://anything.com")
    assert "Access-Control-Allow-Origin" in cors


@pytest.mark.asyncio
async def test_cache_key_generation() -> None:
    manager = SecurityHeadersManager()
    key1 = manager._generate_cache_key("/api/test")
    key2 = manager._generate_cache_key("/api/test")
    key3 = manager._generate_cache_key(None)
    assert key1 == key2
    assert key3 == "default"


@pytest.mark.asyncio
async def test_csp_unsafe_warning() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"script-src": ["'unsafe-inline'"]},
    )
    headers = await manager.get_headers()
    assert "Content-Security-Policy" in headers


@pytest.mark.asyncio
async def test_load_cached_config() -> None:
    import json
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(
        side_effect=lambda ns, key: {
            "csp_config": json.dumps({"default-src": ["'self'"]}),
            "hsts_config": json.dumps({"max_age": 31536000}),
            "custom_headers": json.dumps({"X-Custom": "val"}),
        }.get(key)
    )
    mock_redis.set_key = AsyncMock()
    manager.redis_handler = mock_redis
    await manager._load_cached_config()
    assert manager.csp_config == {"default-src": ["'self'"]}
    assert manager.hsts_config == {"max_age": 31536000}
    assert manager.custom_headers == {"X-Custom": "val"}


@pytest.mark.asyncio
async def test_load_cached_config_error() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(side_effect=Exception("fail"))
    manager.redis_handler = mock_redis
    await manager._load_cached_config()


@pytest.mark.asyncio
async def test_cache_configuration() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    manager.csp_config = {"default-src": ["'self'"]}
    manager.hsts_config = {"max_age": 31536000}
    manager.custom_headers = {"X-Test": "val"}
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    manager.redis_handler = mock_redis
    await manager._cache_configuration()
    assert mock_redis.set_key.call_count == 3


@pytest.mark.asyncio
async def test_get_headers_builds_csp() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"], "img-src": ["*"]},
    )
    headers = await manager.get_headers()
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "img-src *" in csp


@pytest.mark.asyncio
async def test_get_headers_builds_hsts() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        hsts_max_age=86400,
    )
    headers = await manager.get_headers()
    assert "Strict-Transport-Security" in headers


@pytest.mark.asyncio
async def test_cors_headers_no_config() -> None:
    manager = SecurityHeadersManager()
    cors = await manager.get_cors_headers("https://example.com")
    assert cors == {}


@pytest.mark.asyncio
async def test_get_cors_headers_not_allowed() -> None:
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        cors_origins=["https://trusted.com"],
    )
    cors = await manager.get_cors_headers("https://evil.com")
    assert cors == {}


@pytest.mark.asyncio
async def test_validate_csp_report_missing_report() -> None:
    manager = SecurityHeadersManager()
    result = await manager.validate_csp_report({})
    assert result is False


@pytest.mark.asyncio
async def test_reset_with_redis() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(return_value=["key1"])
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
    manager.redis_handler = mock_redis
    await manager.reset()


@pytest.mark.asyncio
async def test_get_headers_with_agent() -> None:
    from unittest.mock import AsyncMock, patch

    manager = SecurityHeadersManager()
    manager.agent_handler = AsyncMock()
    manager.headers_cache.clear()

    with patch.object(manager, "_send_headers_applied_event", new_callable=AsyncMock):
        await manager.get_headers("/api/test")
        manager._send_headers_applied_event.assert_called_once()
    manager.agent_handler = None


@pytest.mark.asyncio
async def test_load_cached_config_no_redis() -> None:
    manager = SecurityHeadersManager()
    manager.redis_handler = None
    await manager._load_cached_config()


@pytest.mark.asyncio
async def test_update_default_headers_content_type() -> None:
    manager = SecurityHeadersManager()
    manager.configure(enabled=True, content_type_options="nosniff-custom")
    headers = await manager.get_headers()
    assert headers["X-Content-Type-Options"] == "nosniff-custom"


@pytest.mark.asyncio
async def test_update_default_headers_xss_protection() -> None:
    manager = SecurityHeadersManager()
    manager.configure(enabled=True, xss_protection="0")
    headers = await manager.get_headers()
    assert headers["X-XSS-Protection"] == "0"


@pytest.mark.asyncio
async def test_update_default_headers_permissions_policy_custom() -> None:
    manager = SecurityHeadersManager()
    manager.configure(enabled=True, permissions_policy="camera=()")
    headers = await manager.get_headers()
    assert headers["Permissions-Policy"] == "camera=()"


@pytest.mark.asyncio
async def test_cache_configuration_no_redis() -> None:
    manager = SecurityHeadersManager()
    manager.redis_handler = None
    manager.csp_config = {"default-src": ["'self'"]}
    await manager._cache_configuration()


@pytest.mark.asyncio
async def test_cache_configuration_error() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock(side_effect=Exception("cache fail"))
    manager.redis_handler = mock_redis
    manager.csp_config = {"default-src": ["'self'"]}
    await manager._cache_configuration()


@pytest.mark.asyncio
async def test_build_csp_empty_sources() -> None:
    manager = SecurityHeadersManager()
    result = manager._build_csp({"upgrade-insecure-requests": []})
    assert "upgrade-insecure-requests" in result


@pytest.mark.asyncio
async def test_cors_wildcard_credentials_check() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = {"origins": ["*"], "allow_credentials": True}
    result = manager._is_wildcard_with_credentials(["*"])
    assert result is True


@pytest.mark.asyncio
async def test_get_validated_cors_config_no_config() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = None
    methods, headers = manager._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]


@pytest.mark.asyncio
async def test_get_validated_cors_config_non_list_types() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "allow_methods": "not_a_list",
        "allow_headers": "not_a_list",
    }
    methods, headers = manager._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]


@pytest.mark.asyncio
async def test_get_cors_headers_non_list_origins() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = {"origins": "not_a_list"}
    result = await manager.get_cors_headers("https://example.com")
    assert result == {}


@pytest.mark.asyncio
async def test_get_cors_headers_wildcard_with_credentials() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
    }
    result = await manager.get_cors_headers("https://example.com")
    assert result == {}


@pytest.mark.asyncio
async def test_send_headers_applied_event() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    manager = SecurityHeadersManager()
    manager.agent_handler = AsyncMock()

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_headers_applied_event("/test", {"X-Test": "val"})
    manager.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_headers_applied_event_error() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    manager = SecurityHeadersManager()
    manager.agent_handler = AsyncMock()
    manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_headers_applied_event("/test", {"X-Test": "val"})


@pytest.mark.asyncio
async def test_validate_csp_report_with_agent() -> None:
    from unittest.mock import AsyncMock, patch

    manager = SecurityHeadersManager()
    manager.agent_handler = AsyncMock()

    with patch.object(
        manager, "_send_csp_violation_event", new_callable=AsyncMock
    ) as mock_send:
        result = await manager.validate_csp_report(
            {
                "csp-report": {
                    "document-uri": "https://example.com",
                    "violated-directive": "script-src",
                    "blocked-uri": "https://evil.com",
                }
            }
        )
    assert result is True
    mock_send.assert_called_once()


@pytest.mark.asyncio
async def test_send_csp_violation_event() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    manager = SecurityHeadersManager()
    manager.agent_handler = AsyncMock()

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_csp_violation_event(
            {
                "document-uri": "https://example.com",
                "violated-directive": "script-src",
                "blocked-uri": "https://evil.com",
            }
        )
    manager.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_csp_violation_event_error() -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    manager = SecurityHeadersManager()
    manager.agent_handler = AsyncMock()
    manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_csp_violation_event({"document-uri": "x"})


@pytest.mark.asyncio
async def test_reset_with_redis_error() -> None:
    from unittest.mock import AsyncMock

    manager = SecurityHeadersManager()
    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(side_effect=Exception("redis error"))
    mock_redis.get_connection = lambda: type(
        "ctx",
        (),
        {
            "__aenter__": AsyncMock(return_value=mock_conn),
            "__aexit__": AsyncMock(return_value=None),
        },
    )()
    mock_redis.config = type("cfg", (), {"redis_prefix": "guard:"})()
    manager.redis_handler = mock_redis
    await manager.reset()
