import re
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
)


@pytest.fixture(autouse=True)
async def reset_sus_patterns() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    original_patterns = None
    original_custom_patterns: set[str] = set()
    if original_instance:
        original_patterns = original_instance.patterns.copy()
        original_custom_patterns = original_instance.custom_patterns.copy()

    yield

    if SusPatternsManager._instance:
        await SusPatternsManager._instance.reset()

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config

    if original_instance and original_patterns:
        original_instance.patterns = original_patterns
        original_instance.custom_patterns = original_custom_patterns


@pytest.fixture
def handler() -> SusPatternsManager:
    SusPatternsManager._instance = None
    return SusPatternsManager()


@pytest.mark.asyncio
async def test_add_pattern(handler: SusPatternsManager) -> None:
    pattern_to_add = r"new_pattern"
    await handler.add_pattern(pattern_to_add, custom=True)
    assert pattern_to_add in handler.custom_patterns


@pytest.mark.asyncio
async def test_remove_pattern(handler: SusPatternsManager) -> None:
    pattern_to_remove = r"new_pattern"
    await handler.add_pattern(pattern_to_remove, custom=True)
    result = await handler.remove_pattern(pattern_to_remove, custom=True)
    assert result is True
    assert pattern_to_remove not in handler.custom_patterns


@pytest.mark.asyncio
async def test_get_all_patterns(handler: SusPatternsManager) -> None:
    default_patterns = handler.patterns
    custom_pattern = r"custom_pattern"
    await handler.add_pattern(custom_pattern, custom=True)
    all_patterns = await handler.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_get_default_patterns(handler: SusPatternsManager) -> None:
    default_patterns = handler.patterns
    custom_pattern = r"custom_pattern_test"
    await handler.add_pattern(custom_pattern, custom=True)

    patterns = await handler.get_default_patterns()

    assert custom_pattern not in patterns
    assert all(pattern in patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_get_custom_patterns(handler: SusPatternsManager) -> None:
    custom_pattern = r"custom_pattern_only"
    await handler.add_pattern(custom_pattern, custom=True)

    patterns = await handler.get_custom_patterns()

    assert custom_pattern in patterns
    default_pattern = handler.patterns[0]
    assert default_pattern not in patterns


@pytest.mark.asyncio
async def test_invalid_pattern_handling(handler: SusPatternsManager) -> None:
    with pytest.raises(re.error):
        await handler.add_pattern(r"invalid(regex", custom=True)


@pytest.mark.asyncio
async def test_remove_nonexistent_pattern(handler: SusPatternsManager) -> None:
    result = await handler.remove_pattern("nonexistent", custom=True)
    assert result is False


def test_singleton_behavior() -> None:
    SusPatternsManager._instance = None
    instance1 = SusPatternsManager()
    instance2 = SusPatternsManager()
    assert instance1 is instance2
    assert instance1.compiled_patterns is instance2.compiled_patterns


@pytest.mark.asyncio
async def test_add_default_pattern(handler: SusPatternsManager) -> None:
    pattern_to_add = r"default_pattern"
    initial_length = len(handler.patterns)

    await handler.add_pattern(pattern_to_add, custom=False)

    assert len(handler.patterns) == initial_length + 1
    assert pattern_to_add in handler.patterns


@pytest.mark.asyncio
async def test_remove_default_pattern() -> None:
    SusPatternsManager._instance = None
    SusPatternsManager.patterns = [
        p[0] for p in SusPatternsManager._pattern_definitions
    ]
    manager = SusPatternsManager()

    pattern_to_remove = r"unique_default_pattern_for_removal_test"
    initial_len = len(manager.patterns)

    await manager.add_pattern(pattern_to_remove, custom=False)
    assert pattern_to_remove in manager.patterns
    assert len(manager.patterns) == initial_len + 1

    result = await manager.remove_pattern(pattern_to_remove, custom=False)

    assert result is True
    assert pattern_to_remove not in manager.patterns
    assert len(manager.patterns) == initial_len

    SusPatternsManager._instance = None
    SusPatternsManager.patterns = [
        p[0] for p in SusPatternsManager._pattern_definitions
    ]


@pytest.mark.asyncio
async def test_get_compiled_patterns_separation(
    handler: SusPatternsManager,
) -> None:
    default_pattern = r"default_test_pattern_\d+"
    custom_pattern = r"custom_test_pattern_\d+"

    await handler.add_pattern(default_pattern, custom=False)
    await handler.add_pattern(custom_pattern, custom=True)

    default_compiled = await handler.get_default_compiled_patterns()
    custom_compiled = await handler.get_custom_compiled_patterns()

    test_default_string = "default_test_pattern_123"
    default_matched = any(p.search(test_default_string) for p, _ctx in default_compiled)
    assert default_matched

    test_custom_string = "custom_test_pattern_456"
    custom_matched = any(p.search(test_custom_string) for p, _ctx in custom_compiled)
    assert custom_matched

    assert len(default_compiled) == len(handler.compiled_patterns)
    assert len(custom_compiled) == len(handler.compiled_custom_patterns)


@pytest.mark.asyncio
async def test_redis_disabled(handler: SusPatternsManager) -> None:
    await handler.initialize_redis(None)

    test_pattern = "test_pattern"
    await handler.add_pattern(test_pattern, custom=True)
    assert test_pattern in handler.custom_patterns

    result = await handler.remove_pattern(test_pattern, custom=True)
    assert result is True
    assert test_pattern not in handler.custom_patterns


@pytest.mark.asyncio
async def test_get_all_compiled_patterns(handler: SusPatternsManager) -> None:
    test_pattern = r"test_pattern\d+"
    await handler.add_pattern(test_pattern, custom=True)

    compiled_patterns = await handler.get_all_compiled_patterns()

    assert len(compiled_patterns) == len(handler.compiled_patterns) + len(
        handler.compiled_custom_patterns
    )

    test_string = "test_pattern123"
    matched = False
    for pattern, _ctx in compiled_patterns:
        if pattern.search(test_string):
            matched = True
            break
    assert matched


@pytest.mark.asyncio
async def test_init_with_config() -> None:
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8

    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    assert manager._compiler is not None
    assert manager._compiler.default_timeout == 3.0
    assert manager._preprocessor is not None
    assert manager._preprocessor.max_content_length == 20000
    assert manager._preprocessor.preserve_attack_patterns is True
    assert manager._semantic_analyzer is not None
    assert manager._performance_monitor is not None
    assert manager._performance_monitor.anomaly_threshold == 2.5
    assert manager._performance_monitor.slow_pattern_threshold == 0.2
    assert manager._semantic_threshold == 0.8

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_get_performance_stats_none() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_monitor = manager._performance_monitor
    manager._performance_monitor = None

    stats = await manager.get_performance_stats()

    assert stats is None

    manager._performance_monitor = original_monitor
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_get_component_status() -> None:
    original_instance = SusPatternsManager._instance

    try:
        SusPatternsManager._instance = None
        manager = SusPatternsManager()

        status = await manager.get_component_status()
        assert status["compiler"] is False
        assert status["preprocessor"] is False
        assert status["semantic_analyzer"] is False
        assert status["performance_monitor"] is False
    finally:
        SusPatternsManager._instance = original_instance


_SENSITIVE_FILE_PATTERNS = [
    r"(?:^|/)\.env(?:\.\w+)?(?:\?|$|/)",
    r"(?:^|/)[\w-]*config[\w-]*\."
    r"(?:env|yml|yaml|json|toml|ini|xml|conf)(?:\?|$)",
    r"(?:^|/)[\w./-]*\.map(?:\?|$)",
    r"(?:^|/)[\w./-]*\."
    r"(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:\?|$)",
    r"(?:^|/)\.(?:git|svn|hg|bzr)(?:/|$)",
    r"(?:^|/)(?:wp-(?:admin|login|content|includes|config)"
    r"|administrator|xmlrpc)\.?(?:php)?(?:/|$|\?)",
    r"(?:^|/)(?:phpinfo|info|test|php_info)\.php(?:\?|$)",
    r"(?:^|/)[\w./-]*\."
    r"(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:\?|$)",
    r"(?:^|/)(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
    r"|\.npmrc|\.dockerenv|web\.config)(?:\?|$)",
]

_COMPILED_SENSITIVE_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _SENSITIVE_FILE_PATTERNS
]


def _matches_sensitive_pattern(path: str) -> bool:
    return any(p.search(path) for p in _COMPILED_SENSITIVE_PATTERNS)


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/app/.env",
    ],
)
def test_sensitive_pattern_dotenv(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for dotenv path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/config.yml",
        "/config.yaml",
        "/config.json",
        "/config.toml",
        "/config.ini",
    ],
)
def test_sensitive_pattern_config_files(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for config path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
    ],
)
def test_sensitive_pattern_vcs_metadata(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for VCS path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/config",
        "/settings",
        "/health",
        "/api/v1/users",
        "/docs",
        "/redoc",
        "/openapi.json",
    ],
)
def test_sensitive_pattern_no_false_positives(path: str) -> None:
    assert not _matches_sensitive_pattern(path), (
        f"False positive: legitimate path matched: {path}"
    )


@pytest.mark.asyncio
async def test_detect_no_threat(handler: SusPatternsManager) -> None:
    result = await handler.detect(
        content="normal content",
        ip_address="1.2.3.4",
        context="test",
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
async def test_detect_regex_threat(handler: SusPatternsManager) -> None:
    result = await handler.detect(
        content="<script>alert(1)</script>",
        ip_address="1.2.3.4",
        context="request_body",
    )
    assert result["is_threat"] is True
    assert len(result["threats"]) > 0


@pytest.mark.asyncio
async def test_detect_pattern_match(handler: SusPatternsManager) -> None:
    is_threat, pattern = await handler.detect_pattern_match(
        content="SELECT * FROM users WHERE 1=1",
        ip_address="1.2.3.4",
        context="request_body",
    )
    assert is_threat is True


@pytest.mark.asyncio
async def test_detect_pattern_match_no_threat(handler: SusPatternsManager) -> None:
    is_threat, pattern = await handler.detect_pattern_match(
        content="normal safe content",
        ip_address="1.2.3.4",
    )
    assert is_threat is False
    assert pattern is None


@pytest.mark.asyncio
async def test_normalize_context() -> None:
    assert SusPatternsManager._normalize_context("query_param:name") == "query_param"
    assert SusPatternsManager._normalize_context("header:X-Custom") == "header"
    assert SusPatternsManager._normalize_context("weird_context") == "unknown"
    assert SusPatternsManager._normalize_context("url_path") == "url_path"


@pytest.mark.asyncio
async def test_calculate_threat_score(handler: SusPatternsManager) -> None:
    score = await handler._calculate_threat_score([], [])
    assert score == 0.0

    score = await handler._calculate_threat_score([{"type": "regex"}], [])
    assert score == 1.0

    score = await handler._calculate_threat_score([], [{"probability": 0.8}])
    assert score == 0.8


@pytest.mark.asyncio
async def test_check_semantic_threats_no_analyzer(handler: SusPatternsManager) -> None:
    handler._semantic_analyzer = None
    threats, score = await handler._check_semantic_threats("test content")
    assert threats == []
    assert score == 0.0


@pytest.mark.asyncio
async def test_send_pattern_event_no_agent(handler: SusPatternsManager) -> None:
    await handler._send_pattern_event("test", "1.2.3.4", "action", "reason")


@pytest.mark.asyncio
async def test_send_pattern_event_with_agent(handler: SusPatternsManager) -> None:
    from unittest.mock import AsyncMock, patch

    handler.agent_handler = AsyncMock()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await handler._send_pattern_event("test", "1.2.3.4", "action", "reason")
    handler.agent_handler.send_event.assert_called_once()
    handler.agent_handler = None


@pytest.mark.asyncio
async def test_send_pattern_event_error(handler: SusPatternsManager) -> None:
    from unittest.mock import AsyncMock, patch

    handler.agent_handler = AsyncMock()
    handler.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await handler._send_pattern_event("test", "1.2.3.4", "action", "reason")
    handler.agent_handler = None


@pytest.mark.asyncio
async def test_preprocess_content_no_preprocessor(handler: SusPatternsManager) -> None:
    handler._preprocessor = None
    result = await handler._preprocess_content("test", None)
    assert result == "test"


@pytest.mark.asyncio
async def test_check_regex_patterns_basic(handler: SusPatternsManager) -> None:
    threats, matched, timeouts = await handler._check_regex_patterns(
        "<script>alert(1)</script>", "1.2.3.4", None, "request_body"
    )
    assert len(threats) > 0


@pytest.mark.asyncio
async def test_detect_with_config() -> None:
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8

    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    result = await manager.detect(
        content="SELECT * FROM users WHERE 1=1",
        ip_address="1.2.3.4",
        context="request_body",
    )
    assert "is_threat" in result
    assert "threat_score" in result
    assert "execution_time" in result

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_detect_pattern_match_semantic(handler: SusPatternsManager) -> None:
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.01

    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    result = await manager.detect(
        content="<script>eval(alert(document.cookie))</script>",
        ip_address="1.2.3.4",
        context="request_body",
    )
    assert result["is_threat"] is True

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_check_pattern_with_timeout_timeout(handler: SusPatternsManager) -> None:
    import concurrent.futures
    import re

    pattern = re.compile(r"test")
    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_future.cancel = MagicMock()
        mock_executor.return_value.__enter__ = MagicMock(
            return_value=MagicMock(submit=MagicMock(return_value=mock_future))
        )
        mock_executor.return_value.__exit__ = MagicMock(return_value=False)

        match, timed_out = await handler._check_pattern_with_timeout(
            pattern, "content", "1.2.3.4", 0.0
        )
    assert match is None
    assert timed_out is True


@pytest.mark.asyncio
async def test_check_pattern_with_timeout_error(handler: SusPatternsManager) -> None:
    import re

    pattern = re.compile(r"test")
    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("unexpected error")
        mock_executor.return_value.__enter__ = MagicMock(
            return_value=MagicMock(submit=MagicMock(return_value=mock_future))
        )
        mock_executor.return_value.__exit__ = MagicMock(return_value=False)

        match, timed_out = await handler._check_pattern_with_timeout(
            pattern, "content", "1.2.3.4", 0.0
        )
    assert match is None
    assert timed_out is False


@pytest.mark.asyncio
async def test_initialize_redis_with_cached_patterns(
    handler: SusPatternsManager,
) -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value="pattern1,pattern2")
    mock_redis.set_key = AsyncMock()
    await handler.initialize_redis(mock_redis)
    assert "pattern1" in handler.custom_patterns
    assert "pattern2" in handler.custom_patterns


@pytest.mark.asyncio
async def test_detect_pattern_match_semantic_type() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    with patch.object(manager, "detect", new_callable=AsyncMock) as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [{"type": "semantic", "attack_type": "xss"}],
        }
        is_threat, pattern = await manager.detect_pattern_match("content", "1.2.3.4")
    assert is_threat is True
    assert pattern == "semantic:xss"
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_detect_pattern_match_unknown_type(handler: SusPatternsManager) -> None:
    with patch.object(handler, "detect", new_callable=AsyncMock) as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [{"type": "other"}],
        }
        is_threat, pattern = await handler.detect_pattern_match("content", "1.2.3.4")
    assert is_threat is True


@pytest.mark.asyncio
async def test_detect_pattern_match_no_threats_details(
    handler: SusPatternsManager,
) -> None:
    with patch.object(handler, "detect", new_callable=AsyncMock) as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [],
        }
        is_threat, pattern = await handler.detect_pattern_match("content", "1.2.3.4")
    assert is_threat is True
    assert pattern == "unknown"


@pytest.mark.asyncio
async def test_add_pattern_with_redis(handler: SusPatternsManager) -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    handler.redis_handler = mock_redis

    await handler.add_pattern("new_redis_pattern", custom=True)
    mock_redis.set_key.assert_called_once()
    handler.redis_handler = None


@pytest.mark.asyncio
async def test_add_pattern_clears_compiler_cache(handler: SusPatternsManager) -> None:
    from unittest.mock import AsyncMock

    handler._compiler = AsyncMock()
    handler._compiler.clear_cache = AsyncMock()

    await handler.add_pattern("compiler_test_pattern", custom=True)
    handler._compiler.clear_cache.assert_called_once()
    handler._compiler = None


@pytest.mark.asyncio
async def test_remove_pattern_clears_caches(handler: SusPatternsManager) -> None:
    from unittest.mock import AsyncMock

    original_compiler = handler._compiler
    original_monitor = handler._performance_monitor
    handler._compiler = AsyncMock()
    handler._compiler.clear_cache = AsyncMock()
    handler._performance_monitor = AsyncMock()
    handler._performance_monitor.remove_pattern_stats = AsyncMock()

    await handler.add_pattern("cache_test", custom=True)
    await handler.remove_pattern("cache_test", custom=True)

    handler._compiler.clear_cache.assert_called()
    handler._performance_monitor.remove_pattern_stats.assert_called()

    handler._compiler = original_compiler
    handler._performance_monitor = original_monitor


@pytest.mark.asyncio
async def test_remove_custom_pattern_with_redis(handler: SusPatternsManager) -> None:
    from unittest.mock import AsyncMock

    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    handler.redis_handler = mock_redis

    await handler.add_pattern("redis_remove_test", custom=True)
    result = await handler.remove_pattern("redis_remove_test", custom=True)
    assert result is True
    handler.redis_handler = None


@pytest.mark.asyncio
async def test_send_threat_event(handler: SusPatternsManager) -> None:
    with patch.object(
        handler, "_send_pattern_event", new_callable=AsyncMock
    ) as mock_send:
        await handler._send_threat_event(
            ["pattern1"],
            [],
            "1.2.3.4",
            "test",
            "content",
            0.9,
            [{"type": "regex"}],
            [{"type": "regex"}],
            [],
            0.01,
            None,
        )
    mock_send.assert_called_once()


@pytest.mark.asyncio
async def test_send_threat_event_semantic(handler: SusPatternsManager) -> None:
    with patch.object(
        handler, "_send_pattern_event", new_callable=AsyncMock
    ) as mock_send:
        await handler._send_threat_event(
            [],
            [{"attack_type": "xss"}],
            "1.2.3.4",
            "test",
            "content",
            0.9,
            [{"type": "semantic"}],
            [],
            [],
            0.01,
            None,
        )
    mock_send.assert_called_once()


@pytest.mark.asyncio
async def test_check_semantic_threats_with_analyzer() -> None:
    SusPatternsManager._instance = None
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.01

    manager = SusPatternsManager(config)
    threats, score = await manager._check_semantic_threats(
        "<script>eval(document.cookie)</script> UNION SELECT * FROM users"
    )
    assert isinstance(threats, list)
    assert isinstance(score, float)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_reset_clears_monitor() -> None:
    SusPatternsManager._instance = None
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8

    manager = SusPatternsManager(config)
    manager._performance_monitor.pattern_stats["test"] = MagicMock()
    manager._performance_monitor.recent_metrics.append(MagicMock())

    await SusPatternsManager.reset()

    assert len(manager._performance_monitor.pattern_stats) == 0
    assert len(manager._performance_monitor.recent_metrics) == 0

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_initialize_agent(handler: SusPatternsManager) -> None:
    mock_agent = AsyncMock()
    await handler.initialize_agent(mock_agent)
    assert handler.agent_handler is mock_agent
    handler.agent_handler = None


@pytest.mark.asyncio
async def test_check_regex_pattern_compiler_timeout(
    handler: SusPatternsManager,
) -> None:
    import time

    handler._compiler = MagicMock()
    handler._compiler.create_safe_matcher = MagicMock(return_value=lambda c: None)
    pattern = re.compile(r"test")

    old_time = time.time
    try:
        time.time = lambda: old_time() + 100
        threat, timed_out = await handler._check_regex_pattern(
            pattern, "content", "1.2.3.4", old_time() - 100
        )
    finally:
        time.time = old_time

    assert threat is None
    assert timed_out is True
    handler._compiler = None


@pytest.mark.asyncio
async def test_check_regex_patterns_context_filter(
    handler: SusPatternsManager,
) -> None:
    threats, matched, timeouts = await handler._check_regex_patterns(
        "normal safe content", "1.2.3.4", None, "query_param"
    )
    assert len(threats) == 0


@pytest.mark.asyncio
async def test_check_semantic_threats_suspicious_fallback() -> None:
    SusPatternsManager._instance = None
    handler = SusPatternsManager()
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {"attack_probabilities": {"xss": 0.01}}
    mock_analyzer.get_threat_score.return_value = 0.9
    handler._semantic_analyzer = mock_analyzer
    handler._semantic_threshold = 0.5

    threats, score = await handler._check_semantic_threats("test content")
    assert len(threats) > 0
    assert threats[0]["attack_type"] == "suspicious"
    handler._semantic_analyzer = None
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_add_pattern_with_agent(handler: SusPatternsManager) -> None:
    handler.agent_handler = AsyncMock()
    with patch.object(
        handler, "_send_pattern_event", new_callable=AsyncMock
    ) as mock_send:
        await handler.add_pattern("agent_test_pattern", custom=True)
    mock_send.assert_called_once()
    handler.agent_handler = None


@pytest.mark.asyncio
async def test_remove_default_pattern_index_out_of_range(
    handler: SusPatternsManager,
) -> None:
    handler.patterns = ["test_pattern"]
    handler.compiled_patterns = []
    result = await handler._remove_default_pattern("test_pattern")
    assert result is False


@pytest.mark.asyncio
async def test_send_pattern_removal_event(handler: SusPatternsManager) -> None:
    handler.agent_handler = AsyncMock()
    with patch.object(
        handler, "_send_pattern_event", new_callable=AsyncMock
    ) as mock_send:
        await handler._send_pattern_removal_event("test", True, 5)
    mock_send.assert_called_once()
    handler.agent_handler = None


@pytest.mark.asyncio
async def test_get_performance_stats_with_monitor() -> None:
    SusPatternsManager._instance = None
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8

    manager = SusPatternsManager(config)
    stats = await manager.get_performance_stats()
    assert stats is not None
    assert "summary" in stats
    assert "slow_patterns" in stats
    assert "problematic_patterns" in stats
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_check_regex_patterns_timeout_append(
    handler: SusPatternsManager,
) -> None:
    with patch.object(
        handler,
        "_check_regex_pattern",
        new_callable=AsyncMock,
        return_value=(None, True),
    ):
        threats, matched, timeouts = await handler._check_regex_patterns(
            "test content", "1.2.3.4", None, "request_body"
        )
    assert len(timeouts) > 0


@pytest.mark.asyncio
async def test_remove_default_pattern_not_found(
    handler: SusPatternsManager,
) -> None:
    result = await handler._remove_default_pattern("nonexistent_pattern_xyz")
    assert result is False


@pytest.mark.asyncio
async def test_configure_semantic_threshold(handler: SusPatternsManager) -> None:
    await handler.configure_semantic_threshold(0.5)
    assert handler._semantic_threshold == 0.5
    await handler.configure_semantic_threshold(1.5)
    assert handler._semantic_threshold == 1.0
    await handler.configure_semantic_threshold(-0.5)
    assert handler._semantic_threshold == 0.0
