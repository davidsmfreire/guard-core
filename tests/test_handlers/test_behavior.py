from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.models import SecurityConfig


@pytest.fixture
def behavior_config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)


@pytest.fixture
def tracker(behavior_config: SecurityConfig) -> BehaviorTracker:
    return BehaviorTracker(behavior_config)


def test_behavior_rule_initialization() -> None:
    rule = BehaviorRule(
        rule_type="usage",
        threshold=10,
        window=60,
        action="log",
    )
    assert rule.rule_type == "usage"
    assert rule.threshold == 10
    assert rule.window == 60
    assert rule.action == "log"
    assert rule.pattern is None
    assert rule.custom_action is None


def test_behavior_rule_with_pattern() -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=5,
        window=30,
        pattern="error",
        action="ban",
    )
    assert rule.rule_type == "return_pattern"
    assert rule.pattern == "error"
    assert rule.action == "ban"


def test_tracker_initialization(tracker: BehaviorTracker) -> None:
    assert tracker.redis_handler is None
    assert tracker.agent_handler is None
    assert len(tracker.usage_counts) == 0
    assert len(tracker.return_patterns) == 0


@pytest.mark.asyncio
async def test_initialize_redis(tracker: BehaviorTracker) -> None:
    mock_redis = MagicMock()
    await tracker.initialize_redis(mock_redis)
    assert tracker.redis_handler is mock_redis


@pytest.mark.asyncio
async def test_initialize_agent(tracker: BehaviorTracker) -> None:
    mock_agent = MagicMock()
    await tracker.initialize_agent(mock_agent)
    assert tracker.agent_handler is mock_agent


@pytest.mark.asyncio
async def test_track_endpoint_usage_below_threshold(
    tracker: BehaviorTracker,
) -> None:
    rule = BehaviorRule(rule_type="usage", threshold=5, window=60, action="log")

    result = await tracker.track_endpoint_usage("endpoint_1", "127.0.0.1", rule)
    assert result is False

    assert "endpoint_1" in tracker.usage_counts
    assert "127.0.0.1" in tracker.usage_counts["endpoint_1"]
    assert len(tracker.usage_counts["endpoint_1"]["127.0.0.1"]) > 0


@pytest.mark.asyncio
async def test_track_endpoint_usage_exceeds_threshold(
    tracker: BehaviorTracker,
) -> None:
    rule = BehaviorRule(rule_type="usage", threshold=3, window=60, action="log")

    for _ in range(4):
        result = await tracker.track_endpoint_usage("endpoint_1", "127.0.0.1", rule)

    assert result is True


@pytest.mark.asyncio
async def test_track_endpoint_usage_with_redis(tracker: BehaviorTracker) -> None:
    import time

    now = time.time()
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    mock_redis.keys = AsyncMock(
        return_value=[
            f"behavior_usage:behavior:usage:ep:ip:{now - 10}",
            f"behavior_usage:behavior:usage:ep:ip:{now - 5}",
        ]
    )
    tracker.redis_handler = mock_redis

    rule = BehaviorRule(rule_type="usage", threshold=1, window=3600)
    result = await tracker.track_endpoint_usage("ep", "ip", rule)
    assert result is True


@pytest.mark.asyncio
async def test_track_return_pattern_no_pattern(tracker: BehaviorTracker) -> None:
    from tests.conftest import MockGuardResponse

    rule = BehaviorRule(rule_type="return_pattern", threshold=5, pattern=None)
    result = await tracker.track_return_pattern("ep", "ip", MockGuardResponse(), rule)
    assert result is False


@pytest.mark.asyncio
async def test_track_return_pattern_status_match(tracker: BehaviorTracker) -> None:
    from tests.conftest import MockGuardResponse

    rule = BehaviorRule(
        rule_type="return_pattern", threshold=0, window=3600, pattern="status:200"
    )
    result = await tracker.track_return_pattern(
        "ep", "ip", MockGuardResponse(status_code=200), rule
    )
    assert result is True


@pytest.mark.asyncio
async def test_track_return_pattern_no_match(tracker: BehaviorTracker) -> None:
    from tests.conftest import MockGuardResponse

    rule = BehaviorRule(
        rule_type="return_pattern", threshold=5, window=3600, pattern="status:404"
    )
    result = await tracker.track_return_pattern(
        "ep", "ip", MockGuardResponse(status_code=200), rule
    )
    assert result is False


@pytest.mark.asyncio
async def test_track_return_pattern_with_redis(tracker: BehaviorTracker) -> None:
    import time

    from tests.conftest import MockGuardResponse

    now = time.time()
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    mock_redis.keys = AsyncMock(
        return_value=[
            f"behavior_returns:key:{now - 10}",
        ]
    )
    tracker.redis_handler = mock_redis

    rule = BehaviorRule(
        rule_type="return_pattern", threshold=0, window=3600, pattern="status:200"
    )
    result = await tracker.track_return_pattern(
        "ep", "ip", MockGuardResponse(status_code=200), rule
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_response_pattern_json(tracker: BehaviorTracker) -> None:
    import json

    from tests.conftest import MockGuardResponse

    body = json.dumps({"error": "not_found"})
    response = MockGuardResponse(content=body)
    result = await tracker._check_response_pattern(response, "json:error==not_found")
    assert result is True


@pytest.mark.asyncio
async def test_check_response_pattern_json_no_match(tracker: BehaviorTracker) -> None:
    import json

    from tests.conftest import MockGuardResponse

    body = json.dumps({"error": "found"})
    response = MockGuardResponse(content=body)
    result = await tracker._check_response_pattern(response, "json:error==not_found")
    assert result is False


@pytest.mark.asyncio
async def test_check_response_pattern_regex(tracker: BehaviorTracker) -> None:
    from tests.conftest import MockGuardResponse

    response = MockGuardResponse(content="Server error occurred")
    result = await tracker._check_response_pattern(response, "regex:error")
    assert result is True


@pytest.mark.asyncio
async def test_check_response_pattern_substring(tracker: BehaviorTracker) -> None:
    from tests.conftest import MockGuardResponse

    response = MockGuardResponse(content="something failed badly")
    result = await tracker._check_response_pattern(response, "failed")
    assert result is True


@pytest.mark.asyncio
async def test_check_response_pattern_no_body(tracker: BehaviorTracker) -> None:
    response = MagicMock()
    response.body = b""
    result = await tracker._check_response_pattern(response, "test")
    assert result is False


@pytest.mark.asyncio
async def test_check_response_pattern_invalid_json(tracker: BehaviorTracker) -> None:
    from tests.conftest import MockGuardResponse

    response = MockGuardResponse(content="not json")
    result = await tracker._check_response_pattern(response, "json:key==val")
    assert result is False


@pytest.mark.asyncio
async def test_apply_action_passive_mode(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = True
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_apply_action_active_ban(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = False
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")
    with patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ban:
        mock_ban.ban_ip = AsyncMock()
        await tracker.apply_action(rule, "1.2.3.4", "ep", "details")
        mock_ban.ban_ip.assert_called_once()


@pytest.mark.asyncio
async def test_apply_action_active_log(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = False
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_apply_action_active_throttle(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = False
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_apply_action_active_alert(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = False
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_apply_action_custom(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = False
    custom = AsyncMock()
    rule = BehaviorRule(
        rule_type="usage", threshold=5, action="log", custom_action=custom
    )
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")
    custom.assert_called_once()


@pytest.mark.asyncio
async def test_apply_action_passive_alert(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = True
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_apply_action_passive_throttle(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = True
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_apply_action_passive_log(tracker: BehaviorTracker) -> None:
    tracker.config.passive_mode = True
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")
    await tracker.apply_action(rule, "1.2.3.4", "ep", "details")


@pytest.mark.asyncio
async def test_send_behavior_event_no_agent(tracker: BehaviorTracker) -> None:
    await tracker._send_behavior_event("test", "1.2.3.4", "action", "reason")


@pytest.mark.asyncio
async def test_send_behavior_event_with_agent(tracker: BehaviorTracker) -> None:
    tracker.agent_handler = AsyncMock()
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await tracker._send_behavior_event("test", "1.2.3.4", "action", "reason")
    tracker.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_behavior_event_error(tracker: BehaviorTracker) -> None:
    tracker.agent_handler = AsyncMock()
    tracker.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await tracker._send_behavior_event("test", "1.2.3.4", "action", "reason")


@pytest.mark.asyncio
async def test_apply_action_sends_event_with_agent(tracker: BehaviorTracker) -> None:
    tracker.agent_handler = AsyncMock()
    tracker.config.passive_mode = False
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")
    with patch.object(
        tracker, "_send_behavior_event", new_callable=AsyncMock
    ) as mock_send:
        await tracker.apply_action(rule, "1.2.3.4", "ep", "details")
        mock_send.assert_called_once()


def test_parse_pattern(tracker: BehaviorTracker) -> None:
    result = tracker._parse_pattern("key==value")
    assert result == ("key", "value")

    result = tracker._parse_pattern("no_equals")
    assert result is None


def test_traverse_json_path(tracker: BehaviorTracker) -> None:
    data = {"a": {"b": {"c": "val"}}}
    result = tracker._traverse_json_path(data, "a.b.c")
    assert result == "val"

    result = tracker._traverse_json_path(data, "a.x")
    assert result is None


def test_handle_array_match(tracker: BehaviorTracker) -> None:
    data = {"items": ["a", "b", "c"]}
    assert tracker._handle_array_match(data, "items[]", "b") is True
    assert tracker._handle_array_match(data, "items[]", "d") is False
    assert tracker._handle_array_match(data, "missing[]", "a") is False
    assert tracker._handle_array_match({"items": "not_list"}, "items[]", "a") is False


def test_match_json_pattern_array(tracker: BehaviorTracker) -> None:
    data = {"items": ["x", "y"]}
    assert tracker._match_json_pattern(data, "items[]==x") is True
    assert tracker._match_json_pattern(data, "items[]==z") is False


def test_match_json_pattern_nested(tracker: BehaviorTracker) -> None:
    data = {"a": {"b": "c"}}
    assert tracker._match_json_pattern(data, "a.b==c") is True
    assert tracker._match_json_pattern(data, "a.b==d") is False


def test_match_json_pattern_invalid(tracker: BehaviorTracker) -> None:
    assert tracker._match_json_pattern({}, "no_equals") is False


@pytest.mark.asyncio
async def test_track_endpoint_usage_redis_invalid_timestamp(
    tracker: BehaviorTracker,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    mock_redis.keys = AsyncMock(
        return_value=[
            "behavior_usage:key:not_a_number",
            "behavior_usage:key:also_bad",
        ]
    )
    tracker.redis_handler = mock_redis
    rule = BehaviorRule(rule_type="usage", threshold=5, window=3600)
    result = await tracker.track_endpoint_usage("ep", "ip", rule)
    assert result is False


@pytest.mark.asyncio
async def test_track_return_pattern_redis_invalid_timestamp(
    tracker: BehaviorTracker,
) -> None:
    from tests.conftest import MockGuardResponse

    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()
    mock_redis.keys = AsyncMock(
        return_value=[
            "behavior_returns:key:not_a_number",
        ]
    )
    tracker.redis_handler = mock_redis
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=5, window=3600, pattern="status:200"
    )
    result = await tracker.track_return_pattern(
        "ep", "ip", MockGuardResponse(status_code=200), rule
    )
    assert result is False


@pytest.mark.asyncio
async def test_check_response_pattern_non_bytes_body(
    tracker: BehaviorTracker,
) -> None:
    response = MagicMock()
    response.body = "string body content"
    response.status_code = 200
    result = await tracker._check_response_pattern(response, "string body")
    assert result is True


@pytest.mark.asyncio
async def test_check_response_pattern_exception(
    tracker: BehaviorTracker,
) -> None:
    response = MagicMock()
    response.body = property(lambda self: (_ for _ in ()).throw(Exception("fail")))
    del response.body
    type(response).body = property(
        lambda self: (_ for _ in ()).throw(Exception("fail"))
    )
    result = await tracker._check_response_pattern(response, "test")
    assert result is False


def test_match_json_pattern_missing_nested_key(tracker: BehaviorTracker) -> None:
    data = {"a": {"b": "c"}}
    assert tracker._match_json_pattern(data, "a.x.y==val") is False


def test_match_json_pattern_exception(tracker: BehaviorTracker) -> None:
    class BadDict(dict):
        def __getitem__(self, key):
            raise RuntimeError("unexpected error")

    assert tracker._match_json_pattern(BadDict({"a": "b"}), "a==b") is False
