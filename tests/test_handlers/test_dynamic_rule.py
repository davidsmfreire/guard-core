import asyncio
from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


@pytest.fixture(autouse=True)
def reset_dynamic_rule_singleton() -> Generator:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_dynamic_rules=False,
    )


@pytest.fixture
def manager(config: SecurityConfig) -> DynamicRuleManager:
    return DynamicRuleManager(config)


def test_singleton_behavior() -> None:
    config = SecurityConfig(enable_redis=False)
    m1 = DynamicRuleManager(config)
    m2 = DynamicRuleManager(config)
    assert m1 is m2


def test_initialization(manager: DynamicRuleManager, config: SecurityConfig) -> None:
    assert manager.config == config
    assert manager.agent_handler is None
    assert manager.redis_handler is None
    assert manager.current_rules is None
    assert manager.update_task is None


@pytest.mark.asyncio
async def test_initialize_redis(manager: DynamicRuleManager) -> None:
    mock_redis = MagicMock()
    await manager.initialize_redis(mock_redis)
    assert manager.redis_handler is mock_redis


def test_should_update_rules_no_current(manager: DynamicRuleManager) -> None:
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    assert manager._should_update_rules(rules) is True


def test_should_update_rules_same_version(manager: DynamicRuleManager) -> None:
    manager.current_rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    assert manager._should_update_rules(rules) is False


def test_should_update_rules_newer_version(manager: DynamicRuleManager) -> None:
    manager.current_rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    rules = DynamicRules(
        rule_id="test", version=2, timestamp=datetime.now(timezone.utc)
    )
    assert manager._should_update_rules(rules) is True


def test_should_update_rules_different_id(manager: DynamicRuleManager) -> None:
    manager.current_rules = DynamicRules(
        rule_id="test1", version=1, timestamp=datetime.now(timezone.utc)
    )
    rules = DynamicRules(
        rule_id="test2", version=1, timestamp=datetime.now(timezone.utc)
    )
    assert manager._should_update_rules(rules) is True


@pytest.mark.asyncio
async def test_initialize_agent_starts_loop(config: SecurityConfig) -> None:
    config.enable_dynamic_rules = True
    DynamicRuleManager._instance = None
    manager = DynamicRuleManager(config)
    mock_agent = AsyncMock()

    with patch.object(manager, "_rule_update_loop", new_callable=AsyncMock):
        await manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent
    if manager.update_task:
        manager.update_task.cancel()
        try:
            await manager.update_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_stop(manager: DynamicRuleManager) -> None:
    async def dummy_loop() -> None:
        await asyncio.sleep(100)

    manager.update_task = asyncio.create_task(dummy_loop())
    await manager.stop()
    assert manager.update_task is None


@pytest.mark.asyncio
async def test_stop_no_task(manager: DynamicRuleManager) -> None:
    await manager.stop()
    assert manager.update_task is None


@pytest.mark.asyncio
async def test_get_current_rules(manager: DynamicRuleManager) -> None:
    assert await manager.get_current_rules() is None
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    manager.current_rules = rules
    assert await manager.get_current_rules() is rules


@pytest.mark.asyncio
async def test_force_update(manager: DynamicRuleManager) -> None:
    with patch.object(manager, "update_rules", new_callable=AsyncMock) as mock:
        await manager.force_update()
        mock.assert_called_once()


@pytest.mark.asyncio
async def test_update_rules_disabled(manager: DynamicRuleManager) -> None:
    manager.config.enable_dynamic_rules = False
    await manager.update_rules()


@pytest.mark.asyncio
async def test_update_rules_no_agent(manager: DynamicRuleManager) -> None:
    manager.config.enable_dynamic_rules = True
    manager.agent_handler = None
    await manager.update_rules()


@pytest.mark.asyncio
async def test_update_rules_no_rules_returned(manager: DynamicRuleManager) -> None:
    manager.config.enable_dynamic_rules = True
    manager.agent_handler = AsyncMock()
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=None)
    await manager.update_rules()


@pytest.mark.asyncio
async def test_update_rules_same_version(manager: DynamicRuleManager) -> None:
    manager.config.enable_dynamic_rules = True
    manager.agent_handler = AsyncMock()
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    manager.current_rules = rules
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=rules)
    await manager.update_rules()


@pytest.mark.asyncio
async def test_update_rules_applies_new(manager: DynamicRuleManager) -> None:
    manager.config.enable_dynamic_rules = True
    manager.agent_handler = AsyncMock()
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=rules)

    with (
        patch.object(manager, "_apply_rules", new_callable=AsyncMock),
        patch.object(manager, "_send_rule_received_event", new_callable=AsyncMock),
        patch.object(manager, "_send_rule_applied_event", new_callable=AsyncMock),
    ):
        await manager.update_rules()

    assert manager.current_rules is rules


@pytest.mark.asyncio
async def test_update_rules_error(manager: DynamicRuleManager) -> None:
    manager.config.enable_dynamic_rules = True
    manager.agent_handler = AsyncMock()
    manager.agent_handler.get_dynamic_rules = AsyncMock(side_effect=Exception("fail"))
    await manager.update_rules()


@pytest.mark.asyncio
async def test_apply_rules_full(manager: DynamicRuleManager) -> None:
    rules = DynamicRules(
        rule_id="test",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["1.2.3.4"],
        ip_whitelist=["5.6.7.8"],
        blocked_countries=["CN"],
        whitelist_countries=["US"],
        blocked_cloud_providers={"AWS"},
        blocked_user_agents=["BadBot"],
        suspicious_patterns=["evil"],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={"/api": (10, 60)},
        enable_penetration_detection=True,
        enable_ip_banning=False,
        enable_rate_limiting=True,
        emergency_mode=False,
    )

    with (
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ban,
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_ban.ban_ip = AsyncMock()
        mock_ban.unban_ip = AsyncMock()
        mock_sus.add_pattern = AsyncMock()
        await manager._apply_rules(rules)

    assert manager.config.blocked_countries == ["CN"]
    assert manager.config.rate_limit == 50


@pytest.mark.asyncio
async def test_apply_rules_error_raises(manager: DynamicRuleManager) -> None:
    rules = DynamicRules(
        rule_id="test",
        version=1,
        timestamp=datetime.now(timezone.utc),
    )
    with patch.object(
        manager,
        "_apply_ip_rules",
        new_callable=AsyncMock,
        side_effect=Exception("fail"),
    ):
        with pytest.raises(Exception, match="fail"):
            await manager._apply_rules(rules)


@pytest.mark.asyncio
async def test_activate_emergency_mode(manager: DynamicRuleManager) -> None:
    manager.config.auto_ban_threshold = 10
    await manager._activate_emergency_mode(["10.0.0.1"])
    assert manager.config.emergency_mode is True
    assert manager.config.auto_ban_threshold == 5


@pytest.mark.asyncio
async def test_activate_emergency_mode_with_agent(manager: DynamicRuleManager) -> None:
    manager.agent_handler = AsyncMock()
    manager.config.auto_ban_threshold = 10

    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._activate_emergency_mode(["10.0.0.1"])

    manager.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_rule_applied_event_no_agent(manager: DynamicRuleManager) -> None:
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    await manager._send_rule_applied_event(rules)


@pytest.mark.asyncio
async def test_send_rule_applied_event_with_agent(manager: DynamicRuleManager) -> None:
    manager.agent_handler = AsyncMock()
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_rule_applied_event(rules)
    manager.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_rule_received_event_no_agent(manager: DynamicRuleManager) -> None:
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    await manager._send_rule_received_event(rules)


@pytest.mark.asyncio
async def test_send_rule_received_event_with_agent(manager: DynamicRuleManager) -> None:
    manager.agent_handler = AsyncMock()
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_rule_received_event(rules)
    manager.agent_handler.send_event.assert_called_once()


@pytest.mark.asyncio
async def test_send_emergency_event_no_agent(manager: DynamicRuleManager) -> None:
    await manager._send_emergency_event([])


@pytest.mark.asyncio
async def test_apply_feature_toggles(manager: DynamicRuleManager) -> None:
    rules = DynamicRules(
        rule_id="test",
        version=1,
        timestamp=datetime.now(timezone.utc),
        enable_penetration_detection=False,
        enable_ip_banning=False,
        enable_rate_limiting=False,
    )
    await manager._apply_feature_toggles(rules)
    assert manager.config.enable_penetration_detection is False
    assert manager.config.enable_ip_banning is False
    assert manager.config.enable_rate_limiting is False


@pytest.mark.asyncio
async def test_apply_ip_bans_error(manager: DynamicRuleManager) -> None:
    with patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ban:
        mock_ban.ban_ip = AsyncMock(side_effect=Exception("fail"))
        await manager._apply_ip_bans(["1.2.3.4"], 3600)


@pytest.mark.asyncio
async def test_apply_ip_whitelist_error(manager: DynamicRuleManager) -> None:
    with patch("guard_core.handlers.ipban_handler.ip_ban_manager") as mock_ban:
        mock_ban.unban_ip = AsyncMock(side_effect=Exception("fail"))
        await manager._apply_ip_whitelist(["1.2.3.4"])


@pytest.mark.asyncio
async def test_rule_update_loop_cancellation(manager: DynamicRuleManager) -> None:
    manager.config.dynamic_rule_interval = 0.01
    with patch.object(manager, "update_rules", new_callable=AsyncMock):
        task = asyncio.create_task(manager._rule_update_loop())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_rule_update_loop_error_recovery(manager: DynamicRuleManager) -> None:
    manager.config.dynamic_rule_interval = 0.01
    call_count = 0

    async def failing_update() -> None:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise RuntimeError("update failed")

    with patch.object(manager, "update_rules", side_effect=failing_update):
        task = asyncio.create_task(manager._rule_update_loop())
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    assert call_count >= 2


@pytest.mark.asyncio
async def test_send_rule_received_event_error(manager: DynamicRuleManager) -> None:
    manager.agent_handler = AsyncMock()
    manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_rule_received_event(rules)


@pytest.mark.asyncio
async def test_apply_rules_emergency_mode(manager: DynamicRuleManager) -> None:
    manager.config.auto_ban_threshold = 10
    rules = DynamicRules(
        rule_id="test",
        version=1,
        timestamp=datetime.now(timezone.utc),
        emergency_mode=True,
        emergency_whitelist=["10.0.0.1"],
    )
    with patch.object(manager, "_apply_ip_rules", new_callable=AsyncMock):
        with patch.object(manager, "_apply_blocking_rules", new_callable=AsyncMock):
            with patch.object(
                manager, "_apply_feature_toggles", new_callable=AsyncMock
            ):
                await manager._apply_rules(rules)
    assert manager.config.emergency_mode is True


@pytest.mark.asyncio
async def test_send_rule_applied_event_error(manager: DynamicRuleManager) -> None:
    manager.agent_handler = AsyncMock()
    manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_rule_applied_event(rules)


@pytest.mark.asyncio
async def test_send_emergency_event_error(manager: DynamicRuleManager) -> None:
    manager.agent_handler = AsyncMock()
    manager.agent_handler.send_event = AsyncMock(side_effect=Exception("fail"))
    with patch.dict("sys.modules", {"guard_agent": MagicMock()}):
        await manager._send_emergency_event(["10.0.0.1"])
