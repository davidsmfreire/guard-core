import logging

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import SecurityConfig


@pytest.fixture
def manager() -> DynamicRuleManager:
    config = SecurityConfig(enable_redis=False)
    return DynamicRuleManager(config)


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_filters_invalid_providers(
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    await manager._apply_cloud_provider_rules({"AWS", "Bogus", "GCP"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP"}
    assert "ignored unknown cloud providers" in caplog.text
    assert "Bogus" in caplog.text


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_all_valid(
    manager: DynamicRuleManager,
) -> None:
    await manager._apply_cloud_provider_rules({"AWS", "GCP", "Azure"})
    assert manager.config.block_cloud_providers == {"AWS", "GCP", "Azure"}


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_empty_set(
    manager: DynamicRuleManager,
) -> None:
    await manager._apply_cloud_provider_rules(set())
    assert manager.config.block_cloud_providers == set()


@pytest.mark.asyncio
async def test_apply_cloud_provider_rules_all_invalid(
    manager: DynamicRuleManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    await manager._apply_cloud_provider_rules({"Bogus1", "Bogus2"})
    assert manager.config.block_cloud_providers == set()
    assert "ignored unknown cloud providers" in caplog.text
