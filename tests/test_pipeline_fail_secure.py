from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig


def test_default_security_config_is_fail_secure() -> None:
    config = SecurityConfig()
    assert hasattr(config, "fail_secure")
    assert config.fail_secure is True


def test_fail_secure_can_be_disabled() -> None:
    config = SecurityConfig(fail_secure=False)
    assert config.fail_secure is False


@pytest.mark.asyncio
async def test_pipeline_returns_blocked_when_fail_secure_and_check_raises() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(fail_secure=True)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = AsyncMock(side_effect=RuntimeError("boom"))
    failing_check.create_error_response = AsyncMock(return_value="BLOCKED")

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())
    assert result == "BLOCKED"


@pytest.mark.asyncio
async def test_pipeline_falls_through_when_not_fail_secure() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(fail_secure=False)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = AsyncMock(side_effect=RuntimeError("boom"))

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())
    assert result is None


def test_default_security_config_is_redis_fail_open() -> None:
    config = SecurityConfig()
    assert config.redis_fail_open is True


@pytest.mark.asyncio
async def test_pipeline_fails_open_on_redis_error_despite_fail_secure() -> None:
    config = SecurityConfig(fail_secure=True, redis_fail_open=True)

    failing_check = MagicMock()
    failing_check.check_name = "ip_security"
    failing_check.config = config
    failing_check.check = AsyncMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )
    failing_check.create_error_response = AsyncMock(return_value="BLOCKED")

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())

    assert result is None
    failing_check.create_error_response.assert_not_called()


@pytest.mark.asyncio
async def test_pipeline_blocks_on_redis_error_when_fail_open_disabled() -> None:
    config = SecurityConfig(fail_secure=True, redis_fail_open=False)

    failing_check = MagicMock()
    failing_check.check_name = "ip_security"
    failing_check.config = config
    failing_check.check = AsyncMock(
        side_effect=GuardRedisError(503, "Redis connection failed")
    )
    failing_check.create_error_response = AsyncMock(return_value="BLOCKED")

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())

    assert result == "BLOCKED"
