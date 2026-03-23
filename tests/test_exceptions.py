from guard_core.exceptions import GuardCoreError, GuardRedisError


def test_guard_core_error():
    error = GuardCoreError("test error")
    assert str(error) == "test error"


def test_guard_redis_error():
    error = GuardRedisError(503, "Redis unavailable")
    assert error.status_code == 503
    assert error.detail == "Redis unavailable"
    assert str(error) == "Redis unavailable"
    assert isinstance(error, GuardCoreError)
