import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.detection_engine.monitor import (
    PatternStats,
    PerformanceMetric,
    PerformanceMonitor,
)


def test_initialization() -> None:
    monitor = PerformanceMonitor()
    assert monitor.anomaly_threshold == 3.0
    assert monitor.slow_pattern_threshold == 0.1
    assert monitor.history_size == 1000
    assert monitor.max_tracked_patterns == 1000
    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0
    assert len(monitor.anomaly_callbacks) == 0

    monitor = PerformanceMonitor(
        anomaly_threshold=5.0,
        slow_pattern_threshold=0.5,
        history_size=500,
        max_tracked_patterns=200,
    )
    assert monitor.anomaly_threshold == 5.0
    assert monitor.slow_pattern_threshold == 0.5
    assert monitor.history_size == 500
    assert monitor.max_tracked_patterns == 200


def test_initialization_bounds() -> None:
    monitor = PerformanceMonitor(
        anomaly_threshold=0.5,
        slow_pattern_threshold=0.001,
        history_size=50,
        max_tracked_patterns=50,
    )
    assert monitor.anomaly_threshold == 1.0
    assert monitor.slow_pattern_threshold == 0.01
    assert monitor.history_size == 100
    assert monitor.max_tracked_patterns == 100

    monitor = PerformanceMonitor(
        anomaly_threshold=20.0,
        slow_pattern_threshold=20.0,
        history_size=20000,
        max_tracked_patterns=10000,
    )
    assert monitor.anomaly_threshold == 10.0
    assert monitor.slow_pattern_threshold == 10.0
    assert monitor.history_size == 10000
    assert monitor.max_tracked_patterns == 5000


@pytest.mark.asyncio
async def test_record_metric_pattern_truncation() -> None:
    monitor = PerformanceMonitor()

    long_pattern = "a" * 150
    await monitor.record_metric(
        pattern=long_pattern,
        execution_time=0.05,
        content_length=100,
        matched=True,
    )

    stored_pattern = list(monitor.pattern_stats.keys())[0]
    assert len(stored_pattern) == 114
    assert stored_pattern.endswith("...[truncated]")


@pytest.mark.asyncio
async def test_record_metric_max_patterns_limit() -> None:
    monitor = PerformanceMonitor(max_tracked_patterns=100)

    patterns = [f"pattern_{i:03d}" for i in range(100)]
    for pattern in patterns:
        await monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(monitor.pattern_stats) == 100

    await monitor.record_metric(
        pattern="pattern_100",
        execution_time=0.01,
        content_length=100,
        matched=False,
    )

    assert len(monitor.pattern_stats) == 100
    assert "pattern_000" not in monitor.pattern_stats
    assert "pattern_100" in monitor.pattern_stats


@pytest.mark.asyncio
async def test_record_metric_with_timeout() -> None:
    monitor = PerformanceMonitor()

    await monitor.record_metric(
        pattern="timeout_pattern",
        execution_time=1.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    stats = monitor.pattern_stats["timeout_pattern"]
    assert stats.total_executions == 1
    assert stats.total_timeouts == 1
    assert stats.total_matches == 0
    assert len(stats.recent_times) == 0


@pytest.mark.asyncio
async def test_check_anomalies_timeout() -> None:
    monitor = PerformanceMonitor()

    anomalies_detected: list[dict[str, Any]] = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    await monitor.record_metric(
        pattern="timeout_test",
        execution_time=5.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "timeout"
    assert "timeout_test" in anomalies_detected[0]["pattern"]


@pytest.mark.asyncio
async def test_check_anomalies_statistical() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected: list[dict[str, Any]] = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "stat_pattern"
    for _ in range(20):
        await monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    anomalies_detected.clear()

    await monitor.record_metric(
        pattern=pattern,
        execution_time=0.1,
        content_length=100,
        matched=False,
    )

    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "statistical_anomaly"
    assert anomalies_detected[0]["z_score"] > 2.0


@pytest.mark.asyncio
async def test_check_anomalies_with_agent() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()

    await monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )

    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "pattern_anomaly_slow_execution"
    assert event.action_taken == "anomaly_detected"
    assert event.metadata["correlation_id"] == "test-123"


@pytest.mark.asyncio
async def test_check_anomalies_agent_error() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock(side_effect=Exception("Agent error"))

    await monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


def test_get_pattern_report_not_found() -> None:
    monitor = PerformanceMonitor()

    report = monitor.get_pattern_report("non_existent")
    assert report is None


def test_get_pattern_report_truncation() -> None:
    monitor = PerformanceMonitor()

    pattern = "test_pattern"
    stats = PatternStats(
        pattern=pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[pattern] = stats

    report = monitor.get_pattern_report(pattern)
    assert report is not None
    assert report["pattern"] == pattern
    assert report["total_executions"] == 10
    assert report["match_rate"] == 0.5
    assert report["timeout_rate"] == 0.1


def test_get_summary_stats_empty() -> None:
    monitor = PerformanceMonitor()

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 0
    assert stats["avg_execution_time"] == 0.0
    assert stats["timeout_rate"] == 0.0
    assert stats["match_rate"] == 0.0


@pytest.mark.asyncio
async def test_get_summary_stats_with_data() -> None:
    monitor = PerformanceMonitor()

    await monitor.record_metric("p1", 0.01, 100, True, False)
    await monitor.record_metric("p2", 0.02, 200, False, False)
    await monitor.record_metric("p3", 1.0, 300, False, True)
    await monitor.record_metric("p4", 0.03, 400, True, False)

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 4
    assert stats["match_rate"] == 0.5
    assert stats["timeout_rate"] == 0.25
    assert stats["total_patterns"] == 4


def test_register_anomaly_callback() -> None:
    monitor = PerformanceMonitor()

    def callback(anomaly: dict[str, Any]) -> None:
        pass

    monitor.register_anomaly_callback(callback)
    assert len(monitor.anomaly_callbacks) == 1
    assert monitor.anomaly_callbacks[0] == callback


@pytest.mark.asyncio
async def test_clear_stats() -> None:
    monitor = PerformanceMonitor()

    await monitor.record_metric("pattern1", 0.01, 100, True)
    await monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2
    assert len(monitor.recent_metrics) == 2

    await monitor.clear_stats()

    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0


@pytest.mark.asyncio
async def test_remove_pattern_stats() -> None:
    monitor = PerformanceMonitor()

    await monitor.record_metric("pattern1", 0.01, 100, True)
    await monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2

    await monitor.remove_pattern_stats("pattern1")

    assert len(monitor.pattern_stats) == 1
    assert "pattern1" not in monitor.pattern_stats
    assert "pattern2" in monitor.pattern_stats

    await monitor.remove_pattern_stats("non_existent")


@pytest.mark.asyncio
async def test_get_slow_patterns() -> None:
    monitor = PerformanceMonitor()

    patterns = [
        ("very_slow", 0.5),
        ("slow", 0.2),
        ("medium", 0.1),
        ("fast", 0.01),
        ("very_fast", 0.001),
    ]

    for pattern, exec_time in patterns:
        for _ in range(3):
            await monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    slow_patterns = monitor.get_slow_patterns(limit=3)

    assert len(slow_patterns) == 3
    assert "very_slow" in slow_patterns[0]["pattern"]
    assert "slow" in slow_patterns[1]["pattern"]
    assert "medium" in slow_patterns[2]["pattern"]


@pytest.mark.asyncio
async def test_metric_validation() -> None:
    monitor = PerformanceMonitor()

    await monitor.record_metric(
        pattern="test",
        execution_time=-1.0,
        content_length=-100,
        matched=False,
    )

    metric = monitor.recent_metrics[0]
    assert metric.execution_time == 0.0
    assert metric.content_length == 0


@pytest.mark.asyncio
async def test_pattern_stats_dataclass() -> None:
    stats = PatternStats(pattern="test_pattern")

    assert stats.pattern == "test_pattern"
    assert stats.total_executions == 0
    assert stats.total_matches == 0
    assert stats.total_timeouts == 0
    assert stats.avg_execution_time == 0.0
    assert stats.max_execution_time == 0.0
    assert stats.min_execution_time == float("inf")
    assert isinstance(stats.recent_times, deque)
    assert stats.recent_times.maxlen == 100


def test_performance_metric_dataclass() -> None:
    now = datetime.now(timezone.utc)
    metric = PerformanceMetric(
        pattern="test_pattern",
        execution_time=0.05,
        content_length=1000,
        timestamp=now,
        matched=True,
        timeout=False,
    )

    assert metric.pattern == "test_pattern"
    assert metric.execution_time == 0.05
    assert metric.content_length == 1000
    assert metric.timestamp == now
    assert metric.matched is True
    assert metric.timeout is False


@pytest.mark.asyncio
async def test_concurrent_access() -> None:
    monitor = PerformanceMonitor()

    async def record_metrics(pattern: str, count: int) -> None:
        for i in range(count):
            await monitor.record_metric(
                pattern=f"{pattern}_{i % 3}",
                execution_time=0.01 * (i % 5 + 1),
                content_length=100 * (i % 3 + 1),
                matched=i % 2 == 0,
            )

    tasks = [
        record_metrics("task1", 10),
        record_metrics("task2", 10),
        record_metrics("task3", 10),
    ]

    await asyncio.gather(*tasks)

    assert len(monitor.recent_metrics) == 30
    total_patterns = len(monitor.pattern_stats)
    assert total_patterns > 0

    for _, stats in monitor.pattern_stats.items():
        assert stats.total_executions > 0
        assert stats.max_execution_time >= stats.min_execution_time
        if stats.recent_times:
            assert stats.avg_execution_time > 0


@pytest.mark.asyncio
async def test_get_problematic_patterns_high_timeout() -> None:
    monitor = PerformanceMonitor()

    for _ in range(10):
        await monitor.record_metric(
            pattern="timeout_heavy",
            execution_time=1.0,
            content_length=100,
            matched=False,
            timeout=True,
        )

    problematic = monitor.get_problematic_patterns()
    assert len(problematic) > 0
    assert any(p["issue"] == "high_timeout_rate" for p in problematic)


@pytest.mark.asyncio
async def test_get_problematic_patterns_consistently_slow() -> None:
    monitor = PerformanceMonitor(slow_pattern_threshold=0.01)

    for _ in range(5):
        await monitor.record_metric(
            pattern="slow_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            timeout=False,
        )

    problematic = monitor.get_problematic_patterns()
    assert len(problematic) > 0
    assert any(p["issue"] == "consistently_slow" for p in problematic)


@pytest.mark.asyncio
async def test_get_problematic_patterns_empty() -> None:
    monitor = PerformanceMonitor()
    problematic = monitor.get_problematic_patterns()
    assert problematic == []


@pytest.mark.asyncio
async def test_notify_callbacks_error_with_agent() -> None:
    monitor = PerformanceMonitor()

    def bad_callback(anomaly: dict) -> None:
        raise Exception("callback error")

    monitor.register_anomaly_callback(bad_callback)
    agent = MagicMock()
    agent.send_event = AsyncMock()

    await monitor.record_metric(
        pattern="test",
        execution_time=5.0,
        content_length=100,
        matched=False,
        timeout=True,
        agent_handler=agent,
    )

    assert agent.send_event.call_count >= 1


def test_detect_statistical_anomaly_below_threshold() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=100.0)
    stats = PatternStats(pattern="test")
    stats.recent_times = deque(
        [0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02]
    )
    stats.total_executions = 10
    monitor.pattern_stats["test"] = stats

    metric = PerformanceMetric(
        pattern="test",
        execution_time=0.015,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )
    result = monitor._detect_statistical_anomaly(metric)
    assert result is None


async def test_send_callback_error_event_inner_exception() -> None:
    monitor = PerformanceMonitor()
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=Exception("inner fail"))
    await monitor._send_callback_error_event(
        Exception("outer"), {"type": "test"}, agent, "corr-id"
    )


def test_get_pattern_report_long_pattern() -> None:
    monitor = PerformanceMonitor()
    long_pattern = "x" * 200
    result = monitor.get_pattern_report(long_pattern)
    assert result is None


def test_get_problematic_patterns_zero_executions() -> None:
    monitor = PerformanceMonitor()
    stats = PatternStats(pattern="test")
    stats.total_executions = 0
    monitor.pattern_stats["test"] = stats
    result = monitor.get_problematic_patterns()
    assert result == []
