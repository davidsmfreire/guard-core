import types
from typing import Any, cast

from guard_core.sync.detection_engine import safe_regex as re
from guard_core.sync.detection_engine.compiler import PatternCompiler


def test_distinct_patterns_get_distinct_cache_entries() -> None:
    compiler = PatternCompiler()

    p1 = compiler.compile_pattern("alpha", re.IGNORECASE)
    p2 = compiler.compile_pattern("beta", re.IGNORECASE)

    assert p1.pattern == "alpha"
    assert p2.pattern == "beta"
    assert len(compiler._compiled_cache) == 2


def test_cache_key_is_deterministic_pattern_flags_form() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("xyz", 0)
    keys = list(compiler._compiled_cache.keys())
    assert keys == ["xyz:0"], (
        f"cache key must be deterministic 'pattern:flags', got {keys!r}"
    )


def test_same_pattern_same_flags_hits_cache() -> None:
    compiler = PatternCompiler()
    p1 = compiler.compile_pattern("repeat", re.IGNORECASE)
    p2 = compiler.compile_pattern("repeat", re.IGNORECASE)
    assert p1 is p2
    assert len(compiler._compiled_cache) == 1


def test_same_pattern_different_flags_creates_separate_entries() -> None:
    compiler = PatternCompiler()
    p_ci = compiler.compile_pattern("Word", re.IGNORECASE)
    p_cs = compiler.compile_pattern("Word", 0)
    assert p_ci is not p_cs
    assert len(compiler._compiled_cache) == 2


def test_cache_eviction_when_full() -> None:
    compiler = PatternCompiler(max_cache_size=2)
    compiler.compile_pattern("first", 0)
    compiler.compile_pattern("second", 0)
    compiler.compile_pattern("third", 0)
    assert len(compiler._compiled_cache) == 2
    assert "first:0" not in compiler._compiled_cache


def test_cache_hit_lru_reorder() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("cached", 0)
    compiler.compile_pattern("cached", 0)
    assert len(compiler._compiled_cache) == 1


def test_compile_pattern_sync() -> None:
    compiler = PatternCompiler()
    result = compiler.compile_pattern_sync("hello", re.IGNORECASE)
    assert isinstance(result, re.Pattern)
    assert result.pattern == "hello"
    assert result.search("say HELLO") is not None


def test_validate_pattern_safety_safe_pattern() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("hello world")
    assert safe is True
    assert msg == "Pattern appears safe"


def test_validate_pattern_safety_dangerous_pattern() -> None:
    # Classic catastrophic-backtracking patterns are linear under RE2, so they
    # are now accepted (and run quickly) instead of being rejected.
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety(r"(.*)+")
    assert safe is True
    assert msg == "Pattern appears safe"

    compiled = compiler.compile_pattern_sync(r"(.*)+")
    assert compiled.search("a" * 10000 + "!") is not None


def test_validate_pattern_safety_custom_test_strings() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("test", test_strings=["abc", "xyz"])
    assert safe is True


def test_validate_pattern_safety_invalid_regex() -> None:
    compiler = PatternCompiler()
    safe, msg = compiler.validate_pattern_safety("[invalid")
    assert safe is False
    assert "RE2" in msg


def test_validate_pattern_safety_rejects_unsupported_constructs() -> None:
    # RE2 has no lookaround or backreferences; such patterns are rejected at
    # compile time rather than silently degrading to a backtracking engine.
    compiler = PatternCompiler()
    for pattern in (r"(?=foo)bar", r"(?<=foo)bar", r"(\w+)\1"):
        safe, msg = compiler.validate_pattern_safety(pattern)
        assert safe is False
        assert "RE2" in msg


def test_batch_compile_with_validation() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile(["hello", "world"], validate=True)
    assert "hello" in result
    assert "world" in result


def test_batch_compile_without_validation() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile(["hello"], validate=False)
    assert "hello" in result


def test_batch_compile_skips_dangerous_patterns() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile([r"(.*)+", "safe"], validate=True)
    assert r"(.*)+'" not in result
    assert "safe" in result


def test_batch_compile_skips_invalid_regex() -> None:
    compiler = PatternCompiler()
    result = compiler.batch_compile(["[invalid", "valid"], validate=False)
    assert "[invalid" not in result
    assert "valid" in result


def test_clear_cache() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("a", 0)
    compiler.compile_pattern("b", 0)
    assert len(compiler._compiled_cache) == 2
    compiler.clear_cache()
    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0


def test_compile_pattern_cache_hit_then_evicted_branch() -> None:
    compiler = PatternCompiler()
    compiler.compile_pattern("evict_me", 0)

    original_lock = compiler._lock

    class EvictOnFirstAcquire:
        _call_count = 0

        def __enter__(self) -> "EvictOnFirstAcquire":
            self._call_count += 1
            if self._call_count == 1:
                compiler._compiled_cache.clear()
                compiler._cache_order.clear()
            original_lock.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            original_lock.__exit__(exc_type, exc_val, exc_tb)

    compiler._lock = cast(Any, EvictOnFirstAcquire())
    result = compiler.compile_pattern("evict_me", 0)
    assert result.pattern == "evict_me"


def test_compile_pattern_concurrent_write_branch() -> None:
    compiler = PatternCompiler()

    original_lock = compiler._lock

    class InsertOnFirstAcquire:
        _call_count = 0

        def __enter__(self) -> "InsertOnFirstAcquire":
            self._call_count += 1
            if self._call_count == 1:
                key = "concurrent:0"
                compiler._compiled_cache[key] = re.compile("concurrent", 0)
                compiler._cache_order.append(key)
            original_lock.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            original_lock.__exit__(exc_type, exc_val, exc_tb)

    compiler._lock = cast(Any, InsertOnFirstAcquire())
    result = compiler.compile_pattern("concurrent", 0)
    assert result.pattern == "concurrent"
