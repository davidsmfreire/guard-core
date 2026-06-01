import asyncio

from guard_core.detection_engine import safe_regex as re


class PatternCompiler:
    MAX_CACHE_SIZE = 1000

    def __init__(self, default_timeout: float = 5.0, max_cache_size: int = 1000):
        self.default_timeout = default_timeout
        self.max_cache_size = min(max_cache_size, 5000)
        self._compiled_cache: dict[str, re.Pattern] = {}
        self._cache_order: list[str] = []
        self._lock = asyncio.Lock()

    async def compile_pattern(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        cache_key = f"{pattern}:{flags}"

        if cache_key in self._compiled_cache:
            async with self._lock:
                if cache_key in self._compiled_cache:
                    self._cache_order.remove(cache_key)
                    self._cache_order.append(cache_key)
                    return self._compiled_cache[cache_key]

        async with self._lock:
            if cache_key not in self._compiled_cache:
                if len(self._compiled_cache) >= self.max_cache_size:
                    oldest_key = self._cache_order.pop(0)
                    del self._compiled_cache[oldest_key]

                self._compiled_cache[cache_key] = re.compile(pattern, flags)
                self._cache_order.append(cache_key)

            return self._compiled_cache[cache_key]

    def compile_pattern_sync(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        return re.compile(pattern, flags)

    def validate_pattern_safety(
        self, pattern: str, test_strings: list[str] | None = None
    ) -> tuple[bool, str]:
        # RE2 matches in linear time, so any pattern it accepts is free of
        # catastrophic backtracking - validation reduces to a successful
        # compile. Backreferences and lookaround (unsupported by RE2) are
        # rejected here rather than silently degrading to a vulnerable engine.
        try:
            self.compile_pattern_sync(pattern)
        except re.error as exc:
            return False, f"Pattern rejected by RE2: {exc}"
        return True, "Pattern appears safe"

    async def batch_compile(
        self, patterns: list[str], validate: bool = True
    ) -> dict[str, re.Pattern]:
        compiled_patterns = {}
        for pattern in patterns:
            if validate:
                is_safe, reason = self.validate_pattern_safety(pattern)
                if not is_safe:
                    continue
            try:
                compiled_patterns[pattern] = await self.compile_pattern(pattern)
            except re.error:
                continue
        return compiled_patterns

    async def clear_cache(self) -> None:
        async with self._lock:
            self._compiled_cache.clear()
            self._cache_order.clear()
