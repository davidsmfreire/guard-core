# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-03-23

### Added

- Initial release of guard-core as the framework-agnostic security engine.
- Protocol layer: `GuardRequest`, `GuardResponse`, `GuardResponseFactory`, `GuardMiddlewareProtocol`.
- 17 security check implementations in `SecurityCheckPipeline`.
- Detection engine: `PatternCompiler`, `ContentPreprocessor`, `SemanticAnalyzer`, `PerformanceMonitor`.
- Handlers: `IPBanManager`, `RateLimitManager`, `RedisManager`, `CloudManager`, `SecurityHeadersManager`, `SusPatternsManager`, `BehaviorTracker`, `DynamicRuleManager`, `IPInfoManager`.
- `SecurityConfig` Pydantic model with full validation.
- Decorator system: `SecurityDecorator` with 6 mixin classes (`AccessControlMixin`, `AuthenticationMixin`, `RateLimitingMixin`, `BehavioralMixin`, `ContentFilteringMixin`, `AdvancedMixin`).
- Event system: `SecurityEventBus`, `MetricsCollector`.
- Dependency injection via context objects: `ResponseContext`, `RoutingContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`.
- `HandlerInitializer` for Redis and agent wiring.
- `GuardRedisError` exception replacing framework-specific HTTP exceptions.
- Full test suite: 892 tests, 100% coverage.
- Documentation: architecture guides, adapter development guides, engine internals, API reference.
- CI/CD: GitHub Actions workflows for testing, linting, release, CodeQL, scheduled lint, docs deployment.
- Code quality: ruff, mypy, vulture, bandit, safety, pip-audit, radon, xenon, deptry, pre-commit hooks.
