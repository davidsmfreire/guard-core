---
title: Handlers
description: API reference for guard-core's handler classes including IPBanManager, RateLimitManager, CloudManager, and others
keywords: handlers, ip ban, rate limit, cloud, redis, security headers, guard-core
---

# Handlers

Guard-core handlers are singleton services that manage specific security subsystems. Each handler supports optional Redis and agent integration.

## IPBanManager

Manages banned IP addresses with a dual-layer cache (TTLCache + Redis).

::: guard_core.handlers.ipban_handler.IPBanManager

---

## RateLimitManager

Implements sliding window rate limiting with in-memory and Redis backends.

::: guard_core.handlers.ratelimit_handler.RateLimitManager

---

## CloudManager

Fetches and caches IP ranges for AWS, GCP, and Azure cloud providers.

::: guard_core.handlers.cloud_handler.CloudManager

---

## RedisManager

Provides namespaced Redis operations with connection management and fault tolerance.

::: guard_core.handlers.redis_handler.RedisManager

---

## SecurityHeadersManager

Applies HTTP security headers (CSP, HSTS, CORS, and defaults) to responses.

::: guard_core.handlers.security_headers_handler.SecurityHeadersManager

---

## BehaviorTracker

Tracks endpoint usage patterns and response patterns for behavioral analysis.

::: guard_core.handlers.behavior_handler.BehaviorTracker

---

## SusPatternsManager

Orchestrates the detection engine for threat pattern matching and semantic analysis.

::: guard_core.handlers.suspatterns_handler.SusPatternsManager
