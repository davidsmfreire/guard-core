---

title: Cloud IP Store
description: API reference for CloudIpStoreProtocol, InMemoryCloudIpStore, and RedisCloudIpStore
keywords: cloud ip store, redis, in-memory, cloud manager, guard-core
---

Cloud IP Store
==============

`CloudIpStoreProtocol` defines the pluggable backend for cached cloud-provider IP ranges. Guard-core ships two concrete implementations — `InMemoryCloudIpStore` and `RedisCloudIpStore` — and the active store can be swapped via `SecurityConfig.cloud_ip_store`.

___

CloudIpStoreProtocol
--------------------

**Location**: `guard_core/protocols/cloud_ip_store_protocol.py`

```python
from typing import Protocol, runtime_checkable


@runtime_checkable
class CloudIpStoreProtocol(Protocol):
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...
    async def clear(self) -> None: ...
```

| Method                          | Description                                                                          |
|---------------------------------|--------------------------------------------------------------------------------------|
| `get(provider)`                 | Return the cached CIDR set for the provider, or `None` if absent.                    |
| `set(provider, ranges, ttl=)`   | Cache the CIDR set for the provider. `ttl` is honored by stores that support it.     |
| `clear()`                       | Drop all cached entries.                                                             |

A sync mirror lives at `guard_core/sync/protocols/cloud_ip_store_protocol.py` as `SyncCloudIpStoreProtocol`.

___

InMemoryCloudIpStore
--------------------

**Location**: `guard_core/handlers/cloud_ip_stores.py`

```python
class InMemoryCloudIpStore:
    def __init__(self) -> None: ...
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None: ...
    async def clear(self) -> None: ...
```

Process-local dictionary backed store. The `ttl` argument is accepted for protocol compatibility but is not enforced. This is the default store when no Redis is configured.

___

RedisCloudIpStore
-----------------

**Location**: `guard_core/handlers/cloud_ip_stores.py`

```python
class RedisCloudIpStore:
    def __init__(
        self,
        redis_handler: RedisHandlerProtocol,
        key_prefix: str = "guard:cloud_ip",
    ) -> None: ...
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None: ...
    async def clear(self) -> None: ...
```

Redis-backed store. Each provider's CIDR set is JSON-encoded as a sorted list and written under `guard:cloud_ip:<provider>`. `set()` honors the optional `ttl`. `clear()` removes every key under the configured prefix.

___

When to swap stores
-------------------

- **Default** — leave `SecurityConfig.cloud_ip_store=None`. Guard-core uses `InMemoryCloudIpStore`.
- **Auto-upgrade to Redis** — when Redis is enabled (`enable_redis=True` and a `RedisManager` is wired through `HandlerInitializer`), the cloud manager transparently uses Redis-backed caching via the configured prefix.
- **Explicit override** — for horizontally-scaled deployments that want every instance reading from a single pre-populated namespace (or to use a custom backend like an SQL store), pass an explicit store:

```python
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

redis = RedisManager(SecurityConfig())
config = SecurityConfig(
    cloud_ip_store=RedisCloudIpStore(redis, key_prefix="guard:cloud_ip"),
)
```

When `cloud_ip_store` is explicit, the `HandlerInitializer.initialize_redis_handlers()` path wires it into `cloud_handler.set_store(...)` after Redis bootstrap. Lazy bootstrap (`lazy_init=True`) defers the first cloud-IP fetch until the first request that needs it.

___

Redis namespace migration
-------------------------

The v2.0.0 release moved the cloud-IP cache from the legacy `cloud_ranges` namespace (comma-separated CSV values per provider) to `guard:cloud_ip` (JSON-encoded sorted list per provider).

- **Default writers** — `RedisCloudIpStore` writes to `guard:cloud_ip:<provider>`.
- **Legacy reader** — when `CloudManager._store is None` (no `cloud_ip_store` configured and Redis is not auto-wired), the legacy CSV path under `cloud_ranges` is still reachable, but the default and the Redis store both use the new namespace.

Any ops tooling, dashboards, or sidecars reading those Redis keys directly must switch to the new namespace.

___

See also
--------

- [SecurityConfig - IP Lifecycle Controls](../configuration/security-config.md#ip-lifecycle-controls)
- [Internals - Cloud Providers](../internals/cloud-providers.md)
