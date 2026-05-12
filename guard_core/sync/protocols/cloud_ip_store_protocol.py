from collections.abc import Callable
from typing import Protocol, runtime_checkable

from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


@runtime_checkable
class SyncCloudIpStoreProtocol(Protocol):
    def get(self, provider: str) -> set[str] | None: ...

    def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None: ...

    def clear(self) -> None: ...


SyncCloudIpStoreFactory = Callable[[SyncRedisHandlerProtocol], SyncCloudIpStoreProtocol]
