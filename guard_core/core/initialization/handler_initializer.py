from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


class HandlerInitializer:
    def __init__(
        self,
        config: "SecurityConfig",
        redis_handler: Any = None,
        agent_handler: Any = None,
        geo_ip_handler: Any = None,
        rate_limit_handler: Any = None,
        guard_decorator: Any = None,
    ):
        self.config = config
        self.redis_handler = redis_handler
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        self.rate_limit_handler = rate_limit_handler
        self.guard_decorator = guard_decorator

    async def initialize_redis_handlers(self) -> None:
        if not (self.config.enable_redis and self.redis_handler):
            return

        await self.redis_handler.initialize()

        from guard_core.handlers.cloud_handler import cloud_handler
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        if self.config.block_cloud_providers:
            await cloud_handler.initialize_redis(
                self.redis_handler,
                self.config.block_cloud_providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )

        await ip_ban_manager.initialize_redis(self.redis_handler)
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_redis(self.redis_handler)
        await sus_patterns_handler.initialize_redis(self.redis_handler)

    async def initialize_agent_for_handlers(self) -> None:
        if not self.agent_handler:
            return

        from guard_core.handlers.cloud_handler import cloud_handler
        from guard_core.handlers.ipban_handler import ip_ban_manager
        from guard_core.handlers.suspatterns_handler import sus_patterns_handler

        await ip_ban_manager.initialize_agent(self.agent_handler)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_agent(self.agent_handler)
        await sus_patterns_handler.initialize_agent(self.agent_handler)

        if self.config.block_cloud_providers:
            await cloud_handler.initialize_agent(self.agent_handler)

        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            await self.geo_ip_handler.initialize_agent(self.agent_handler)

    async def initialize_dynamic_rule_manager(self) -> None:
        if not (self.agent_handler and self.config.enable_dynamic_rules):
            return

        from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        await dynamic_rule_manager.initialize_agent(self.agent_handler)

        if self.redis_handler:
            await dynamic_rule_manager.initialize_redis(self.redis_handler)

    async def initialize_agent_integrations(self) -> None:
        if not self.agent_handler:
            return

        await self.agent_handler.start()

        if self.redis_handler:
            await self.agent_handler.initialize_redis(self.redis_handler)
            await self.redis_handler.initialize_agent(self.agent_handler)

        await self.initialize_agent_for_handlers()

        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            await self.guard_decorator.initialize_agent(self.agent_handler)

        await self.initialize_dynamic_rule_manager()
