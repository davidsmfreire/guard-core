import pytest

from guard_core.decorators import SecurityDecorator
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.models import SecurityConfig


@pytest.fixture
def decorator():
    config = SecurityConfig(enable_redis=False)
    return SecurityDecorator(config)


def _dummy_endpoint():
    pass


def _another_endpoint():
    pass


class TestAccessControlMixin:
    def test_require_ip_whitelist(self, decorator):
        decorator.require_ip(whitelist=["10.0.0.1"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.ip_whitelist == ["10.0.0.1"]

    def test_require_ip_blacklist(self, decorator):
        decorator.require_ip(blacklist=["10.0.0.2"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.ip_blacklist == ["10.0.0.2"]

    def test_require_ip_both(self, decorator):
        decorator.require_ip(whitelist=["1.1.1.1"], blacklist=["2.2.2.2"])(
            _dummy_endpoint
        )
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.ip_whitelist == ["1.1.1.1"]
        assert rc.ip_blacklist == ["2.2.2.2"]

    def test_require_ip_no_args(self, decorator):
        decorator.require_ip()(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.ip_whitelist is None
        assert rc.ip_blacklist is None

    def test_block_countries(self, decorator):
        decorator.block_countries(["US", "CN"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.blocked_countries == ["US", "CN"]

    def test_allow_countries(self, decorator):
        decorator.allow_countries(["GB", "DE"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.whitelist_countries == ["GB", "DE"]

    def test_block_clouds_default(self, decorator):
        decorator.block_clouds()(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.block_cloud_providers == {"AWS", "GCP", "Azure"}

    def test_block_clouds_specific(self, decorator):
        decorator.block_clouds(["AWS"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.block_cloud_providers == {"AWS"}

    def test_bypass(self, decorator):
        decorator.bypass(["rate_limit", "ip_check"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert "rate_limit" in rc.bypassed_checks
        assert "ip_check" in rc.bypassed_checks


class TestAuthenticationMixin:
    def test_require_https(self, decorator):
        decorator.require_https()(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.require_https is True

    def test_require_auth_default(self, decorator):
        decorator.require_auth()(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.auth_required == "bearer"

    def test_require_auth_custom(self, decorator):
        decorator.require_auth(type="basic")(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.auth_required == "basic"

    def test_api_key_auth_default(self, decorator):
        decorator.api_key_auth()(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.api_key_required is True
        assert rc.required_headers["X-API-Key"] == "required"

    def test_api_key_auth_custom_header(self, decorator):
        decorator.api_key_auth(header_name="X-Custom-Key")(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.api_key_required is True
        assert rc.required_headers["X-Custom-Key"] == "required"

    def test_require_headers(self, decorator):
        decorator.require_headers(
            {"X-Request-ID": "required", "Accept": "application/json"}
        )(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.required_headers["X-Request-ID"] == "required"
        assert rc.required_headers["Accept"] == "application/json"


class TestBehavioralMixin:
    def test_usage_monitor(self, decorator):
        decorator.usage_monitor(max_calls=100, window=60)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert len(rc.behavior_rules) == 1
        rule = rc.behavior_rules[0]
        assert rule.rule_type == "usage"
        assert rule.threshold == 100
        assert rule.window == 60
        assert rule.action == "ban"

    def test_usage_monitor_defaults(self, decorator):
        decorator.usage_monitor(max_calls=50)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        rule = rc.behavior_rules[0]
        assert rule.window == 3600
        assert rule.action == "ban"

    def test_return_monitor(self, decorator):
        decorator.return_monitor(
            pattern="error", max_occurrences=5, window=120, action="log"
        )(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert len(rc.behavior_rules) == 1
        rule = rc.behavior_rules[0]
        assert rule.rule_type == "return_pattern"
        assert rule.threshold == 5
        assert rule.window == 120
        assert rule.pattern == "error"
        assert rule.action == "log"

    def test_behavior_analysis(self, decorator):
        rules = [
            BehaviorRule(rule_type="usage", threshold=10),
            BehaviorRule(rule_type="frequency", threshold=20),
        ]
        decorator.behavior_analysis(rules)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert len(rc.behavior_rules) == 2

    def test_suspicious_frequency(self, decorator):
        decorator.suspicious_frequency(
            max_frequency=2.0, window=300, action="throttle"
        )(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        rule = rc.behavior_rules[0]
        assert rule.rule_type == "frequency"
        assert rule.threshold == int(2.0 * 300)
        assert rule.window == 300
        assert rule.action == "throttle"


class TestContentFilteringMixin:
    def test_block_user_agents(self, decorator):
        decorator.block_user_agents(["bot", "crawler"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert "bot" in rc.blocked_user_agents
        assert "crawler" in rc.blocked_user_agents

    def test_content_type_filter(self, decorator):
        decorator.content_type_filter(["application/json"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.allowed_content_types == ["application/json"]

    def test_max_request_size(self, decorator):
        decorator.max_request_size(1024)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.max_request_size == 1024

    def test_require_referrer(self, decorator):
        decorator.require_referrer(["example.com"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.require_referrer == ["example.com"]

    def test_custom_validation(self, decorator):
        async def my_validator(request):
            return None

        decorator.custom_validation(my_validator)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert my_validator in rc.custom_validators


class TestRateLimitingMixin:
    def test_rate_limit(self, decorator):
        decorator.rate_limit(requests=100, window=30)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.rate_limit == 100
        assert rc.rate_limit_window == 30

    def test_rate_limit_default_window(self, decorator):
        decorator.rate_limit(requests=50)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.rate_limit == 50
        assert rc.rate_limit_window == 60

    def test_geo_rate_limit(self, decorator):
        limits = {"US": (100, 60), "CN": (50, 60)}
        decorator.geo_rate_limit(limits)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.geo_rate_limits == limits


class TestAdvancedMixin:
    def test_time_window(self, decorator):
        decorator.time_window("09:00", "17:00", timezone="US/Eastern")(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.time_restrictions == {
            "start": "09:00",
            "end": "17:00",
            "timezone": "US/Eastern",
        }

    def test_time_window_default_timezone(self, decorator):
        decorator.time_window("08:00", "20:00")(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.time_restrictions["timezone"] == "UTC"

    def test_suspicious_detection_enabled(self, decorator):
        decorator.suspicious_detection(enabled=True)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.enable_suspicious_detection is True

    def test_suspicious_detection_disabled(self, decorator):
        decorator.suspicious_detection(enabled=False)(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.enable_suspicious_detection is False

    @pytest.mark.asyncio
    async def test_honeypot_detection_json_trap_filled(self, decorator):
        import json

        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["honeypot"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert len(rc.custom_validators) == 1

        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "application/json"},
            body_content=json.dumps({"honeypot": "gotcha"}).encode(),
        )
        result = await rc.custom_validators[0](request)
        assert result is not None
        assert result.status_code == 403
        assert isinstance(result.headers, dict)
        assert isinstance(result.body, bytes)

    @pytest.mark.asyncio
    async def test_honeypot_detection_json_no_trap(self, decorator):
        import json

        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["honeypot"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)

        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "application/json"},
            body_content=json.dumps({"name": "legit"}).encode(),
        )
        result = await rc.custom_validators[0](request)
        assert result is None

    @pytest.mark.asyncio
    async def test_honeypot_detection_form_trap_filled(self, decorator):
        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["trap_field"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)

        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body_content=b"trap_field=filled&name=test",
        )
        result = await rc.custom_validators[0](request)
        assert result is not None
        assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_honeypot_detection_get_request_skipped(self, decorator):
        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["honeypot"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)

        request = MockGuardRequest(method="GET")
        result = await rc.custom_validators[0](request)
        assert result is None

    @pytest.mark.asyncio
    async def test_honeypot_detection_unknown_content_type(self, decorator):
        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["honeypot"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)

        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "text/plain"},
            body_content=b"honeypot=filled",
        )
        result = await rc.custom_validators[0](request)
        assert result is None

    @pytest.mark.asyncio
    async def test_honeypot_detection_form_body_decode_error(self, decorator):
        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["trap"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)

        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body_content=b"",
        )

        async def bad_body():
            raise Exception("decode error")

        request.body = bad_body
        result = await rc.custom_validators[0](request)
        assert result is None

    @pytest.mark.asyncio
    async def test_honeypot_detection_json_body_decode_error(self, decorator):
        from tests.conftest import MockGuardRequest

        decorator.honeypot_detection(trap_fields=["trap"])(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)

        request = MockGuardRequest(
            method="POST",
            headers={"content-type": "application/json"},
            body_content=b"",
        )

        async def bad_body():
            raise Exception("decode error")

        request.body = bad_body
        result = await rc.custom_validators[0](request)
        assert result is None


class TestDecoratorChaining:
    def test_multiple_decorators_on_same_function(self, decorator):
        decorator.rate_limit(requests=100)(_dummy_endpoint)
        decorator.require_https()(_dummy_endpoint)
        route_id = decorator._get_route_id(_dummy_endpoint)
        rc = decorator.get_route_config(route_id)
        assert rc.rate_limit == 100
        assert rc.require_https is True

    def test_guard_route_id_attribute(self, decorator):
        decorated = decorator.rate_limit(requests=10)(_dummy_endpoint)
        assert hasattr(decorated, "_guard_route_id")
