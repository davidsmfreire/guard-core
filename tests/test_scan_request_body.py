from typing import cast

from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import detect_penetration_attempt


class _FakeRequest:
    def __init__(self, body: bytes) -> None:
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.url_path = "/"
        self.method = "POST"
        self.client_host = "127.0.0.1"
        self.state = type("S", (), {})()
        self._body = body
        self.body_reads = 0

    async def body(self) -> bytes:
        self.body_reads += 1
        return self._body


async def test_body_scanned_by_default() -> None:
    request = _FakeRequest(b"<script>alert(1)</script>")

    result = await detect_penetration_attempt(
        cast(GuardRequest, request), SecurityConfig()
    )

    assert result.is_threat is True
    assert request.body_reads == 1


async def test_body_not_read_when_scanning_disabled() -> None:
    request = _FakeRequest(b"<script>alert(1)</script>")

    result = await detect_penetration_attempt(
        cast(GuardRequest, request), SecurityConfig(scan_request_body=False)
    )

    assert result.is_threat is False
    assert request.body_reads == 0


async def test_disabling_body_scan_keeps_query_scanning() -> None:
    request = _FakeRequest(b"")
    request.query_params = {"q": "<script>alert(1)</script>"}

    result = await detect_penetration_attempt(
        cast(GuardRequest, request), SecurityConfig(scan_request_body=False)
    )

    assert result.is_threat is True
    assert request.body_reads == 0
