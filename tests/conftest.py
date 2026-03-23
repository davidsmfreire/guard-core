import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


class MockState:
    def __init__(self) -> None:
        self._attrs: dict = {}

    def __getattr__(self, name: str) -> object:
        if name == "_attrs":
            return super().__getattribute__(name)
        return self._attrs.get(name)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_attrs":
            super().__setattr__(name, value)
        else:
            self._attrs[name] = value


class MockGuardRequest:
    def __init__(
        self,
        path: str = "/",
        method: str = "GET",
        headers: dict | None = None,
        client_host: str | None = "127.0.0.1",
        scheme: str = "https",
        query_params: dict | None = None,
        body_content: bytes = b"",
        scope: dict | None = None,
    ) -> None:
        self._path = path
        self._method = method
        self._headers = headers or {}
        self._client_host = client_host
        self._scheme = scheme
        self._query_params = query_params or {}
        self._body = body_content
        self._state = MockState()
        self._scope = scope or {}

    @property
    def url_path(self) -> str:
        return self._path

    @property
    def url_scheme(self) -> str:
        return self._scheme

    @property
    def url_full(self) -> str:
        return f"{self._scheme}://test{self._path}"

    def url_replace_scheme(self, scheme: str) -> str:
        return f"{scheme}://test{self._path}"

    @property
    def method(self) -> str:
        return self._method

    @property
    def client_host(self) -> str | None:
        return self._client_host

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def query_params(self) -> dict:
        return self._query_params

    async def body(self) -> bytes:
        return self._body

    @property
    def state(self) -> MockState:
        return self._state

    @property
    def scope(self) -> dict:
        return self._scope


class MockGuardResponse:
    def __init__(
        self,
        content: str = "",
        status_code: int = 200,
        headers: dict | None = None,
    ) -> None:
        self._status_code = status_code
        self._headers = headers or {}
        self._body = content.encode() if isinstance(content, str) else content

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def body(self) -> bytes:
        return self._body


class MockGuardResponseFactory:
    def create_response(self, content: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(content, status_code)

    def create_redirect_response(self, url: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(f"Redirect to {url}", status_code, {"Location": url})


@pytest.fixture
def mock_request() -> MockGuardRequest:
    return MockGuardRequest()


@pytest.fixture
def mock_response() -> MockGuardResponse:
    return MockGuardResponse()


@pytest.fixture
def mock_response_factory() -> MockGuardResponseFactory:
    return MockGuardResponseFactory()


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)


@pytest.fixture(autouse=True)
def cleanup_ipban_singleton() -> None:
    IPBanManager._instance = None
    yield  # type: ignore
    IPBanManager._instance = None


@pytest.fixture(autouse=True)
def cleanup_suspatterns_singleton() -> None:
    SusPatternsManager._instance = None
    yield  # type: ignore
    SusPatternsManager._instance = None


@pytest.fixture(autouse=True)
def reset_headers_manager() -> None:
    SecurityHeadersManager._instance = None
    yield  # type: ignore
    SecurityHeadersManager._instance = None
