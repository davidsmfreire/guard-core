from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse, GuardResponseFactory
from tests.conftest import MockGuardRequest, MockGuardResponse, MockGuardResponseFactory


def test_mock_request_satisfies_protocol():
    request = MockGuardRequest(path="/test", method="POST", client_host="10.0.0.1")
    assert isinstance(request, GuardRequest)
    assert request.url_path == "/test"
    assert request.method == "POST"
    assert request.client_host == "10.0.0.1"
    assert request.url_scheme == "https"
    assert "test" in request.url_full
    assert request.url_replace_scheme("http").startswith("http://")


def test_mock_response_satisfies_protocol():
    response = MockGuardResponse("OK", 200)
    assert isinstance(response, GuardResponse)
    assert response.status_code == 200
    assert response.body == b"OK"


def test_mock_response_factory_satisfies_protocol():
    factory = MockGuardResponseFactory()
    assert isinstance(factory, GuardResponseFactory)

    response = factory.create_response("error", 403)
    assert response.status_code == 403
    assert response.body == b"error"

    redirect = factory.create_redirect_response("https://example.com", 301)
    assert redirect.status_code == 301
    assert redirect.headers["Location"] == "https://example.com"


def test_request_state_is_mutable():
    request = MockGuardRequest()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = {"test": True}
    assert request.state.client_ip == "1.2.3.4"
    assert request.state.route_config == {"test": True}


def test_request_without_client():
    request = MockGuardRequest(client_host=None)
    assert request.client_host is None


async def test_request_body():
    request = MockGuardRequest(body_content=b'{"key": "value"}')
    body = await request.body()
    assert body == b'{"key": "value"}'
