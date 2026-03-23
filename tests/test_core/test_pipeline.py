from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from tests.conftest import MockGuardRequest, MockGuardResponse


class MockCheck(SecurityCheck):
    def __init__(self, middleware: Mock, name: str, should_block: bool = False) -> None:
        super().__init__(middleware)
        self._name = name
        self._should_block = should_block

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request):
        if self._should_block:
            return MockGuardResponse(content="Blocked", status_code=403)
        return None


class FailingCheck(SecurityCheck):
    def __init__(self, middleware: Mock, name: str = "failing_check") -> None:
        super().__init__(middleware)
        self._name = name

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request):
        raise ValueError("Check error")


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.fail_secure = False
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = AsyncMock(
        return_value=MockGuardResponse(content="Error", status_code=500)
    )
    return middleware


@pytest.fixture
def mock_req() -> MockGuardRequest:
    return MockGuardRequest(path="/test", method="GET")


class TestSecurityCheckPipeline:
    def test_pipeline_initialization(self, mock_middleware: Mock) -> None:
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])

        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check2"]

    @pytest.mark.asyncio
    async def test_execute_all_checks_pass(
        self, mock_middleware: Mock, mock_req: MockGuardRequest
    ) -> None:
        check1 = MockCheck(mock_middleware, "check1", should_block=False)
        check2 = MockCheck(mock_middleware, "check2", should_block=False)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = await pipeline.execute(mock_req)

        assert result is None

    @pytest.mark.asyncio
    async def test_execute_first_check_blocks(
        self, mock_middleware: Mock, mock_req: MockGuardRequest
    ) -> None:
        check1 = MockCheck(mock_middleware, "check1", should_block=True)
        check2 = MockCheck(mock_middleware, "check2", should_block=False)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = await pipeline.execute(mock_req)

        assert result is not None
        assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_execute_second_check_blocks(
        self, mock_middleware: Mock, mock_req: MockGuardRequest
    ) -> None:
        check1 = MockCheck(mock_middleware, "check1", should_block=False)
        check2 = MockCheck(mock_middleware, "check2", should_block=True)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = await pipeline.execute(mock_req)

        assert result is not None
        assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_execute_with_exception_fail_open(
        self, mock_middleware: Mock, mock_req: MockGuardRequest
    ) -> None:
        failing_check = FailingCheck(mock_middleware, "failing_check")
        passing_check = MockCheck(mock_middleware, "passing_check", should_block=False)

        mock_middleware.config.fail_secure = False

        pipeline = SecurityCheckPipeline([failing_check, passing_check])
        result = await pipeline.execute(mock_req)

        assert result is None

    @pytest.mark.asyncio
    async def test_execute_with_exception_fail_secure(
        self, mock_middleware: Mock, mock_req: MockGuardRequest
    ) -> None:
        failing_check = FailingCheck(mock_middleware, "failing_check")
        passing_check = MockCheck(mock_middleware, "passing_check", should_block=False)

        mock_middleware.config.fail_secure = True

        pipeline = SecurityCheckPipeline([failing_check, passing_check])
        result = await pipeline.execute(mock_req)

        assert result is not None
        assert result.status_code == 500

    def test_add_check(self, mock_middleware: Mock) -> None:
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1])
        assert len(pipeline) == 1

        pipeline.add_check(check2)
        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check2"]

    def test_insert_check(self, mock_middleware: Mock) -> None:
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")
        check3 = MockCheck(mock_middleware, "check3")

        pipeline = SecurityCheckPipeline([check1, check3])
        pipeline.insert_check(1, check2)

        assert len(pipeline) == 3
        assert pipeline.get_check_names() == ["check1", "check2", "check3"]

    def test_remove_check_found(self, mock_middleware: Mock) -> None:
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")
        check3 = MockCheck(mock_middleware, "check3")

        pipeline = SecurityCheckPipeline([check1, check2, check3])
        result = pipeline.remove_check("check2")

        assert result is True
        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check3"]

    def test_remove_check_not_found(self, mock_middleware: Mock) -> None:
        check1 = MockCheck(mock_middleware, "check1")

        pipeline = SecurityCheckPipeline([check1])
        result = pipeline.remove_check("nonexistent")

        assert result is False
        assert len(pipeline) == 1

    def test_repr(self, mock_middleware: Mock) -> None:
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])
        repr_str = repr(pipeline)

        assert "SecurityCheckPipeline" in repr_str
        assert "2 checks" in repr_str
        assert "check1" in repr_str
        assert "check2" in repr_str

    @pytest.mark.parametrize(
        "checks,expected_count",
        [
            ([], 0),
            (["check1"], 1),
            (["check1", "check2"], 2),
            (["check1", "check2", "check3"], 3),
        ],
    )
    def test_pipeline_various_sizes(
        self, mock_middleware: Mock, checks: list[str], expected_count: int
    ) -> None:
        check_objects: list[SecurityCheck] = [
            MockCheck(mock_middleware, name) for name in checks
        ]
        pipeline = SecurityCheckPipeline(check_objects)

        assert len(pipeline) == expected_count
        assert pipeline.get_check_names() == checks
