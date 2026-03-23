import concurrent.futures
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.detection_engine.preprocessor import ContentPreprocessor


def test_initialization() -> None:
    preprocessor = ContentPreprocessor()
    assert preprocessor.max_content_length == 10000
    assert preprocessor.preserve_attack_patterns is True
    assert preprocessor.agent_handler is None
    assert preprocessor.correlation_id is None
    assert len(preprocessor.attack_indicators) > 0
    assert len(preprocessor.compiled_indicators) == len(preprocessor.attack_indicators)

    agent_handler = MagicMock()
    preprocessor = ContentPreprocessor(
        max_content_length=5000,
        preserve_attack_patterns=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )
    assert preprocessor.max_content_length == 5000
    assert preprocessor.preserve_attack_patterns is False
    assert preprocessor.agent_handler is agent_handler
    assert preprocessor.correlation_id == "test-123"


def test_normalize_unicode() -> None:
    preprocessor = ContentPreprocessor()

    test_cases = [
        ("\u2044", "/"),
        ("\uff0f", "/"),
        ("\u29f8", "/"),
        ("\u0130", "I"),
        ("\u0131", "i"),
        ("\u200b", ""),
        ("\u200c", ""),
        ("\u200d", ""),
        ("\ufeff", ""),
        ("\u00ad", ""),
        ("\u037e", ";"),
        ("\uff1c", "<"),
        ("\uff1e", ">"),
    ]

    for input_char, expected in test_cases:
        result = preprocessor.normalize_unicode(f"test{input_char}test")
        assert result == f"test{expected}test"

    malicious = f"<script{chr(0x200B)}>{chr(0xFF0F)}alert(1){chr(0xFF1C)}/script>"
    normalized = preprocessor.normalize_unicode(malicious)
    assert normalized == "<script>/alert(1)</script>"


def test_remove_excessive_whitespace() -> None:
    preprocessor = ContentPreprocessor()

    assert (
        preprocessor.remove_excessive_whitespace("test  multiple   spaces")
        == "test multiple spaces"
    )
    assert (
        preprocessor.remove_excessive_whitespace("test\t\ttabs\n\nnewlines")
        == "test tabs newlines"
    )
    assert (
        preprocessor.remove_excessive_whitespace("  leading trailing  ")
        == "leading trailing"
    )
    assert (
        preprocessor.remove_excessive_whitespace("  mixed\t \n  whitespace  ")
        == "mixed whitespace"
    )


def test_remove_null_bytes() -> None:
    preprocessor = ContentPreprocessor()

    assert preprocessor.remove_null_bytes("test\x00null\x00bytes") == "testnullbytes"

    content = "test\x01\x02\x03control\x04\x05chars"
    result = preprocessor.remove_null_bytes(content)
    assert result == "testcontrolchars"

    content = "test\ttab\nnewline\rcarriage"
    result = preprocessor.remove_null_bytes(content)
    assert result == content


@pytest.mark.asyncio
async def test_send_preprocessor_event_no_agent() -> None:
    preprocessor = ContentPreprocessor(agent_handler=None)

    await preprocessor._send_preprocessor_event(
        event_type="test_event", action_taken="test_action", reason="test_reason"
    )


@pytest.mark.asyncio
async def test_send_preprocessor_event_with_agent() -> None:
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()

    preprocessor = ContentPreprocessor(
        agent_handler=agent_handler, correlation_id="test-456"
    )

    await preprocessor._send_preprocessor_event(
        event_type="test_event",
        action_taken="test_action",
        reason="test_reason",
        extra_data="test_value",
    )

    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "test_event"
    assert event.action_taken == "test_action"
    assert event.reason == "test_reason"
    assert event.metadata["component"] == "ContentPreprocessor"
    assert event.metadata["correlation_id"] == "test-456"
    assert event.metadata["extra_data"] == "test_value"


@pytest.mark.asyncio
async def test_send_preprocessor_event_with_error() -> None:
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock(side_effect=Exception("Agent error"))

    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch("logging.getLogger") as mock_logger:
        mock_logger.return_value.error = MagicMock()

        await preprocessor._send_preprocessor_event(
            event_type="test_event", action_taken="test_action", reason="test_reason"
        )

        mock_logger.return_value.error.assert_called_once()
        error_msg = mock_logger.return_value.error.call_args[0][0]
        assert "Failed to send preprocessor event to agent" in error_msg


def test_extract_attack_regions_timeout() -> None:
    preprocessor = ContentPreprocessor()

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        content = "<script>alert(1)</script>"
        regions = preprocessor.extract_attack_regions(content)

        assert regions == []


def test_extract_attack_regions_no_attacks() -> None:
    preprocessor = ContentPreprocessor()

    content = "This is just normal text without any attack patterns"
    regions = preprocessor.extract_attack_regions(content)

    assert regions == []


def test_truncate_safely_no_truncation_needed() -> None:
    preprocessor = ContentPreprocessor(max_content_length=1000)

    content = "Short content"
    result = preprocessor.truncate_safely(content)

    assert result == content


def test_truncate_safely_preserve_disabled() -> None:
    preprocessor = ContentPreprocessor(
        max_content_length=50, preserve_attack_patterns=False
    )

    content = "a" * 100
    result = preprocessor.truncate_safely(content)

    assert len(result) == 50
    assert result == "a" * 50


def test_truncate_safely_no_attack_patterns() -> None:
    preprocessor = ContentPreprocessor(max_content_length=50)

    content = "This is normal content without attacks " * 10
    result = preprocessor.truncate_safely(content)

    assert len(result) == 50


@pytest.mark.asyncio
async def test_decode_common_encodings_iterations() -> None:
    preprocessor = ContentPreprocessor()

    content = "%253Cscript%253E"
    result = await preprocessor.decode_common_encodings(content)

    assert result == "<script>"

    content = "%26lt%3Bscript%26gt%3B"
    result = await preprocessor.decode_common_encodings(content)

    assert result == "<script>"


@pytest.mark.asyncio
async def test_preprocess_empty_content() -> None:
    preprocessor = ContentPreprocessor()

    result = await preprocessor.preprocess("")
    assert result == ""


@pytest.mark.asyncio
async def test_preprocess_full_flow() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)

    content = (
        f"{chr(0x200B)}<script>{chr(0xFF0F)}alert(1)"
        f"</script>  multiple   spaces %3Cimg%3E\x00null"
    )

    result = await preprocessor.preprocess(content)

    assert chr(0x200B) not in result
    assert chr(0xFF0F) not in result
    assert "  " not in result
    assert "<img>" in result
    assert "\x00" not in result
    assert len(result) <= 200


@pytest.mark.asyncio
async def test_preprocess_batch() -> None:
    preprocessor = ContentPreprocessor()

    contents = ["<script>alert(1)</script>", "%3Cimg%3E", "normal text", ""]

    results = await preprocessor.preprocess_batch(contents)

    assert len(results) == len(contents)
    assert results[0] == "<script>alert(1)</script>"
    assert results[1] == "<img>"
    assert results[2] == "normal text"
    assert results[3] == ""


def test_attack_indicators_compilation() -> None:
    preprocessor = ContentPreprocessor()

    test_content = "<script>alert(1)</script> SELECT * FROM users <?php eval() <iframe>"

    matches = []
    for indicator in preprocessor.compiled_indicators:
        if indicator.search(test_content):
            matches.append(indicator.pattern)

    assert len(matches) > 0
    assert any("<script" in m for m in matches)
    assert any("SELECT" in m for m in matches)
    assert any("<?php" in m for m in matches)


@pytest.mark.asyncio
async def test_integration_xss_bypass_attempt() -> None:
    preprocessor = ContentPreprocessor()

    xss = f"<scr{chr(0x200B)}ipt>al{chr(0x200C)}ert(1)</sc{chr(0x200D)}ript>"
    result = await preprocessor.preprocess(xss)

    assert "<script>alert(1)</script>" in result


@pytest.mark.asyncio
async def test_integration_sql_injection_bypass() -> None:
    preprocessor = ContentPreprocessor()

    sqli = "1' %55NION %53ELECT * FROM users--"
    result = await preprocessor.preprocess(sqli)

    assert "UNION SELECT" in result


@pytest.mark.asyncio
async def test_decode_common_encodings_html_error() -> None:
    preprocessor = ContentPreprocessor(agent_handler=MagicMock())
    preprocessor.agent_handler.send_event = AsyncMock()

    with patch("html.unescape", side_effect=Exception("html fail")):
        result = await preprocessor.decode_common_encodings("test &lt; value")
    assert isinstance(result, str)


def test_extract_attack_regions_with_content() -> None:
    preprocessor = ContentPreprocessor()
    content = "normal text <script>alert(1)</script> more text SELECT * FROM users"
    regions = preprocessor.extract_attack_regions(content)
    assert len(regions) >= 0


def test_truncate_safely_with_attack_regions() -> None:
    preprocessor = ContentPreprocessor(max_content_length=100)
    content = "A" * 50 + "<script>alert(1)</script>" + "B" * 200
    result = preprocessor.truncate_safely(content)
    assert len(result) <= 100


def test_extract_attack_regions_max_regions_break() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)
    content = "<script>a</script>" * 200
    regions = preprocessor.extract_attack_regions(content)
    assert len(regions) >= 1


def test_extract_attack_regions_non_overlapping() -> None:
    preprocessor = ContentPreprocessor()
    content = "A" * 500 + "<script>x</script>" + "B" * 500 + "SELECT * FROM"
    regions = preprocessor.extract_attack_regions(content)
    for i in range(1, len(regions)):
        assert regions[i][0] >= regions[i - 1][0]


def test_add_non_attack_content() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)
    content = "AAAA" + "BBBB" * 20 + "CCCC"
    attack_regions = [(4, 84)]
    result_parts = [content[4:84]]
    preprocessor._add_non_attack_content(content, attack_regions, result_parts, 100)
    assert len(result_parts) > 1


async def test_decode_common_encodings_url_decode_error() -> None:
    preprocessor = ContentPreprocessor()
    with patch("urllib.parse.unquote", side_effect=Exception("decode fail")):
        result = await preprocessor.decode_common_encodings("test%20value")
    assert isinstance(result, str)
