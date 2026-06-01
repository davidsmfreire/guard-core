import binascii
import unicodedata
from typing import Any

from guard_core.sync.detection_engine import safe_regex as re


class ContentPreprocessor:
    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ):
        self.max_content_length = max_content_length
        self.preserve_attack_patterns = preserve_attack_patterns
        self.agent_handler = agent_handler
        self.correlation_id = correlation_id

        self.attack_indicators = [
            r"<script",
            r"javascript:",
            r"on\w+=",
            r"SELECT\s+.{0,50}?\s+FROM",
            r"UNION\s+SELECT",
            r"\.\./",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"<\?php",
            r"<%",
            r"{{",
            r"{%",
            r"<iframe",
            r"<object",
            r"<embed",
            r"onerror\s*=",
            r"onload\s*=",
            r"\$\{",
            r"\\x[0-9a-fA-F]{2}",
            r"%[0-9a-fA-F]{2}",
        ]

        self.compiled_indicators = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.attack_indicators
        ]

    # RE2 has no lookaround; the token-boundary assertions that the base64 and
    # inner-comment patterns used are enforced in the substitution callbacks
    # below by inspecting the characters adjacent to each match.
    _BASE64_CHARS = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    _BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    _HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
    _UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
    _SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
    _SQL_LINE_COMMENT_RE = re.compile(r"(--|#)[^\n]*")

    def _send_preprocessor_event(
        self,
        event_type: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from datetime import datetime, timezone

            event = type(
                "SecurityEvent",
                (),
                {
                    "timestamp": datetime.now(timezone.utc),
                    "event_type": event_type,
                    "ip_address": "system",
                    "action_taken": action_taken,
                    "reason": reason,
                    "metadata": {
                        "component": "ContentPreprocessor",
                        "correlation_id": self.correlation_id,
                        **kwargs,
                    },
                },
            )()
            self.agent_handler.send_event(event)
        except Exception as e:
            import logging

            logging.getLogger("guard_core.sync.detection_engine").error(
                f"Failed to send preprocessor event to agent: {e}"
            )

    def normalize_unicode(self, content: str) -> str:
        normalized = unicodedata.normalize("NFKC", content)

        lookalikes = {
            "\u2044": "/",
            "\uff0f": "/",
            "\u29f8": "/",
            "\u0130": "I",
            "\u0131": "i",
            "\u200b": "",
            "\u200c": "",
            "\u200d": "",
            "\ufeff": "",
            "\u00ad": "",
            "\u034f": "",
            "\u180e": "",
            "\u2028": "\n",
            "\u2029": "\n",
            "\ue000": "",
            "\ufff0": "",
            "\u01c0": "|",
            "\u037e": ";",
            "\u2215": "/",
            "\u2216": "\\",
            "\uff1c": "<",
            "\uff1e": ">",
        }

        for char, replacement in lookalikes.items():
            normalized = normalized.replace(char, replacement)

        return normalized

    def remove_excessive_whitespace(self, content: str) -> str:
        content = re.sub(r"\s+", " ", content)
        content = content.strip()
        return content

    def extract_attack_regions(self, content: str) -> list[tuple[int, int]]:
        max_regions = min(100, self.max_content_length // 100)
        regions: list[tuple[int, int]] = []

        for indicator in self.compiled_indicators:
            for match in indicator.finditer(content):
                if len(regions) >= max_regions:
                    break
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)
                regions.append((start, end))

            if len(regions) >= max_regions:
                break

        if regions:
            regions.sort()
            merged = [regions[0]]
            for start, end in regions[1:]:
                if start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))
            return merged[:max_regions]

        return []

    def _extract_and_concatenate_attack_regions(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        result = ""
        remaining = self.max_content_length

        for start, end in attack_regions:
            chunk_len = min(end - start, remaining)
            result += content[start : start + chunk_len]
            remaining -= chunk_len
            if remaining <= 0:
                break

        return result

    def _build_result_with_attack_regions_and_context(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        attack_length = sum(end - start for start, end in attack_regions)
        gap_budget = self.max_content_length - attack_length
        result_parts: list[str] = []
        last_end = 0

        for start, end in attack_regions:
            if last_end < start and gap_budget > 0:
                chunk_len = min(start - last_end, gap_budget)
                result_parts.append(content[last_end : last_end + chunk_len])
                gap_budget -= chunk_len
            result_parts.append(content[start:end])
            last_end = end

        if last_end < len(content) and gap_budget > 0:
            tail_len = min(len(content) - last_end, gap_budget)
            result_parts.append(content[last_end : last_end + tail_len])

        return "".join(result_parts)

    def truncate_safely(self, content: str) -> str:
        if len(content) <= self.max_content_length:
            return content

        if not self.preserve_attack_patterns:
            return content[: self.max_content_length]

        attack_regions = self.extract_attack_regions(content)

        if not attack_regions:
            return content[: self.max_content_length]

        attack_length = sum(end - start for start, end in attack_regions)

        if attack_length >= self.max_content_length:
            return self._extract_and_concatenate_attack_regions(content, attack_regions)

        return self._build_result_with_attack_regions_and_context(
            content, attack_regions
        )

    def remove_null_bytes(self, content: str) -> str:
        content = content.replace("\x00", "")

        control_chars = "".join(chr(i) for i in range(32) if i not in (9, 10, 13))
        translator = str.maketrans("", "", control_chars)
        return content.translate(translator)

    def _decode_base64_candidates(self, content: str) -> str:
        import base64

        def _replace(match: re.Match) -> str:
            start, end = match.start(), match.end()
            text = match.string
            if start > 0 and text[start - 1] in self._BASE64_CHARS:
                return match.group(0)
            if end < len(text) and text[end] in self._BASE64_CHARS | {"="}:
                return match.group(0)
            token = match.group(0)
            padding = (4 - len(token) % 4) % 4
            padded = token + "=" * padding
            try:
                decoded = base64.b64decode(padded, validate=True).decode(
                    "utf-8", errors="ignore"
                )
            except (ValueError, binascii.Error):
                return token
            if decoded and any(c.isprintable() for c in decoded):
                return decoded
            return token

        return self._BASE64_RE.sub(_replace, content)

    def _decode_hex_escapes(self, content: str) -> str:
        def _replace(match: re.Match) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        return self._HEX_ESCAPE_RE.sub(_replace, content)

    def _decode_unicode_escapes(self, content: str) -> str:
        def _replace(match: re.Match) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        return self._UNICODE_ESCAPE_RE.sub(_replace, content)

    def _strip_sql_comments(self, content: str) -> str:
        def _replace_block(match: re.Match) -> str:
            start, end = match.start(), match.end()
            text = match.string
            prev = text[start - 1] if start > 0 else ""
            nxt = text[end] if end < len(text) else ""
            # Join the surrounding tokens when a comment is wedged between two
            # same-case letters (e.g. SE/**/LECT, un/**/ion) - a classic SQL
            # keyword-splitting evasion. Otherwise collapse to a single space.
            if prev.isalpha() and nxt.isalpha() and prev.isupper() == nxt.isupper():
                return ""
            return " "

        content = self._SQL_BLOCK_COMMENT_RE.sub(_replace_block, content)
        content = self._SQL_LINE_COMMENT_RE.sub(" ", content)
        return content

    def decode_common_encodings(self, content: str) -> str:
        max_decode_iterations = 7
        iterations = 0

        while iterations < max_decode_iterations:
            original = content

            try:
                import urllib.parse

                decoded = urllib.parse.unquote(content, errors="ignore")
                if decoded != content:
                    content = decoded
            except Exception as e:
                self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to URL decode content",
                    error=str(e),
                    error_type="url_decode",
                )

            try:
                import html

                decoded = html.unescape(content)
                if decoded != content:
                    content = decoded
            except Exception as e:
                self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to HTML decode content",
                    error=str(e),
                    error_type="html_decode",
                )

            content = self._decode_hex_escapes(content)
            content = self._decode_unicode_escapes(content)
            content = self._decode_base64_candidates(content)

            if content == original:
                break

            iterations += 1

        content = self._strip_sql_comments(content)
        return content

    def preprocess(self, content: str) -> str:
        if not content:
            return ""

        content = self.normalize_unicode(content)
        content = self.decode_common_encodings(content)
        content = self.remove_null_bytes(content)
        content = self.remove_excessive_whitespace(content)
        content = self.truncate_safely(content)

        return content

    def preprocess_batch(self, contents: list[str]) -> list[str]:
        return [self.preprocess(content) for content in contents]
