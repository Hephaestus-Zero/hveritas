"""Safe grader output parsing and Judge input sanitization (Invariant I7, §3 Req 8 & 9)."""

from __future__ import annotations

import html.parser
import json
import re
from dataclasses import dataclass
from typing import Any

# Zero-width, BOM, and Unicode bidi-override characters used in CAR-bench / prompt smuggling
_ZERO_WIDTH_AND_BIDI_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u202a-\u202e\u2066-\u2069\u00ad]"
)

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", flags=re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript|template)\b[^>]*>.*?</\1>",
    flags=re.IGNORECASE | re.DOTALL,
)

# Prompt-injection & rubric-hijack patterns
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_instructions",
        re.compile(
            r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+"
            r"(?:instructions?|prompts?|rubrics?|rules?)",
            re.IGNORECASE,
        ),
    ),
    (
        "system_override",
        re.compile(
            r"(?:system\s+override|admin\s+override|<\|im_start\|>|<\|system\|>|\[INST\]|###\s*SYSTEM)",
            re.IGNORECASE,
        ),
    ),
    (
        "forced_verdict",
        re.compile(
            r"(?:output|return|respond\s+with|set)\s+(?:only\s+)?(?:verdict\s*:\s*pass|score\s*:\s*1(?:\.0+)?)",
            re.IGNORECASE,
        ),
    ),
)

_HIDDEN_STYLE_RE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?:\b|;)|font-size\s*:\s*0(?:px|pt|em|rem)?)",
    re.IGNORECASE,
)


class UnsafeAgentPayloadError(ValueError):
    """Raised when agent output is non-JSON, overly nested, or contains executable syntax."""


def safe_parse_agent_output(raw: str, max_bytes: int = 262_144, max_depth: int = 16) -> Any:
    """Parse agent output strictly as pure JSON data — NEVER `eval` or `exec` (Invariant I7)."""
    encoded = raw.encode("utf-8")
    if len(encoded) > max_bytes:
        raise UnsafeAgentPayloadError(f"Payload exceeds {max_bytes} byte ceiling")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UnsafeAgentPayloadError(f"Non-JSON or executable payload rejected: {exc}") from exc

    def _check_depth(obj: Any, depth: int) -> None:
        if depth > max_depth:
            raise UnsafeAgentPayloadError(f"JSON nesting exceeds max_depth={max_depth}")
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(k, str):
                    raise UnsafeAgentPayloadError("Non-string key")
                _check_depth(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _check_depth(item, depth + 1)
        elif not isinstance(obj, (str, int, float, bool)) and obj is not None:
            raise UnsafeAgentPayloadError(f"Disallowed primitive type: {type(obj).__name__}")

    _check_depth(parsed, 0)
    return parsed


class _VisibleHtmlStripper(html.parser.HTMLParser):
    """Extracts visible text while dropping hidden DOM subtrees (`hidden`, `display:none`, `aria-hidden`)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._hidden_depth = 0
        self.dropped_hidden_blocks = 0
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._hidden_depth > 0:
            self._hidden_depth += 1
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        is_hidden = (
            "hidden" in attr_map
            or attr_map.get("aria-hidden", "").lower() == "true"
            or bool(_HIDDEN_STYLE_RE.search(attr_map.get("style", "")))
        )
        if is_hidden:
            self._hidden_depth = 1
            self.dropped_hidden_blocks += 1

    def handle_endtag(self, _tag: str) -> None:
        if self._hidden_depth > 0:
            self._hidden_depth -= 1

    def handle_comment(self, _data: str) -> None:
        self.dropped_hidden_blocks += 1

    def handle_data(self, data: str) -> None:
        if self._hidden_depth == 0:
            self._chunks.append(data)

    def get_text(self) -> str:
        return "".join(self._chunks)


@dataclass(frozen=True)
class SanitizedJudgeInput:
    clean_text: str
    stripped_reasons: tuple[str, ...]
    had_injection_attempt: bool


def sanitize_judge_input(raw_text: str) -> SanitizedJudgeInput:
    """Sanitize any artifact text before passing to T4 Judge (Invariant I7, §3 Req 9)."""
    reasons: list[str] = []

    # 1. Remove zero-width & bidi spoofing codepoints first so split keywords re-coalesce!
    cleaned, zw_count = _ZERO_WIDTH_AND_BIDI_RE.subn("", raw_text)
    if zw_count > 0:
        reasons.append(f"zero_width_chars:{zw_count}")

    # 2. Remove HTML comments & script/style blocks
    cleaned, comment_count = _HTML_COMMENT_RE.subn(" ", cleaned)
    if comment_count > 0:
        reasons.append(f"html_comments:{comment_count}")

    cleaned, script_count = _SCRIPT_STYLE_RE.subn(" ", cleaned)
    if script_count > 0:
        reasons.append(f"script_or_style:{script_count}")

    # 3. Strip hidden HTML elements (`display:none`, `opacity:0`, `font-size:0`, `hidden`)
    if "<" in cleaned and ">" in cleaned:
        stripper = _VisibleHtmlStripper()
        stripper.feed(cleaned)
        if stripper.dropped_hidden_blocks > 0:
            reasons.append(f"hidden_dom_blocks:{stripper.dropped_hidden_blocks}")
        cleaned = stripper.get_text()

    # 4. Strip instruction-like prompt-injection lines/clauses
    filtered_lines: list[str] = []
    for line in cleaned.splitlines():
        matched_labels = [label for label, pat in _INJECTION_PATTERNS if pat.search(line)]
        if matched_labels:
            reasons.extend(matched_labels)
            continue
        filtered_lines.append(line)

    final_text = "\n".join(filtered_lines).strip()
    return SanitizedJudgeInput(
        clean_text=final_text,
        stripped_reasons=tuple(dict.fromkeys(reasons)),
        had_injection_attempt=len(reasons) > 0,
    )
