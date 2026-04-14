from __future__ import annotations

import re
from urllib.parse import unquote


class SimulatedWAF:
    """Intentionally imperfect regex-based filter for defensive testing demos."""

    def __init__(self) -> None:
        self.patterns = [
            re.compile(r"test_xss", re.IGNORECASE),
            re.compile(r"safe_script_token", re.IGNORECASE),
            re.compile(r"event_handler", re.IGNORECASE),
            re.compile(r"dom_sink_test", re.IGNORECASE),
        ]

    def normalize(self, value: str) -> str:
        # Single-pass normalization to demonstrate why deeper normalization is needed.
        return unquote(value).lower()

    def inspect(self, value: str) -> tuple[bool, str]:
        normalized = self.normalize(value)
        for pattern in self.patterns:
            if pattern.search(normalized):
                return True, f"blocked_by:{pattern.pattern}"
        return False, "allowed:no_rule_match"
