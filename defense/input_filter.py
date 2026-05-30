"""Input validation and sanitization defense module."""

from __future__ import annotations

import re
import html
from typing import Any, Optional


class InputFilter:
    SQLI_KEYWORDS = [
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
        "ALTER", "CREATE", "EXEC", "EXECUTE", "WAITFOR", "SLEEP",
        "BENCHMARK", "INFORMATION_SCHEMA", "NULL", "--", "/*", "*/",
        "OR 1=1", "AND 1=1", "OR '1'='1", "AND '1'='1",
    ]

    SQLI_REGEX = re.compile(
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC(UTE)?)\b)",
        re.IGNORECASE,
    )

    XSS_REGEX = re.compile(
        r"(<script|</script|<img|<svg|<iframe|onerror=|onload=|"
        r"onclick=|onmouseover=|javascript:|data:text/html|<body\s+onload)",
        re.IGNORECASE,
    )

    SQL_COMMENT_REGEX = re.compile(r"(--|#|/\*|\*/)")

    @classmethod
    def sanitize_sql(cls, value: str) -> str:
        """Escape dangerous SQL characters."""
        if not isinstance(value, str):
            return str(value) if value is not None else ""
        value = value.replace("\\", "\\\\")
        value = value.replace("'", "\\'")
        value = value.replace("\"", "\\\"")
        value = value.replace(";", "")
        return value

    @classmethod
    def sanitize_html(cls, value: str) -> str:
        """HTML entity encode to prevent XSS."""
        if not isinstance(value, str):
            return str(value) if value is not None else ""
        return html.escape(value, quote=True)

    @classmethod
    def detect_sqli(cls, value: str) -> bool:
        """Detect SQL injection patterns in input."""
        if not isinstance(value, str):
            return False
        upper = value.upper()
        for keyword in cls.SQLI_KEYWORDS:
            if keyword.upper() in upper:
                return True
        if cls.SQL_COMMENT_REGEX.search(value):
            return True
        if re.search(r"(['\"])\s*(OR|AND)\s*\1\s*=\s*\1", value, re.IGNORECASE):
            return True
        return False

    @classmethod
    def detect_xss(cls, value: str) -> bool:
        """Detect XSS patterns in input."""
        if not isinstance(value, str):
            return False
        if cls.XSS_REGEX.search(value):
            return True
        decoded = html.unescape(value)
        if cls.XSS_REGEX.search(decoded):
            return True
        # 更严格的标签检测：只在发现类似标签结构时才触发
        if "<" in value and ">" in value:
            tag_pattern = re.compile(r"<\s*[\w]+[^>]*>")
            if tag_pattern.search(value):
                return True
        return False

    @classmethod
    def validate_string(cls, value: str, pattern: str = r"^[a-zA-Z0-9_\-\.\s]+$") -> bool:
        """Whitelist validation for expected character sets."""
        if not isinstance(value, str):
            return False
        return bool(re.match(pattern, value))

    @classmethod
    def validate_integer(cls, value: Any) -> bool:
        """Validate that input is a safe integer."""
        if isinstance(value, int):
            return True
        if isinstance(value, str):
            return value.isdigit() or (value.startswith("-") and value[1:].isdigit())
        return False

    @classmethod
    def filter_request_data(cls, data: dict) -> tuple[dict, list[str]]:
        """Filter all values in a request data dict. Returns (cleaned_data, alerts)."""
        cleaned = {}
        alerts = []
        for key, value in data.items():
            val = str(value) if value is not None else ""
            if cls.detect_sqli(val):
                alerts.append(f"[SQLi BLOCKED] Parameter '{key}' contains SQL injection pattern")
                cleaned[key] = ""
            elif cls.detect_xss(val):
                alerts.append(f"[XSS BLOCKED] Parameter '{key}' contains XSS pattern")
                cleaned[key] = cls.sanitize_html(val)
            else:
                cleaned[key] = val
        return cleaned, alerts
