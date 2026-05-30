"""Attack payloads library for SQL injection and XSS testing.

Payloads are loaded from JSON files in the payloads/ directory.
To customize, edit the JSON files directly — no Python changes needed.
"""

import json
import os

_payload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")


def _load_json(filename: str):
    path = os.path.join(_payload_dir, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [!] Failed to load payloads from {path}: {e}")
        return None


SQLI_PAYLOADS = _load_json("sqli.json") or {}
XSS_PAYLOADS = _load_json("xss.json") or {}
DB_ERROR_PATTERNS = _load_json("db_errors.json") or []

DOC_PAGE_CONTENT_PATTERNS = [
    r"(?i)<(?:pre|code)[^>]*>[\s\S]*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[\s\S]*?</(?:pre|code)>",
    r"(?i)<(?:pre|code)[^>]*>[\s\S]*?(?:MariaDB|MySQL|PostgreSQL|Oracle|MSSQL)[\s\S]*?</(?:pre|code)>",
    r"(?i)check the manual that corresponds to your (?:MariaDB|MySQL)",
    r"(?i)example\s+(?:error|injection|payload)",
    r"(?i)documentation\s+(?:for|page)",
    r"(?i)how\s+to\s+(?:exploit|use)",
    r"(?i)steps?\s+to\s+(?:reproduce|exploit)",
]
