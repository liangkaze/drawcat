"""Tests for the scanner module components."""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.crawler import Crawler
from scanner.payloads import DB_ERROR_PATTERNS, SQLI_PAYLOADS, XSS_PAYLOADS
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss import XSSScanner


class TestPayloads(unittest.TestCase):
    def test_sqli_payloads_exist(self):
        self.assertGreater(len(SQLI_PAYLOADS["error_based"]), 0)
        self.assertGreater(len(SQLI_PAYLOADS["boolean_based"]), 0)
        self.assertGreater(len(SQLI_PAYLOADS["time_based"]), 0)

    def test_xss_payloads_exist(self):
        self.assertGreater(len(XSS_PAYLOADS["basic"]), 0)
        self.assertGreater(len(XSS_PAYLOADS["event_handler"]), 0)
        self.assertGreater(len(XSS_PAYLOADS["bypass"]), 0)

    def test_db_error_patterns(self):
        self.assertIn(r"SQL syntax.*MySQL", DB_ERROR_PATTERNS)
        self.assertIn(r"Unclosed quotation mark", DB_ERROR_PATTERNS)


class TestCrawler(unittest.TestCase):
    def test_normalize_url(self):
        crawler = Crawler("http://example.com")
        result = crawler._normalize_url("/path?x=1#anchor")
        self.assertEqual(result, "http://example.com/path?x=1")

    def test_is_internal(self):
        crawler = Crawler("http://example.com")
        self.assertTrue(crawler._is_internal("http://example.com/page"))
        self.assertTrue(crawler._is_internal("/relative"))
        self.assertFalse(crawler._is_internal("http://other.com/page"))


class TestSQLiScanner(unittest.TestCase):
    def test_inject_in_url(self):
        scanner = SQLInjectionScanner()
        result = scanner._inject_in_url(
            "http://example.com/search?q=test&page=1", "q", "' OR 1=1--"
        )
        self.assertIn("q=%27+OR+1%3D1--", result)
        self.assertIn("page=1", result)

    def test_inject_in_form(self):
        scanner = SQLInjectionScanner()
        form = {
            "action": "/login",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        }
        data = scanner._inject_in_form(form, "username", "admin'--")
        self.assertEqual(data["username"], "admin'--")
        self.assertEqual(data["password"], "")


class TestXSSScanner(unittest.TestCase):
    def test_payload_reflected(self):
        scanner = XSSScanner()
        reflected, is_static, is_exploitable = scanner._payload_reflected(
            "<script>alert(1)</script>",
            "<html><body><script>alert(1)</script></body></html>",
        )
        self.assertTrue(reflected)
        self.assertFalse(is_static)
        self.assertTrue(is_exploitable)  # Raw payload in body text

    def test_payload_not_reflected(self):
        scanner = XSSScanner()
        reflected, is_static, is_exploitable = scanner._payload_reflected(
            "<script>alert(1)</script>",
            "<html><body>No XSS here</body></html>",
        )
        self.assertFalse(reflected)
        self.assertFalse(is_exploitable)

    def test_encoded_reflection_detected(self):
        scanner = XSSScanner()
        reflected, is_static, is_exploitable = scanner._payload_reflected(
            "<script>alert(1)</script>",
            "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>",
        )
        self.assertTrue(reflected)       # Payload found after HTML unescape
        self.assertFalse(is_exploitable)  # Entity-encoded → not exploitable

    def test_payload_reflected_in_attribute_safe(self):
        """Payload reflected inside a quoted attribute → not exploitable."""
        scanner = XSSScanner()
        reflected, is_static, is_exploitable = scanner._payload_reflected(
            "<script>alert(1)</script>",
            '<html><input value="&lt;script&gt;alert(1)&lt;/script&gt;">',
        )
        self.assertTrue(reflected)
        self.assertFalse(is_exploitable)

    def test_payload_attribute_breakout(self):
        """Payload breaks out of attribute with quote → exploitable."""
        scanner = XSSScanner()
        reflected, is_static, is_exploitable = scanner._payload_reflected(
            '"><script>alert(1)</script>',
            '<html><input value=""><script>alert(1)</script>">',
        )
        self.assertTrue(reflected)
        self.assertTrue(is_exploitable)


if __name__ == "__main__":
    unittest.main()
