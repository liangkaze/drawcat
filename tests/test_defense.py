"""Tests for the defense module components."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from defense.input_filter import InputFilter
from defense.cookie_security import CookieSecurity
from defense.waf import SimpleWAF
from defense.param_query import ParamQuery


class TestInputFilter(unittest.TestCase):
    def test_detect_sqli_basic(self):
        self.assertTrue(InputFilter.detect_sqli("' OR '1'='1"))
        self.assertTrue(InputFilter.detect_sqli("1 UNION SELECT NULL"))
        self.assertTrue(InputFilter.detect_sqli("admin'--"))
        self.assertTrue(InputFilter.detect_sqli("'; DROP TABLE users--"))

    def test_detect_sqli_safe_input(self):
        self.assertFalse(InputFilter.detect_sqli("normal_username"))
        self.assertFalse(InputFilter.detect_sqli("test@example.com"))
        self.assertFalse(InputFilter.detect_sqli("123"))

    def test_detect_xss_basic(self):
        self.assertTrue(InputFilter.detect_xss("<script>alert(1)</script>"))
        self.assertTrue(InputFilter.detect_xss("<img src=x onerror=alert(1)>"))
        self.assertTrue(InputFilter.detect_xss("javascript:alert(1)"))

    def test_detect_xss_safe_input(self):
        self.assertFalse(InputFilter.detect_xss("Hello World"))
        self.assertFalse(InputFilter.detect_xss("test@example.com"))

    def test_sanitize_html(self):
        result = InputFilter.sanitize_html('<script>alert("xss")</script>')
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;", result)
        self.assertIn("&gt;", result)
        self.assertIn("&quot;", result)

    def test_sanitize_sql(self):
        result = InputFilter.sanitize_sql("test'value")
        self.assertIn("\\'", result)
        result2 = InputFilter.sanitize_sql('test"value')
        self.assertIn('\\"', result2)

    def test_validate_integer(self):
        self.assertTrue(InputFilter.validate_integer("123"))
        self.assertTrue(InputFilter.validate_integer(456))
        self.assertTrue(InputFilter.validate_integer("-1"))
        self.assertFalse(InputFilter.validate_integer("abc"))
        self.assertFalse(InputFilter.validate_integer("1.5"))
        self.assertFalse(InputFilter.validate_integer("1' OR 1=1"))

    def test_filter_request_data_blocks_sqli(self):
        data = {"username": "admin' OR '1'='1", "password": "test"}
        cleaned, alerts = InputFilter.filter_request_data(data)
        self.assertEqual(cleaned["username"], "")
        self.assertTrue(any("SQLi" in a for a in alerts))

    def test_filter_request_data_sanitizes_xss(self):
        data = {"comment": "<script>alert(1)</script>"}
        cleaned, alerts = InputFilter.filter_request_data(data)
        self.assertNotIn("<script>", cleaned["comment"])
        self.assertTrue(any("XSS" in a for a in alerts))


class TestCookieSecurity(unittest.TestCase):
    def test_secure_config_defaults(self):
        config = CookieSecurity.secure_config("abc123")
        self.assertTrue(config["httponly"])
        self.assertTrue(config["secure"])
        self.assertEqual(config["samesite"], "Lax")

    def test_audit_insecure_cookies(self):
        cookies = {
            "session": {"httponly": False, "secure": False, "samesite": ""},
            "csrf": {"httponly": False, "secure": False, "samesite": ""},
        }
        warnings = CookieSecurity.audit_cookies(cookies)
        self.assertGreaterEqual(len(warnings), 2)


class TestSimpleWAF(unittest.TestCase):
    def setUp(self):
        self.waf = SimpleWAF(rate_limit=5, window_seconds=60)

    def test_inspect_clean_request(self):
        allowed, cleaned, alerts = self.waf.inspect_request(
            "GET", "/search", {"q": "hello"}, {}, {}, "127.0.0.1"
        )
        self.assertTrue(allowed)
        self.assertEqual(len(alerts), 0)

    def test_inspect_sqli_request_blocked(self):
        allowed, cleaned, alerts = self.waf.inspect_request(
            "GET", "/search", {"q": "' OR 1=1--"}, {}, {}, "127.0.0.1"
        )
        self.assertFalse(allowed)

    def test_inspect_xss_request(self):
        allowed, cleaned, alerts = self.waf.inspect_request(
            "GET", "/greet", {"name": "<script>alert(1)</script>"}, {}, {}, "127.0.0.1"
        )
        self.assertTrue(any("XSS" in a for a in alerts))

    def test_security_headers(self):
        headers = SimpleWAF.security_headers()
        self.assertIn("X-Content-Type-Options", headers)
        self.assertIn("X-Frame-Options", headers)
        self.assertIn("Content-Security-Policy", headers)


class TestParamQuery(unittest.TestCase):
    def setUp(self):
        self.db_path = ":memory:"
        self.pq = ParamQuery(self.db_path)
        self.pq.execute(
            "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT, value TEXT)"
        )
        self.pq.execute(
            "INSERT INTO test VALUES (1, 'alice', 'secret1')"
        )
        self.pq.execute(
            "INSERT INTO test VALUES (2, 'bob', 'secret2')"
        )

    def tearDown(self):
        self.pq.close()

    def test_safe_query(self):
        row = self.pq.fetch_one("SELECT * FROM test WHERE name=?", ("alice",))
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "alice")

    def test_sqli_attempt_prevented(self):
        malicious = "' OR '1'='1"
        row = self.pq.fetch_one("SELECT * FROM test WHERE name=?", (malicious,))
        self.assertIsNone(row)

    def test_fetch_all(self):
        rows = self.pq.fetch_all("SELECT * FROM test")
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
