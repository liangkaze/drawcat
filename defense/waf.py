"""Simple Web Application Firewall (WAF) module.

Intercepts HTTP requests before they reach the application and applies
input filtering, rate limiting, and security header injection.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Optional

from defense.input_filter import InputFilter


class SimpleWAF:
    def __init__(self, rate_limit: int = 100, window_seconds: int = 60):
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.request_counts: dict[str, list[float]] = defaultdict(list)
        self.blocked_ips: set[str] = set()
        self.alerts: list[str] = []

    def _check_rate_limit(self, client_ip: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        self.request_counts[client_ip] = [
            t for t in self.request_counts[client_ip] if t > window_start
        ]
        self.request_counts[client_ip].append(now)
        if len(self.request_counts[client_ip]) > self.rate_limit:
            self.blocked_ips.add(client_ip)
            self.alerts.append(f"[WAF] IP {client_ip} rate-limited")
            return False
        return True

    def inspect_request(
        self,
        method: str,
        path: str,
        query_params: dict,
        body: dict,
        headers: dict,
        client_ip: str = "127.0.0.1",
    ) -> tuple[bool, dict, list[str]]:
        """Inspect a request. Returns (allowed, cleaned_body, alerts)."""
        alerts = []

        if client_ip in self.blocked_ips:
            return False, {}, ["[WAF] IP blocked"]

        if not self._check_rate_limit(client_ip):
            return False, {}, ["[WAF] Rate limit exceeded"]

        # Inspect query parameters
        for param, value in query_params.items():
            val = str(value)
            if InputFilter.detect_sqli(val):
                alerts.append(f"[WAF-SQLi] Query param '{param}' blocked")
                return False, {}, alerts
            if InputFilter.detect_xss(val):
                alerts.append(f"[WAF-XSS] Query param '{param}' blocked")
                return False, {}, alerts

        # Inspect body
        cleaned_body, body_alerts = InputFilter.filter_request_data(body)
        alerts.extend(body_alerts)

        # Block if SQLi or XSS found in body
        for alert in body_alerts:
            if "SQLi" in alert or "XSS" in alert:
                return False, {}, alerts

        self.alerts.extend(alerts)
        return True, cleaned_body, alerts

    @staticmethod
    def security_headers() -> dict:
        """Return recommended security headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:;"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=()",
        }

    def get_summary(self) -> dict:
        return {
            "total_alerts": len(self.alerts),
            "blocked_ips": list(self.blocked_ips),
            "alerts": self.alerts[-20:],
        }
