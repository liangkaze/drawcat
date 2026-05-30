"""Cookie security configuration module."""

from __future__ import annotations

from typing import Optional


class CookieSecurity:
    """Configures secure cookie attributes to prevent XSS-based cookie theft."""

    @staticmethod
    def secure_config(
        value: str,
        key: str = "session",
        httponly: bool = True,
        secure: bool = True,
        samesite: str = "Lax",
        max_age: Optional[int] = 3600,
        path: str = "/",
    ) -> dict:
        return {
            "key": key,
            "value": value,
            "httponly": httponly,
            "secure": secure,
            "samesite": samesite,
            "max_age": max_age,
            "path": path,
        }

    @staticmethod
    def set_cookie_headers(response, config: dict) -> None:
        """Apply secure cookie settings to a Flask response object."""
        response.set_cookie(
            key=config["key"],
            value=config["value"],
            httponly=config.get("httponly", True),
            secure=config.get("secure", True),
            samesite=config.get("samesite", "Lax"),
            max_age=config.get("max_age", 3600),
            path=config.get("path", "/"),
        )

    @staticmethod
    def audit_cookies(cookies: dict) -> list[str]:
        """Audit existing cookies for security issues. Returns list of warnings."""
        warnings = []
        for name, attrs in cookies.items():
            if not attrs.get("httponly"):
                warnings.append(f"Cookie '{name}' missing HttpOnly flag — vulnerable to XSS theft")
            if not attrs.get("secure"):
                warnings.append(f"Cookie '{name}' missing Secure flag — transmitted over HTTP")
            if attrs.get("samesite", "").lower() not in ("strict", "lax"):
                warnings.append(f"Cookie '{name}' missing SameSite — vulnerable to CSRF")
        return warnings

    @staticmethod
    def secure_cookie_header() -> str:
        """Generate recommended Set-Cookie header string."""
        return (
            'Set-Cookie: session=...; '
            'HttpOnly; Secure; SameSite=Lax; Max-Age=3600; Path=/'
        )
