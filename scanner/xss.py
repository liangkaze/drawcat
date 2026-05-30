"""Cross-Site Scripting (XSS) detection engine."""

from __future__ import annotations

import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import requests
from bs4 import BeautifulSoup

from scanner.payloads import XSS_PAYLOADS


@dataclass
class XSSFinding:
    url: str
    param: str
    method: str
    payload: str
    xss_type: str  # reflected, stored, dom
    evidence: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"


class XSSScanner:
    def __init__(
        self,
        timeout: int = 10,
        delay: float = 0.1,
        session: Optional[requests.Session] = None,
    ):
        self.timeout = timeout
        self.delay = delay
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update(
                {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                }
            )
        self.findings: list[XSSFinding] = []

    def _inject_in_url(self, url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _inject_in_form(self, form: dict, param: str, payload: str) -> dict:
        data = {}
        for inp in form["inputs"]:
            data[inp["name"]] = payload if inp["name"] == param else inp["value"]
        return data

    # ------------------------------------------------------------------
    # 页面分类
    # ------------------------------------------------------------------

    SKIP_PAGES = [
        "instructions.php", "setup.php", "about.php", "phpinfo.php",
        "logout.php", "login.php", "security.php", "index.php",
    ]

    # URL 路径含这些关键词表示 SQLi 页面，XSS 发现需要额外验证
    SQLI_PAGE_PATTERNS = ["sqli_", "/sqli/"]

    # SQL 错误上下文关键词 — payload 出现在这些文本附近表示反射来自错误消息
    SQL_ERROR_CONTEXT = [
        r"(?i)You have an error in your SQL",
        r"(?i)SQL syntax.*MySQL",
        r"(?i)syntax error at or near",
        r"(?i)unterminated quoted string",
        r"(?i)Unclosed quotation mark",
        r"(?i)supplied argument is not a valid",
        r"(?i)must be an integer",
        r"(?i)invalid input syntax",
    ]

    def _should_skip(self, url: str) -> bool:
        path = urllib.parse.urlparse(url).path.lower()
        return any(skip in path for skip in self.SKIP_PAGES)

    def _is_sqli_page(self, url: str) -> bool:
        """判断 URL 是否属于 SQL 注入页面，这类页面上的 XSS 需要额外验证。"""
        path = urllib.parse.urlparse(url).path.lower()
        return any(p in path for p in self.SQLI_PAGE_PATTERNS)

    def _in_sql_error_context(self, payload: str, response_text: str) -> bool:
        """检查 payload 是否出现在 SQL 错误消息附近（SQL 错误回显不是 XSS）。"""
        idx = response_text.find(payload)
        if idx == -1:
            return False
        # 检查 payload 前后 300 字符窗口内是否有 SQL 错误特征
        window = response_text[max(0, idx - 300):idx + len(payload) + 300]
        return any(re.search(p, window) for p in self.SQL_ERROR_CONTEXT)

    @staticmethod
    def _extract_structure(text: str) -> tuple:
        if not text:
            return (0, set(), 0)
        tags = set(re.findall(r"<\s*/?\s*(\w+)", text))
        tag_count = len(re.findall(r"<\s*/?\s*\w+", text))
        return (len(text), frozenset(tags), tag_count)

    def _get_baseline_response(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> str:
        """获取正常参数下的响应文本作为基线。"""
        test_val = original_value or "baseline_xss_chk"
        try:
            if form:
                data = self._inject_in_form(form, param, test_val)
                if method.upper() == "GET":
                    resp = self.session.get(
                        form["action"], params=data,
                        timeout=self.timeout, allow_redirects=False,
                    )
                else:
                    resp = self.session.post(
                        form["action"], data=data,
                        timeout=self.timeout, allow_redirects=False,
                    )
            else:
                test_url = self._inject_in_url(url, param, test_val)
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            return resp.text
        except requests.RequestException:
            return ""

    # ------------------------------------------------------------------
    # Payload 回显检测（带上下文分析）
    # ------------------------------------------------------------------

    def _payload_reflected(self, payload: str, response_text: str, baseline_text: str = "") -> tuple:
        """检查 payload 是否在响应中回显，并分析可利用性。

        返回 (reflected, is_static, is_exploitable) 三元组。
        is_exploitable: payload 回显在可执行上下文中（标签外、事件处理器内、可 breakout 的属性等）。
        """
        raw_idx = response_text.find(payload)
        if raw_idx == -1:
            # Raw payload not found → try HTML-unescaped matching
            text_unescaped = (
                response_text.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", '"')
                .replace("&#x27;", "'")
                .replace("&#39;", "'")
                .replace("&#34;", '"')
                .replace("&amp;", "&")
            )
            if payload in text_unescaped:
                # Payload reflected but entity-encoded → safe in almost all contexts
                return True, False, False
            core = payload.replace("<script>", "").replace("</script>", "").strip()
            if core and core in text_unescaped:
                return True, False, False
            return False, False, False

        # Raw payload found — check if in a static/documentation code block
        is_static = False
        if baseline_text:
            try:
                soup = BeautifulSoup(response_text, "lxml")
                for code_tag in soup.find_all(["pre", "code", "samp", "kbd"]):
                    if payload in code_tag.get_text():
                        is_static = True
                        break
            except Exception:
                pass
        if is_static:
            return True, True, False

        # Analyze the HTML context around the reflection point
        context_before = response_text[:raw_idx]
        last_lt = context_before.rfind("<")
        last_gt = context_before.rfind(">")

        if last_lt > last_gt:
            # Inside an HTML tag — analyze what kind of context
            tag_context = context_before[last_lt:]

            # Event handler context (onerror, onclick, etc.) → always exploitable
            if re.search(r'\bon\w+\s*=\s*["\']?[^"\'>]*$', tag_context, re.IGNORECASE):
                return True, False, True

            # Double-quoted attribute value
            dq_match = re.search(
                r'(?:value|name|id|class|type|placeholder|href|src|action|data-\w+)\s*=\s*"([^"]*)$',
                tag_context,
            )
            if dq_match:
                after = response_text[raw_idx + len(payload):]
                if '"' in payload and re.match(r'\s*["\']?\s*>', after):
                    return True, False, True  # Breaks out of attribute
                return True, False, False  # Safely encapsulated in attribute

            # Single-quoted attribute value
            sq_match = re.search(
                r"(?:value|name|id|class|type|placeholder|href|src|action|data-\w+)\s*=\s*'([^']*)$",
                tag_context,
            )
            if sq_match:
                after = response_text[raw_idx + len(payload):]
                if "'" in payload and re.match(r'\s*["\']?\s*>', after):
                    return True, False, True
                return True, False, False

            # Inside a tag but not in a recognized safe attribute
            # Check if it's inside <script> or <style> — potentially exploitable
            if re.search(r'<(?:script|style)\b[^>]*>', tag_context, re.IGNORECASE):
                return True, False, True
            return True, False, False

        # Outside any HTML tag (raw body text) — exploitable
        return True, False, True

    def _check_csp(self, resp: requests.Response) -> str:
        """检测响应中的 CSP 头，返回 CSP 策略摘要（空字符串表示无 CSP）。"""
        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            return ""
        # 提取关键指令
        directives = []
        if "script-src" in csp:
            match = re.search(r"script-src\s+([^;]+)", csp)
            if match:
                directives.append(f"script-src {match.group(1).strip()}")
        if "'unsafe-inline'" not in csp:
            directives.append("inline-blocked")
        if "default-src" in csp:
            match = re.search(r"default-src\s+([^;]+)", csp)
            if match:
                directives.append(f"default-src {match.group(1).strip()}")
        return "; ".join(directives) if directives else "CSP present"

    # ------------------------------------------------------------------
    # Reflected XSS
    # ------------------------------------------------------------------

    def _check_reflected_xss(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> list[XSSFinding]:
        findings = []
        all_payloads = (
            XSS_PAYLOADS["basic"][:8] +
            XSS_PAYLOADS["img_variants"][:4] +
            XSS_PAYLOADS["svg_vectors"][:3] +
            XSS_PAYLOADS.get("dvwa_specific", [])[:4]
        )
        baseline_text = self._get_baseline_response(
            url, param, method, form, original_value,
        )
        for payload in all_payloads:
            time.sleep(self.delay)
            try:
                if form:
                    data = self._inject_in_form(form, param, payload)
                    if method.upper() == "GET":
                        resp = self.session.get(
                            form["action"], params=data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                    else:
                        resp = self.session.post(
                            form["action"], data=data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                else:
                    test_url = self._inject_in_url(url, param, payload)
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                reflected, is_static, is_exploitable = self._payload_reflected(
                    payload, resp.text, baseline_text,
                )
                if reflected and not is_static and is_exploitable:
                    # SQLi 页面上的回显需要排除 SQL 错误消息上下文
                    if self._is_sqli_page(url) and self._in_sql_error_context(payload, resp.text):
                        continue
                    csp_info = self._check_csp(resp)
                    evidence = "Payload reflected in response body (non-static context)"
                    confidence = "MEDIUM"
                    if csp_info:
                        evidence += f" | CSP: {csp_info}"
                        confidence = "LOW"
                    findings.append(XSSFinding(
                        url=url, param=param, method=method,
                        payload=payload, xss_type="Reflected",
                        evidence=evidence, confidence=confidence,
                    ))
                    break
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # DOM-based XSS
    # ------------------------------------------------------------------

    def _check_dom_xss(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None,
    ) -> list[XSSFinding]:
        findings = []
        tested_payloads = set()
        for payload in XSS_PAYLOADS["dom_based"]:
            if payload in tested_payloads:
                continue
            tested_payloads.add(payload)
            time.sleep(self.delay)
            try:
                if form:
                    data = self._inject_in_form(form, param, payload)
                    if method.upper() == "GET":
                        resp = self.session.get(
                            form["action"], params=data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                    else:
                        resp = self.session.post(
                            form["action"], data=data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                else:
                    test_url = self._inject_in_url(url, param, payload)
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                soup = BeautifulSoup(resp.text, "lxml")
                scripts = soup.find_all("script")
                sinks = ["document.write", "innerHTML", "eval(", "location.hash",
                         "location.href", "document.URL", "document.documentURI",
                         "window.location", "setTimeout", "setInterval"]
                for script in scripts:
                    if script.string:
                        for sink in sinks:
                            if sink in script.string:
                                if payload.replace("'", "").replace('"', '')[:10] in script.string:
                                    findings.append(XSSFinding(
                                        url=url, param=param,
                                        method=form["method"] if form else "GET",
                                        payload=payload, xss_type="DOM-based",
                                        evidence=f"Payload reaches DOM sink '{sink}' in JavaScript",
                                    ))
                                    break
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # Stored XSS
    # ------------------------------------------------------------------

    def _check_stored_xss(self, form: dict) -> list[XSSFinding]:
        findings = []
        for payload in (XSS_PAYLOADS["basic"][:3] + XSS_PAYLOADS.get("dvwa_specific", [])[:3]):
            time.sleep(self.delay)
            try:
                data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("submit", "button", "image", "reset"):
                        continue
                    if inp["name"]:
                        data[inp["name"]] = payload
                resp = self.session.post(
                    form["action"], data=data,
                    timeout=self.timeout, allow_redirects=True,
                )
                reflected, is_static, is_exploitable = self._payload_reflected(payload, resp.text)
                if not reflected or is_static or not is_exploitable:
                    continue

                # 二次验证：GET 同一页面确认 payload 已持久化
                time.sleep(self.delay * 2)
                try:
                    verify_resp = self.session.get(
                        form["page_url"], timeout=self.timeout, allow_redirects=True,
                    )
                    persisted, _, _ = self._payload_reflected(payload, verify_resp.text)
                    if not persisted:
                        continue
                except requests.RequestException:
                    continue

                csp_info = self._check_csp(verify_resp)
                evidence = "Payload persisted and reflected after POST (verified via GET)"
                confidence = "MEDIUM"
                if csp_info:
                    evidence += f" | CSP: {csp_info}"
                    confidence = "LOW"
                findings.append(XSSFinding(
                    url=form["action"], param="(form body)",
                    method=form["method"], payload=payload,
                    xss_type="Stored",
                    evidence=evidence, confidence=confidence,
                ))
                break
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # 扫描入口
    # ------------------------------------------------------------------

    def scan_url(self, url: str) -> list[XSSFinding]:
        if self._should_skip(url):
            return self.findings
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for param, values in params.items():
            original_value = values[0] if values else ""
            findings = self._check_reflected_xss(url, param, "GET", original_value=original_value)
            self.findings.extend(findings)
            if not findings:
                dom_findings = self._check_dom_xss(url, param)
                self.findings.extend(dom_findings)
        return self.findings

    def scan_form(self, form: dict) -> list[XSSFinding]:
        if self._should_skip(form["action"]):
            return self.findings
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset", "hidden"):
                continue
            if inp["name"] in ("user_token", "csrf_token", "_token"):
                continue
            original_value = inp.get("value", "")
            findings = self._check_reflected_xss(
                form["action"], inp["name"], form["method"], form,
                original_value=original_value,
            )
            self.findings.extend(findings)
            if not findings:
                dom_findings = self._check_dom_xss(form["action"], inp["name"], form["method"], form)
                self.findings.extend(dom_findings)
        stored = self._check_stored_xss(form)
        self.findings.extend(stored)
        return self.findings

    def scan(self, urls: set[str], forms: list[dict]) -> list[XSSFinding]:
        for url in urls:
            if urllib.parse.urlparse(url).query:
                self.scan_url(url)
        for form in forms:
            self.scan_form(form)
        return self.findings
