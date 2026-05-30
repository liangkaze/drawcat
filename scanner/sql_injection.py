"""SQL Injection detection engine with multiple detection techniques."""

from __future__ import annotations

import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import requests
from bs4 import BeautifulSoup

from scanner.payloads import (
    DB_ERROR_PATTERNS,
    SQLI_PAYLOADS,
    DOC_PAGE_CONTENT_PATTERNS,
)


@dataclass
class SQLiFinding:
    url: str
    param: str
    method: str
    payload: str
    technique: str
    evidence: str
    severity: str = "HIGH"
    confidence: str = "MEDIUM"


class SQLInjectionScanner:
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
        self.findings: list[SQLiFinding] = []

    def _inject_in_url(self, url: str, param: str, payload: str, prefix: str = "") -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [prefix + payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _inject_in_form(self, form: dict, param: str, payload: str, prefix: str = "") -> dict:
        data = {}
        for inp in form["inputs"]:
            data[inp["name"]] = (prefix + payload) if inp["name"] == param else inp["value"]
        return data

    # ------------------------------------------------------------------
    # 页面分类：识别文档/帮助页面，这些页面自带 DB 错误文本作为示例
    # ------------------------------------------------------------------

    SKIP_PAGES = [
        "instructions.php", "setup.php", "about.php", "phpinfo.php",
        "logout.php", "login.php", "security.php", "index.php",
    ]

    # URL 路径含这些关键词时表示 XSS/文件类页面，跳过 SQLi 检测
    SKIP_SQLI_URL_PATTERNS = [
        "xss_", "/xss/",
    ]

    def _should_skip(self, url: str) -> bool:
        """跳过已知的非漏洞页面，避免误报。"""
        path = urllib.parse.urlparse(url).path.lower()
        return any(skip in path for skip in self.SKIP_PAGES)

    def _should_skip_sqli(self, url: str) -> bool:
        """跳过明确非 SQL 的页面（XSS 页面等），避免 Boolean-based 误报。"""
        path = urllib.parse.urlparse(url).path.lower()
        return any(p in path for p in self.SKIP_SQLI_URL_PATTERNS)

    def _is_documentation_page(self, html: str) -> bool:
        """基于页面内容判断是否为文档/帮助页面（自带数据库错误示例文本）。"""
        if not html:
            return False
        score = 0
        for pattern in DOC_PAGE_CONTENT_PATTERNS:
            if re.search(pattern, html):
                score += 1
        # 匹配到 2 个以上文档特征时标记为文档页
        if score >= 2:
            return True
        # DOM 结构检查：code/pre 标签中包含 SQL 关键字
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["pre", "code"]):
                text = tag.get_text()
                if re.search(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s", text):
                    if re.search(r"(?i)(error|syntax|warning|MariaDB|MySQL)", text):
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _extract_structure(text: str) -> tuple:
        """提取页面结构指纹，用于比较两个响应是否来自同一模板。"""
        if not text:
            return (0, set(), 0)
        # HTML 标签数量
        tags = set(re.findall(r"<\s*/?\s*(\w+)", text))
        # 标签计数
        tag_count = len(re.findall(r"<\s*/?\s*\w+", text))
        return (len(text), frozenset(tags), tag_count)

    # ------------------------------------------------------------------
    # 基线采集（双重基线，捕获页面自带的错误文本）
    # ------------------------------------------------------------------

    def _get_baseline_errors(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> set:
        """使用双重基线获取页面自带的 DB 错误模式。

        基线 1: 原始参数值（如 doc=changelog）
        基线 2: 另一个安全值（baseline_chk_42）
        取并集作为综合基线，确保捕获文档页中自带的所有 DB 错误文本。
        """
        baseline_patterns = set()
        safe_values = [v for v in [original_value, "baseline_chk_42"] if v]
        if not safe_values:
            safe_values = ["1"]

        for test_val in safe_values:
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
                for pattern in DB_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        baseline_patterns.add(pattern)
            except requests.RequestException:
                continue
        return baseline_patterns

    def _get_baseline_response(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> tuple:
        """获取基线响应的文本和结构指纹，用于与注入响应做相似性对比。"""
        test_val = original_value or "1"
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
            return resp.text, self._extract_structure(resp.text), resp.status_code
        except requests.RequestException:
            return "", (0, set(), 0), 0

    # ------------------------------------------------------------------
    # Error-based 检测
    # ------------------------------------------------------------------

    def _check_error_based(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> list[SQLiFinding]:
        findings = []
        tested_payloads = set()

        baseline_errors = self._get_baseline_errors(
            url, param, method, form, original_value,
        )

        for payload in SQLI_PAYLOADS["error_based"] + SQLI_PAYLOADS.get("dvwa_specific", []):
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

                for pattern in DB_ERROR_PATTERNS:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if not match:
                        continue
                    if pattern in baseline_errors:
                        continue

                    # 新 DB 错误出现 → 验证上下文
                    error_text = match.group(0)
                    error_pos = match.start()

                    # 验证 1: 错误不在文档页面的 <pre>/<code> 标签中
                    # 仅在已识别为文档页时才跳过，避免误杀真实的运行时错误输出
                    in_doc_block = False
                    if self._is_documentation_page(resp.text):
                        try:
                            soup = BeautifulSoup(resp.text, "lxml")
                            for code_tag in soup.find_all(["pre", "code", "samp", "kbd"]):
                                if error_text in code_tag.get_text():
                                    in_doc_block = True
                                    break
                        except Exception:
                            pass
                    if in_doc_block:
                        continue

                    # 验证 2: 错误附近存在 SQL 上下文关键词
                    context_window = resp.text[
                        max(0, error_pos - 100):error_pos + len(error_text) + 100
                    ]
                    sql_context = re.search(
                        r"(?i)(near|syntax|mysql|mariadb|sql|query|select|insert|update|delete)",
                        context_window,
                    )
                    if not sql_context:
                        continue

                    findings.append(SQLiFinding(
                        url=url, param=param, method=method,
                        payload=payload, technique="Error-based",
                        evidence=f"NEW DB error triggered: {pattern[:60]}",
                    ))
                    return findings
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # Boolean-based 检测
    # ------------------------------------------------------------------

    # 盲注响应中常见的语义差异关键词
    BLIND_INDICATOR_WORDS = [
        "exist", "found", "missing", "not found", "no result",
        "no user", "invalid", "error", "true", "false",
        "yes", "no", "success", "fail",
        "不存在", "存在", "错误", "成功", "失败",
        "email", "uid", "user",
    ]

    def _check_boolean_based(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> list[SQLiFinding]:
        findings = []
        baseline_text, baseline_struct, _ = self._get_baseline_response(
            url, param, method, form, original_value,
        )
        confirmed_small_diffs = 0
        # 记录已确认的小差异 payload，用于去重
        confirmed_payloads: set[str] = set()

        for true_payload, false_payload in SQLI_PAYLOADS["boolean_based"]:
            time.sleep(self.delay)
            try:
                if form:
                    true_data = self._inject_in_form(form, param, true_payload, prefix=original_value)
                    false_data = self._inject_in_form(form, param, false_payload, prefix=original_value)
                    if method.upper() == "GET":
                        true_resp = self.session.get(
                            form["action"], params=true_data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                        false_resp = self.session.get(
                            form["action"], params=false_data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                    else:
                        true_resp = self.session.post(
                            form["action"], data=true_data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                        false_resp = self.session.post(
                            form["action"], data=false_data,
                            timeout=self.timeout, allow_redirects=False,
                        )
                else:
                    true_url = self._inject_in_url(url, param, true_payload, prefix=original_value)
                    false_url = self._inject_in_url(url, param, false_payload, prefix=original_value)
                    true_resp = self.session.get(true_url, timeout=self.timeout, allow_redirects=False)
                    false_resp = self.session.get(false_url, timeout=self.timeout, allow_redirects=False)

                len_diff = abs(len(true_resp.text) - len(false_resp.text))

                # 状态码不同时做基础结构验证，防止页面级错误（如 500 vs 200）
                status_match = true_resp.status_code == false_resp.status_code
                if not status_match:
                    _, tags_t, _ = self._extract_structure(true_resp.text)
                    _, tags_f, _ = self._extract_structure(false_resp.text)
                    if tags_t and tags_f:
                        tag_overlap = len(tags_t & tags_f) / max(len(tags_t | tags_f), 1)
                        if tag_overlap < 0.5:
                            continue  # 结构差异过大 → 页面级错误，不是盲注

                # 内容差异分析（基于纯文本，去除 HTML 噪声）
                def _strip_html(text: str) -> str:
                    return re.sub(r"<[^>]+>", " ", text)
                true_text = _strip_html(true_resp.text.lower())
                false_text = _strip_html(false_resp.text.lower())
                text_len_diff = abs(len(true_text) - len(false_text))
                true_words = set(re.findall(r"\b\w{3,}\b", true_text))
                false_words = set(re.findall(r"\b\w{3,}\b", false_text))
                word_diff = len(true_words ^ false_words)
                unique_true = true_words - false_words
                unique_false = false_words - true_words

                # 语义差异检测：true/false 的独有词中是否包含盲注指示词
                semantic_true = any(
                    any(ind in w for ind in self.BLIND_INDICATOR_WORDS)
                    for w in unique_true
                )
                semantic_false = any(
                    any(ind in w for ind in self.BLIND_INDICATOR_WORDS)
                    for w in unique_false
                )
                # 双向语义差异：true 和 false 各有不同的语义关键词
                bidirectional_semantic = semantic_true and semantic_false
                semantic_diff = semantic_true or semantic_false

                # 基线差异
                diff_true = abs(len(true_resp.text) - len(baseline_text)) if baseline_text else 0
                diff_false = abs(len(false_resp.text) - len(baseline_text)) if baseline_text else 0

                # 判定逻辑（三层级，文本长度和语义双重验证）
                # 层级 1: 大幅差异 (> 50 bytes 原始) — 高置信度
                if len_diff > 50:
                    if baseline_text and diff_true < 30 and diff_false < 30:
                        continue
                    findings.append(SQLiFinding(
                        url=url, param=param, method=method,
                        payload=true_payload, technique="Boolean-based",
                        evidence=f"Response length differs by {len_diff} bytes ({len(true_resp.text)} vs {len(false_resp.text)})",
                    ))
                    break

                # 层级 2: 中等文本差异 (> 15 字符纯文本) — 需要语义或内容确认
                elif text_len_diff > 15:
                    if semantic_diff and word_diff >= 2:
                        findings.append(SQLiFinding(
                            url=url, param=param, method=method,
                            payload=true_payload, technique="Boolean-based",
                            evidence=f"Boolean blind: {len_diff}B/{text_len_diff} text diff, {word_diff} unique words, semantic={semantic_diff}",
                        ))
                        break
                    elif word_diff >= 4:
                        confirmed_small_diffs += 1
                        if confirmed_small_diffs >= 2:
                            findings.append(SQLiFinding(
                                url=url, param=param, method=method,
                                payload=true_payload, technique="Boolean-based",
                                evidence=f"Boolean blind (confirmed): {len_diff}B diff, {word_diff} unique words across 2+ payloads",
                            ))
                            break

                # 层级 3: 微小差异 (≤ 15 字符文本) — 仅双向语义 + 交叉验证
                elif bidirectional_semantic and word_diff >= 2:
                    payload_key = f"{true_payload}|{false_payload}"
                    if payload_key not in confirmed_payloads:
                        confirmed_payloads.add(payload_key)
                        confirmed_small_diffs += 1
                    if confirmed_small_diffs >= 2:
                        findings.append(SQLiFinding(
                            url=url, param=param, method=method,
                            payload=true_payload, technique="Boolean-based",
                            evidence=f"Boolean blind (semantic): {len_diff}B diff, bidirectional semantic pattern confirmed across 2+ payloads",
                        ))
                        break
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # Time-based 检测
    # ------------------------------------------------------------------

    def _check_time_based(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> list[SQLiFinding]:
        findings = []

        # 多次采样基线，取中位数（比单次测量更可靠）
        baseline_samples = []
        for _ in range(3):
            try:
                start = time.time()
                if form:
                    normal_data = self._inject_in_form(form, param, original_value or "normal")
                    if method.upper() == "GET":
                        self.session.get(form["action"], params=normal_data, timeout=self.timeout, allow_redirects=False)
                    else:
                        self.session.post(form["action"], data=normal_data, timeout=self.timeout, allow_redirects=False)
                else:
                    normal_url = self._inject_in_url(url, param, original_value or "normal")
                    self.session.get(normal_url, timeout=self.timeout, allow_redirects=False)
                baseline_samples.append(time.time() - start)
            except requests.RequestException:
                baseline_samples.append(self.timeout)
        baseline = sorted(baseline_samples)[1]  # 中位数

        # 页面本身就慢 → 跳过时间注入检测
        if baseline > 2.0:
            return findings

        for payload in SQLI_PAYLOADS["time_based"]:
            time.sleep(self.delay)
            try:
                start = time.time()
                try:
                    if form:
                        data = self._inject_in_form(form, param, payload, prefix=original_value)
                        if method.upper() == "GET":
                            self.session.get(
                                form["action"], params=data,
                                timeout=self.timeout, allow_redirects=False,
                            )
                        else:
                            self.session.post(
                                form["action"], data=data,
                                timeout=self.timeout, allow_redirects=False,
                            )
                    else:
                        test_url = self._inject_in_url(url, param, payload, prefix=original_value)
                        self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                except requests.ReadTimeout:
                    elapsed = time.time() - start
                    # ReadTimeout 是 SLEEP 等延迟函数的预期行为
                    findings.append(SQLiFinding(
                        url=url, param=param, method=method,
                        payload=payload, technique="Time-based",
                        evidence=f"Request timed out after {elapsed:.1f}s (baseline: {baseline:.1f}s)",
                    ))
                    break
                except requests.RequestException:
                    pass

                elapsed = time.time() - start
                # 要求至少比基线慢 2.5 倍且绝对延迟 ≥ 2 秒
                if elapsed >= baseline * 2.5 and elapsed >= 2.0:
                    findings.append(SQLiFinding(
                        url=url, param=param, method=method,
                        payload=payload, technique="Time-based",
                        evidence=f"Response delay: {elapsed:.1f}s (baseline: {baseline:.1f}s)",
                    ))
                    break
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # Union-based 检测
    # ------------------------------------------------------------------

    # PHP 错误模式 — 响应差异来自代码执行失败而非 SQL 注入
    PHP_ERROR_PATTERNS = [
        r"Warning:",
        r"Fatal error:",
        r"Parse error:",
        r"Notice:",
        r"include\(",
        r"require\(",
        r"failed to open stream",
        r"on line \d+",
        r"Stack trace:",
        r"undefined (?:variable|index|function|constant)",
        r"Call to undefined",
        r"No such file or directory",
        r"\.php</b> on line",
    ]

    def _check_union_based(
        self, url: str, param: str, method: str = "GET",
        form: Optional[dict] = None, original_value: str = "",
    ) -> list[SQLiFinding]:
        findings = []

        baseline_text, baseline_struct, _ = self._get_baseline_response(
            url, param, method, form, original_value,
        )
        baseline_tags = baseline_struct[1]

        for payload in SQLI_PAYLOADS["union_based"]:
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

                resp_text = resp.text
                len_diff = abs(len(resp_text) - len(baseline_text)) if baseline_text else 0

                # 过滤 1: 微小差异 → CSRF token / 时间戳等动态内容，不是 SQL 注入
                if len_diff < 30:
                    continue

                # 过滤 2: 响应包含 PHP 错误 → 差异来自代码执行失败，不是 SQL 注入
                php_error_count = sum(
                    1 for p in self.PHP_ERROR_PATTERNS
                    if re.search(p, resp_text, re.IGNORECASE)
                )
                if php_error_count >= 2:
                    continue

                # 过滤 3: 检测 payload 是否被原样回显（输入反射而非 SQL 执行）
                payload_normalized = re.sub(r"[\s'\"]", "", payload).lower()
                resp_normalized = re.sub(r"[\s'\"]", "", resp_text).lower()
                payload_echoed = payload_normalized in resp_normalized

                # 过滤 4: @@version / database() / user() 检查
                # 如果 DB 函数名原样出现在响应中 → 未被执行，仅回显
                has_db_leak = False
                db_funcs_in_payload = []
                for func in ["@@version", "database()", "user()", "table_name",
                             "column_name", "information_schema"]:
                    if func in payload.lower():
                        db_funcs_in_payload.append(func)

                if db_funcs_in_payload and baseline_text:
                    # DB 函数被原样回显 → 未被执行
                    if any(f in resp_text for f in db_funcs_in_payload):
                        pass
                    else:
                        # 检查是否存在仅在注入响应中出现、不在基线中的泄露模式
                        leak_patterns = [
                            r"\d+\.\d+\.\d+",             # 版本号 8.0.35
                            r"root@",                       # user() 输出
                            r"localhost",                   # DB host
                            r"MariaDB",                     # DB 类型
                        ]
                        for pat in leak_patterns:
                            match_resp = re.search(pat, resp_text, re.IGNORECASE)
                            match_base = re.search(pat, baseline_text, re.IGNORECASE)
                            if match_resp and not match_base:
                                has_db_leak = True
                                break

                # 过滤 5: 结构相似性 — 真实 UNION 注入应保持页面模板不变
                structure_similar = True
                if baseline_text and baseline_tags:
                    resp_tags = self._extract_structure(resp_text)[1]
                    if baseline_tags and resp_tags:
                        tag_jaccard = len(baseline_tags & resp_tags) / max(
                            len(baseline_tags | resp_tags), 1
                        )
                        structure_similar = tag_jaccard >= 0.6

                if has_db_leak:
                    findings.append(SQLiFinding(
                        url=url, param=param, method=method,
                        payload=payload, technique="Union-based",
                        evidence=f"UNION injection: response diff={len_diff} bytes, db_info_leak=True",
                    ))
                    break

                if len_diff > 200 and not payload_echoed and structure_similar:
                    findings.append(SQLiFinding(
                        url=url, param=param, method=method,
                        payload=payload, technique="Union-based",
                        evidence=f"UNION injection: response diff={len_diff} bytes, db_info_leak=False",
                    ))
                    break
            except requests.RequestException:
                continue
        return findings

    # ------------------------------------------------------------------
    # 扫描入口
    # ------------------------------------------------------------------

    def scan_url(self, url: str) -> list[SQLiFinding]:
        if self._should_skip(url) or self._should_skip_sqli(url):
            return self.findings
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for param, values in params.items():
            original_value = values[0] if values else ""
            for technique in [
                self._check_error_based,
                self._check_boolean_based,
                self._check_time_based,
                self._check_union_based,
            ]:
                findings = technique(url, param, "GET", original_value=original_value)
                self.findings.extend(findings)
                if findings:
                    break
        return self.findings

    def scan_form(self, form: dict) -> list[SQLiFinding]:
        if self._should_skip(form["action"]) or self._should_skip_sqli(form["action"]):
            return self.findings
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset", "hidden"):
                continue
            if inp["name"] in ("user_token", "csrf_token", "_token"):
                continue
            original_value = inp.get("value", "")
            for technique in [
                self._check_error_based,
                self._check_boolean_based,
                self._check_time_based,
                self._check_union_based,
            ]:
                findings = technique(
                    form["action"], inp["name"], form["method"], form,
                    original_value=original_value,
                )
                self.findings.extend(findings)
                if findings:
                    break
        return self.findings

    def scan(self, urls: set[str], forms: list[dict]) -> list[SQLiFinding]:
        for url in urls:
            if urllib.parse.urlparse(url).query:
                self.scan_url(url)
        for form in forms:
            self.scan_form(form)
        return self.findings
