"""Web crawler for discovering URLs and forms on a target domain."""

from __future__ import annotations

import re
import time
import urllib.parse
from collections import deque
from typing import Optional

import requests
from bs4 import BeautifulSoup


class Crawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 10,
        delay: float = 0.5,
        session: Optional[requests.Session] = None,
        cookies: Optional[dict] = None,
        auth: Optional[tuple[str, str]] = None,
        login_url: Optional[str] = None,
        login_data: Optional[dict] = None,
        login_method: str = "POST",
    ):
        # 如果 base_url 指向文件（如 index.php），自动取父目录作为爬虫根路径
        parsed = urllib.parse.urlparse(base_url)
        path = parsed.path.rstrip("/")
        if path and "." in path.rsplit("/", 1)[-1]:
            # 最后一段含 "." → 是文件名，取父目录
            path = path.rsplit("/", 1)[0]
        self.base_url = urllib.parse.urlunparse(
            parsed._replace(path=path + "/" if path else "/")
        )
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay

        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            }
        )

        # 设置初始 Cookie
        if cookies:
            for key, value in cookies.items():
                self.session.cookies.set(key, value)

        # HTTP Basic Auth
        if auth:
            self.session.auth = auth

        self.login_url = login_url
        self.login_data = login_data or {}
        self.login_method = login_method.upper()

        self.visited: set[str] = set()
        self.discovered_urls: set[str] = set()
        self.forms: list[dict] = []
        self.base_domain = urllib.parse.urlparse(base_url).netloc

    def _do_login(self) -> bool:
        """执行登录认证，支持 CSRF token 自动获取（兼容 DVWA 等应用）。"""
        if not self.login_url:
            return True
        try:
            login_url = urllib.parse.urljoin(self.base_url, self.login_url.lstrip("/"))
            print(f"  [DEBUG] Login URL: {login_url}")

            # 先 GET 登录页，提取隐藏字段（CSRF token 等）
            get_resp = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
            print(f"  [DEBUG] GET login page: status={get_resp.status_code}")
            
            soup = BeautifulSoup(get_resp.text, "lxml")

            # 自动提取表单中所有隐藏字段
            form = soup.find("form")
            post_data = dict(self.login_data) if self.login_data else {}
            if form:
                for hidden in form.find_all("input", {"type": "hidden"}):
                    name = hidden.get("name")
                    value = hidden.get("value", "")
                    if name and name not in post_data:
                        post_data[name] = value
                        print(f"  [DEBUG] Extracted hidden field: {name}={value}")
                # 自动补全 submit 按钮
                for submit in form.find_all("input", {"type": "submit"}):
                    name = submit.get("name")
                    value = submit.get("value", "")
                    if name and name not in post_data:
                        post_data[name] = value
                        print(f"  [DEBUG] Extracted submit field: {name}={value}")

            print(f"  [DEBUG] Post data: {post_data}")
            
            if self.login_method == "POST":
                resp = self.session.post(
                    login_url, data=post_data,
                    timeout=self.timeout, allow_redirects=True,
                )
            else:
                resp = self.session.get(
                    login_url, params=post_data,
                    timeout=self.timeout, allow_redirects=True,
                )

            print(f"  [DEBUG] Login response: status={resp.status_code}, url={resp.url}")
            print(f"  [DEBUG] Response contains 'logout': {'logout' in resp.text.lower()}")
            print(f"  [DEBUG] Current cookies: {dict(self.session.cookies)}")

            # 判断登录是否成功：不再出现 login 表单 / 出现 logout 链接
            success = (
                resp.status_code < 400
                and ("logout" in resp.text.lower() or "index.php" in resp.url)
            )
            if success:
                print(f"  [+] Login successful")
                # DVWA 等靶场登录后安全等级默认可能为 impossible，强制覆盖为 low
                parsed_base = urllib.parse.urlparse(self.base_url)
                domain = parsed_base.netloc
                current_security = self.session.cookies.get("security")
                if current_security and current_security != "low":
                    self.session.cookies.set("security", "low", domain=domain, path="/")
                    print(f"  [DEBUG] Override security cookie: {current_security} -> low")
            else:
                print(f"  [!] Login may have failed (status={resp.status_code})")
            return success
        except requests.RequestException as e:
            print(f"  [!] Login failed: {e}")
            return False

    # URL 黑名单：爬虫不应访问的页面（会导致登出、修改配置等副作用）
    CRAWL_SKIP_PATTERNS = [
        "logout.php", "login.php", "setup.php",
        "security.php", "phpinfo.php",
    ]

    def _is_internal(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    def _normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc == "":
            url = urllib.parse.urljoin(self.base_url, url)
        return url.split("#")[0]

    def _extract_links(self, html: str, current_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = self._normalize_url(urllib.parse.urljoin(current_url, href))
            if self._is_internal(full_url) and not full_url.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico", ".svg")):
                # 跳过危险 URL（登出、修改配置等有副作用的页面）
                if any(p in full_url.lower() for p in self.CRAWL_SKIP_PATTERNS):
                    continue
                links.append(full_url)
        return links

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            action_url = self._normalize_url(urllib.parse.urljoin(page_url, action))
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                input_info = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                }
                if input_info["name"]:
                    inputs.append(input_info)
            forms.append(
                {
                    "page_url": page_url,
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                }
            )
        return forms

    def crawl(self, seed_urls: list = None) -> tuple[set[str], list[dict]]:
        # 先登录
        if self.login_url and not self._do_login():
            print("  [!] Continuing without authentication...")

        queue = deque([(self.base_url, 0)])
        # 额外种子 URL 也加入队列
        if seed_urls:
            for url in seed_urls:
                full = urllib.parse.urljoin(self.base_url, url)
                queue.append((full, 0))

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            url = self._normalize_url(url)

            if url in self.visited:
                continue
            if depth > self.max_depth:
                continue

            self.visited.add(url)
            self.discovered_urls.add(url)

            try:
                time.sleep(self.delay)
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue

                html = resp.text
                page_url = resp.url  # 使用实际响应 URL（跟随重定向后的）
                forms = self._extract_forms(html, page_url)
                self.forms.extend(forms)

                if depth < self.max_depth:
                    links = self._extract_links(html, page_url)
                    for link in links:
                        link = self._normalize_url(link)
                        if link not in self.visited:
                            queue.append((link, depth + 1))

            except requests.RequestException:
                continue

        return self.discovered_urls, self.forms
