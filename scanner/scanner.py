"""Main scanner orchestrator combining crawler, SQLi and XSS detection."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import requests

from scanner.crawler import Crawler
from scanner.sql_injection import SQLInjectionScanner, SQLiFinding
from scanner.xss import XSSScanner, XSSFinding


@dataclass
class ScanResult:
    target: str
    urls_found: int
    forms_found: int
    sqli_findings: list[SQLiFinding]
    xss_findings: list[XSSFinding]
    crawl_duration: float = 0.0
    scan_duration: float = 0.0


class Scanner:
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 30,
        timeout: int = 10,
        delay: float = 0.2,
        cookies: Optional[dict] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        login_url: Optional[str] = None,
        login_data: Optional[dict] = None,
        login_method: str = "POST",
        seed_urls: Optional[list] = None,
    ):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay
        self.cookies = cookies
        self.username = username
        self.password = password
        self.login_url = login_url
        self.login_data = login_data
        self.login_method = login_method
        self.seed_urls = seed_urls or []

    def run(self) -> ScanResult:
        # 创建共享 Session（认证信息在整个扫描过程中保持一致）
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            }
        )

        # 设置 Cookie
        if self.cookies:
            for key, value in self.cookies.items():
                session.cookies.set(key, value)

        # 构建登录数据
        # 优先使用预定义的 login_data（如 DVWA 模式传入的）
        if self.login_data:
            login_data = self.login_data
        elif self.username and self.password:
            login_data = {"username": self.username, "password": self.password}
        else:
            login_data = None

        # 爬取
        t0 = time.time()
        crawler = Crawler(
            base_url=self.target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
            timeout=self.timeout,
            delay=self.delay,
            session=session,
            login_url=self.login_url,
            login_data=login_data,
            login_method=self.login_method,
        )
        urls, forms = crawler.crawl(seed_urls=self.seed_urls)
        crawl_time = time.time() - t0

        print(f"  [*] Crawled {len(urls)} URLs, found {len(forms)} forms")

        # SQLi 扫描（共用 session）
        t1 = time.time()
        sqli_scanner = SQLInjectionScanner(
            timeout=self.timeout, delay=self.delay, session=session,
        )
        sqli_findings = sqli_scanner.scan(urls, forms)

        # XSS 扫描（共用 session）
        xss_scanner = XSSScanner(
            timeout=self.timeout, delay=self.delay, session=session,
        )
        xss_findings = xss_scanner.scan(urls, forms)
        scan_time = time.time() - t1

        return ScanResult(
            target=self.target_url,
            urls_found=len(urls),
            forms_found=len(forms),
            sqli_findings=sqli_findings,
            xss_findings=xss_findings,
            crawl_duration=crawl_time,
            scan_duration=scan_time,
        )
