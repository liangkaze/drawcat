#!/usr/bin/env python3
"""Drawcat — Automated Web Vulnerability Scanner & Defense System.

Usage:
    drawcat scan <target_url>                  Scan a target for SQLi and XSS
    drawcat scan <url> --cookie "PHPSESSID=xxx; security=low"
    drawcat scan <url> -u admin -p password --login-url /login.php
    drawcat scan <target_url> --ai             Scan with AI-enhanced report
    drawcat config                             Configure AI provider
    drawcat compare                            Run testbed comparison
    drawcat testbed                            Start vulnerable testbed
    drawcat testbed --secure                   Start secured testbed

"""

import argparse
import json
import os
import subprocess
import sys
import time


def _load_config() -> dict:
    """Load config.json from project root."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_config(cfg: dict) -> None:
    """Save config.json to project root."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _get_ai_config() -> dict:
    """Get AI configuration: config.json first, env var fallback."""
    cfg = _load_config()
    ai = cfg.get("ai", {})
    if not ai.get("api_key"):
        ai["api_key"] = os.environ.get("ANTHROPIC_API_KEY", "")
    return ai


def _parse_cookies(cookie_str: str) -> dict:
    """解析 cookie 字符串 'key1=val1; key2=val2' 为字典。"""
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            cookies[key.strip()] = val.strip()
    return cookies


def _parse_login_data(data_str: str) -> dict:
    """解析登录表单数据 'user=admin&pass=123' 为字典。"""
    data = {}
    for part in data_str.split("&"):
        if "=" in part:
            key, val = part.split("=", 1)
            data[key.strip()] = val.strip()
    return data


def cmd_scan(args):
    from scanner.scanner import Scanner
    from reporter.report_generator import ReportGenerator

    cookies = None
    if args.cookie:
        cookies = _parse_cookies(args.cookie)
        print(f"[*] Using cookies: {list(cookies.keys())}")

    login_data = None
    if args.login_data:
        login_data = _parse_login_data(args.login_data)
    elif args.username and args.password:
        login_data = {"username": args.username, "password": args.password}

    login_url = args.login_url if login_data else None
    if login_data and not login_url:
        login_url = "login.php"
        print(f"[*] Auto-detected login URL: {login_url}")

    # 种子 URL 列表
    seed_urls = []
    if args.urls:
        seed_urls = [u.strip() for u in args.urls.split(",") if u.strip()]

    print(f"\n[*] Starting scan against: {args.target}")
    print(f"[*] Max depth: {args.depth}, Max pages: {args.pages}")
    if login_url:
        print(f"[*] Authentication: {args.login_method} {login_url}")
    if seed_urls:
        print(f"[*] Seed URLs: {len(seed_urls)} additional pages")
    print()

    scanner = Scanner(
        target_url=args.target,
        max_depth=args.depth,
        max_pages=args.pages,
        timeout=args.timeout,
        delay=args.delay,
        cookies=cookies,
        username=args.username,
        password=args.password,
        login_url=login_url,
        login_data=login_data,
        login_method=args.login_method,
        seed_urls=seed_urls,
    )
    result = scanner.run()

    print(f"\n[+] Crawl complete: {result.urls_found} URLs, {result.forms_found} forms ({result.crawl_duration:.1f}s)")
    print(f"[+] Scan complete: {len(result.sqli_findings)} SQLi, {len(result.xss_findings)} XSS findings ({result.scan_duration:.1f}s)")

    # Print findings summary
    if result.sqli_findings:
        print("\n--- SQL Injection Findings ---")
        for f in result.sqli_findings:
            print(f"  [{f.technique}] {f.url} — param='{f.param}' — {f.evidence[:80]}")

    if result.xss_findings:
        print("\n--- XSS Findings ---")
        for f in result.xss_findings:
            print(f"  [{f.xss_type}] {f.url} — param='{f.param}' — {f.evidence[:80]}")

    if not result.sqli_findings and not result.xss_findings:
        print("\n[+] No vulnerabilities detected.")

    # Generate report
    ai_config = _get_ai_config()
    use_ai = args.ai and bool(ai_config.get("api_key"))
    reporter = ReportGenerator(ai_config=ai_config if use_ai else None)

    html_report = reporter.generate_html(result)
    json_report = reporter.generate_json(result)

    # 报告输出到 reports/ 目录
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(report_dir, exist_ok=True)

    filename = args.output or f"scan_report_{int(time.time())}.html"
    if not filename.endswith(".html"):
        filename += ".html"
    html_path = os.path.join(report_dir, os.path.basename(filename))
    json_path = html_path.replace(".html", ".json")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_report)

    print(f"\n[+] HTML report saved to: {html_path}")
    print(f"[+] JSON report saved to: {json_path}")

    if use_ai:
        print("[+] AI analysis included in report")


def cmd_compare(args):
    """Run scanner against both vulnerable and secured testbeds and compare results."""
    from scanner.scanner import Scanner
    from reporter.report_generator import ComparisonReport

    print("\n" + "=" * 60)
    print("  COMPARISON TEST: Vulnerable vs Secured Application")
    print("=" * 60)

    # Start testbed apps
    print("\n[*] Starting vulnerable testbed on port 5000...")
    vuln_proc = subprocess.Popen(
        [sys.executable, "-m", "testbed.app"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )

    print("[*] Starting secured testbed on port 5001...")
    sec_proc = subprocess.Popen(
        [sys.executable, "-m", "testbed.app_secure"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )

    time.sleep(2)

    # Check both processes started successfully
    for proc, name in [(vuln_proc, "vulnerable"), (sec_proc, "secured")]:
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            err_msg = stderr.decode() if stderr else f"Process exited with code {proc.returncode}"
            print(f"[!] Failed to start {name} testbed: {err_msg[:200]}")
            print("[!] Make sure ports 5000 and 5001 are available.")
            # Kill the other process if it started
            other = sec_proc if name == "vulnerable" else vuln_proc
            other.terminate()
            other.wait()
            return

    try:
        # Scan vulnerable
        print("\n[*] Scanning VULNERABLE testbed (http://127.0.0.1:5000)...")
        scanner = Scanner(
            target_url="http://127.0.0.1:5000",
            max_depth=2,
            max_pages=20,
            timeout=5,
            delay=0.1,
        )
        vuln_result = scanner.run()
        print(f"    Found: {len(vuln_result.sqli_findings)} SQLi, {len(vuln_result.xss_findings)} XSS")

        # Scan secured
        print("\n[*] Scanning SECURED testbed (http://127.0.0.1:5001)...")
        scanner2 = Scanner(
            target_url="http://127.0.0.1:5001",
            max_depth=2,
            max_pages=20,
            timeout=5,
            delay=0.1,
        )
        sec_result = scanner2.run()
        print(f"    Found: {len(sec_result.sqli_findings)} SQLi, {len(sec_result.xss_findings)} XSS")

        # Generate comparison
        report = ComparisonReport.compare(vuln_result, sec_result)
        print(report)

        # Save comparison
        report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(report_dir, exist_ok=True)
        filename = args.output or "comparison_report.txt"
        path = os.path.join(report_dir, os.path.basename(filename))
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Comparison report saved to: {path}")

    finally:
        print("\n[*] Shutting down testbed servers...")
        vuln_proc.terminate()
        sec_proc.terminate()
        vuln_proc.wait()
        sec_proc.wait()
        print("[+] Done.")


def cmd_config(args):
    """Interactive AI provider configuration wizard."""
    from reporter.report_generator import BUILTIN_PROVIDERS

    cfg = _load_config()
    ai = cfg.get("ai", {})

    print("\n" + "=" * 50)
    print("  Drawcat AI 配置向导")
    print("=" * 50)

    # 显示当前配置
    current_provider = ai.get("provider", "anthropic")
    current_model = ai.get("model", "")
    current_key = ai.get("api_key", "")
    print(f"\n当前配置:")
    print(f"  提供商: {current_provider}")
    print(f"  模型:   {current_model or '(未设置)'}")
    print(f"  API Key: {'***' + current_key[-4:] if len(current_key) > 4 else '(未设置)'}")

    if args.show:
        return

    # 选择提供商
    print(f"\n可选 AI 提供商:")
    providers_list = list(BUILTIN_PROVIDERS.keys())
    for i, key in enumerate(providers_list):
        info = BUILTIN_PROVIDERS[key]
        print(f"  [{i + 1}] {info['name']} ({key})")

    try:
        choice = input(f"\n选择提供商 [1-{len(providers_list)}, 默认 1]: ").strip()
        idx = int(choice) - 1 if choice else 0
        if not (0 <= idx < len(providers_list)):
            idx = 0
    except (ValueError, IndexError):
        idx = 0

    provider = providers_list[idx]
    info = BUILTIN_PROVIDERS[provider]

    # 选择模型
    model = info["model"]
    if info["models"]:
        print(f"\n{info['name']} 可用模型:")
        for i, m in enumerate(info["models"]):
            print(f"  [{i + 1}] {m}")
        m_choice = input(f"选择模型 [1-{len(info['models'])}, 默认 1]: ").strip()
        try:
            m_idx = int(m_choice) - 1 if m_choice else 0
            if 0 <= m_idx < len(info["models"]):
                model = info["models"][m_idx]
        except (ValueError, IndexError):
            pass
    elif provider == "custom":
        model = input("输入模型名称: ").strip() or ""

    # API Key
    print(f"\nAPI Key ({info['name']}):")
    if current_key:
        print(f"  当前: ***{current_key[-4:]}")
        use_current = input("  是否继续使用当前 Key? [Y/n]: ").strip().lower()
        api_key = current_key if use_current != "n" else ""
    else:
        api_key = input("  输入 API Key: ").strip()

    # Base URL
    base_url = info["base_url"]
    if provider == "custom":
        base_url = input(f"  输入 API Base URL (如 https://api.openai.com/v1): ").strip() or ""

    # 保存
    cfg["ai"] = {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "max_tokens": ai.get("max_tokens", 1000),
        "base_url": base_url,
    }
    _save_config(cfg)

    print(f"\n[+] 配置已保存到 config.json")
    print(f"    提供商: {provider}")
    print(f"    模型:   {model}")
    print(f"    API Key: {'***' + api_key[-4:] if len(api_key) > 4 else '(未设置)'}")
    print(f"\n现在可以用 --ai 参数扫描了:")
    print(f"  python drawcat.py scan http://target.com --ai")


def cmd_testbed(args):
    """Start a testbed application."""
    if args.secure:
        from testbed.app_secure import app, init_db
        init_db()
        print("[+] Starting SECURED testbed on http://127.0.0.1:5001")
        app.run(host="127.0.0.1", port=5001, debug=False)
    else:
        from testbed.app import app, init_db
        init_db()
        print("[+] Starting VULNERABLE testbed on http://127.0.0.1:5000")
        print("[!] WARNING: This app contains deliberate vulnerabilities. Do NOT expose to networks.")
        app.run(host="127.0.0.1", port=5000, debug=False)


def main():
    parser = argparse.ArgumentParser(
        description="Drawcat — Automated Web Vulnerability Scanner & Defense System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  drawcat scan http://target.com
  drawcat scan http://target.com -c "PHPSESSID=xxx; security=low" -dp 3
  drawcat scan http://target.com -u admin -p pass -L /login.php -dp 3
  drawcat scan http://target.com -ai -o report.html
  drawcat config

Short flags:
  -dp   --depth         -pg   --pages         -t    --timeout
  -dy   --delay         -c    --cookie        -u    --username
  -p    --password      -L    --login-url     -ld   --login-data
  -lm   --login-method  -o    --output        -ai   --ai

  drawcat compare
  drawcat testbed
  drawcat testbed --secure""",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Scan a target URL for vulnerabilities")
    scan_p.add_argument("target", help="Target URL to scan")
    scan_p.add_argument("-dp", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    scan_p.add_argument("-pg", "--pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    scan_p.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    scan_p.add_argument("-dy", "--delay", type=float, default=0.15, help="Request delay in seconds (default: 0.15)")

    # 认证选项
    scan_p.add_argument("-c", "--cookie", help='Session cookie string, e.g. "PHPSESSID=xxx; security=low"')
    scan_p.add_argument("-u", "--username", help="Login username")
    scan_p.add_argument("-p", "--password", help="Login password")
    scan_p.add_argument("-L", "--login-url", help="Login page URL, e.g. /login.php")
    scan_p.add_argument("-ld", "--login-data", help="Custom login POST data, e.g. 'user=admin&pass=123'")
    scan_p.add_argument("-lm", "--login-method", default="POST", choices=["GET", "POST"], help="Login HTTP method (default: POST)")

    # 目标选项
    scan_p.add_argument("--urls", help="Comma-separated seed URLs to scan, e.g. '/page1,/page2?id=1'")

    # 报告选项
    scan_p.add_argument("-o", "--output", help="Output file path for HTML report")
    scan_p.add_argument("-ai", "--ai", action="store_true", help="Enable AI analysis via Claude API")
    scan_p.set_defaults(func=cmd_scan)

    # compare
    cmp_p = sub.add_parser("compare", help="Run vulnerability vs secured testbed comparison")
    cmp_p.add_argument("--output", "-o", help="Output file for comparison report")
    cmp_p.set_defaults(func=cmd_compare)

    # testbed
    tb_p = sub.add_parser("testbed", help="Start a testbed server")
    tb_p.add_argument("--secure", action="store_true", help="Start the secured version")
    tb_p.set_defaults(func=cmd_testbed)

    # config
    cfg_p = sub.add_parser("config", help="Interactive AI provider configuration")
    cfg_p.add_argument("--show", action="store_true", help="Show current config only")
    cfg_p.set_defaults(func=cmd_config)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
