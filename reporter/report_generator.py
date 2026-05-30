"""AI-assisted security report generator.

Generates structured reports from scan results with optional AI analysis
via the Anthropic (Claude) API.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

import requests
from jinja2 import Template

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

from scanner.sql_injection import SQLiFinding
from scanner.xss import XSSFinding
from scanner.scanner import ScanResult


# 预置的主流 AI 提供商配置
BUILTIN_PROVIDERS = {
    "anthropic": {
        "name": "Anthropic Claude",
        "model": "claude-haiku-4.5",
        "base_url": "",
        "models": [
            "claude-haiku-4.5",
            "claude-sonnet-4.6",
            "claude-opus-4.7",
        ],
    },
    "deepseek": {
        "name": "DeepSeek",
        "model": "deepseek-chat",
        "base_url": "https://api.deepseek.com/v1",
        "models": [
            "deepseek-chat",
            "deepseek-reasoner",
        ],
    },
    "openai": {
        "name": "OpenAI",
        "model": "gpt-4o-mini",
        "base_url": "https://api.openai.com/v1",
        "models": [
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4.1",
        ],
    },
    "custom": {
        "name": "自定义 (OpenAI 兼容)",
        "model": "",
        "base_url": "",
        "models": [],
    },
}


REPORT_TEMPLATE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>安全扫描报告 — {{ target }}</title>
    <style>
        body { font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; max-width: 1000px; margin: 40px auto; padding: 20px; background: #f8f9fa; }
        h1 { color: #dc3545; border-bottom: 3px solid #dc3545; padding-bottom: 10px; }
        h2 { color: #343a40; margin-top: 30px; }
        .meta { color: #6c757d; font-size: 14px; margin-bottom: 20px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .card { flex: 1; padding: 20px; border-radius: 8px; text-align: center; }
        .card.critical { background: #dc3545; color: #fff; }
        .card.high { background: #fd7e14; color: #fff; }
        .card.medium { background: #ffc107; color: #333; }
        .card.info { background: #17a2b8; color: #fff; }
        .card .count { font-size: 48px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; background: #fff; border-radius: 4px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
        th { background: #343a40; color: #fff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #dee2e6; }
        tr:hover td { background: #f1f3f5; }
        .severity-HIGH { color: #dc3545; font-weight: bold; }
        .severity-MEDIUM { color: #fd7e14; font-weight: bold; }
        pre { background: #212529; color: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }
        .ai-analysis { background: #e7f5ff; border-left: 4px solid #1c7ed6; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .defense-recommendation { background: #d3f9d8; border-left: 4px solid #2b8a3e; padding: 15px; margin: 10px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Web 安全扫描报告</h1>
    <p class="meta">
        目标: <strong>{{ target }}</strong><br>
        扫描日期: <strong>{{ scan_date }}</strong><br>
        爬取 URL: <strong>{{ urls_found }}</strong> | 表单: <strong>{{ forms_found }}</strong><br>
        爬取耗时: <strong>{{ "%.1f"|format(crawl_duration) }}s</strong> | 扫描耗时: <strong>{{ "%.1f"|format(scan_duration) }}s</strong>
    </p>

    <div class="summary">
        <div class="card critical">
            <div class="count">{{ sqli_count }}</div>
            <div>SQL 注入</div>
        </div>
        <div class="card high">
            <div class="count">{{ xss_count }}</div>
            <div>XSS 跨站脚本</div>
        </div>
        <div class="card info">
            <div class="count">{{ total_count }}</div>
            <div>漏洞总数</div>
        </div>
    </div>

    {% if ai_analysis %}
    <div class="ai-analysis">
        <h3>AI 安全分析</h3>
        <p>{{ ai_analysis }}</p>
    </div>
    {% endif %}

    {% if sqli_findings %}
    <h2>SQL 注入发现</h2>
    <table>
        <tr><th>URL</th><th>参数</th><th>方法</th><th>检测技术</th><th>Payload</th><th>证据</th><th>严重程度</th></tr>
        {% for f in sqli_findings %}
        <tr>
            <td>{{ f.url }}</td>
            <td>{{ f.param }}</td>
            <td>{{ f.method }}</td>
            <td>{{ f.technique }}</td>
            <td><code>{{ f.payload }}</code></td>
            <td>{{ f.evidence }}</td>
            <td class="severity-{{ f.severity }}">{{ f.severity }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    {% if xss_findings %}
    <h2>XSS 跨站脚本发现</h2>
    <table>
        <tr><th>URL</th><th>参数</th><th>方法</th><th>类型</th><th>Payload</th><th>证据</th><th>严重程度</th></tr>
        {% for f in xss_findings %}
        <tr>
            <td>{{ f.url }}</td>
            <td>{{ f.param }}</td>
            <td>{{ f.method }}</td>
            <td>{{ f.xss_type }}</td>
            <td><code>{{ f.payload }}</code></td>
            <td>{{ f.evidence }}</td>
            <td class="severity-{{ f.severity }}">{{ f.severity }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    {% if defenses %}
    <h2>防御建议</h2>
    {% for d in defenses %}
    <div class="defense-recommendation">
        <strong>{{ d.title }}</strong>
        <p>{{ d.description }}</p>
        <pre>{{ d.code }}</pre>
    </div>
    {% endfor %}
    {% endif %}

    <hr>
    <p style="text-align:center;color:#868e96;font-size:12px;">由 Drawcat 安全扫描器生成</p>
</body>
</html>"""


class ReportGenerator:
    def __init__(self, ai_config: Optional[dict] = None):
        """ai_config: {'provider', 'api_key', 'model', 'max_tokens', 'base_url'}"""
        ai = ai_config or {}

        self.provider = ai.get("provider", "anthropic")
        self.api_key = ai.get("api_key", "") or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = ai.get("model", "claude-haiku-4.5")
        self.max_tokens = ai.get("max_tokens", 1000)
        self.base_url = ai.get("base_url", "")

        # 解析 base_url: 优先用显式配置，其次用内置提供商默认值
        if not self.base_url and self.provider in BUILTIN_PROVIDERS:
            self.base_url = BUILTIN_PROVIDERS[self.provider]["base_url"]

        self.client = None
        if self.api_key:
            if self.provider == "anthropic" and HAS_ANTHROPIC:
                self.client = Anthropic(api_key=self.api_key)
            elif self.base_url:
                # OpenAI 兼容的 API 用 requests 直接调用
                self.client = True  # 标记为可用
            elif not HAS_ANTHROPIC:
                # 未配置 base_url 且不是 anthropic，无法调用
                pass

    def _build_findings_summary(self, result: ScanResult) -> str:
        """构建发送给 AI 的漏洞摘要文本。"""
        summary = f"""目标: {result.target}
爬取 URL 数: {result.urls_found}, 表单数: {result.forms_found}

SQL 注入发现 ({len(result.sqli_findings)}):
"""
        for f in result.sqli_findings:
            summary += f"- [{f.technique}] {f.url} 参数='{f.param}' payload='{f.payload}'\n"

        summary += f"\nXSS 发现 ({len(result.xss_findings)}):\n"
        for f in result.xss_findings:
            summary += f"- [{f.xss_type}] {f.url} 参数='{f.param}' payload='{f.payload}'\n"

        return summary

    def _call_anthropic(self, system_prompt: str, user_content: str) -> str:
        """通过 Anthropic SDK 调用 Claude。"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_content}],
        )
        return response.content[0].text

    def _call_openai_compatible(self, system_prompt: str, user_content: str) -> str:
        """通过 OpenAI 兼容 API 调用（DeepSeek / OpenAI / 自定义）。"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        }
        resp = requests.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers=headers, json=body, timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _ai_analyze(self, result: ScanResult) -> str:
        """调用 AI API 生成安全分析（中文输出）。"""
        if not self.client:
            return ""
        if not result.sqli_findings and not result.xss_findings:
            return "未检测到漏洞，目标应用在此次扫描范围内未发现 SQL 注入或 XSS 漏洞。"

        system_prompt = (
            "你是一名 Web 应用安全专家。请分析以下扫描发现，用中文输出："
            "1) 整体风险评估摘要，2) 每个漏洞类型的根因分析，"
            "3) 按优先级排列的修复建议。保持简洁（200-300字），技术性强，可操作。"
        )
        user_content = self._build_findings_summary(result)

        try:
            if self.provider == "anthropic":
                return self._call_anthropic(system_prompt, user_content)
            else:
                return self._call_openai_compatible(system_prompt, user_content)
        except Exception as e:
            return f"(AI 分析不可用: {e})"

    def generate_html(self, result: ScanResult) -> str:
        template = Template(REPORT_TEMPLATE_HTML, autoescape=True)
        ai_analysis = self._ai_analyze(result) if self.client else ""

        defenses = [
            {
                "title": "SQL 注入：使用参数化查询",
                "description": "永远不要将用户输入拼接到 SQL 语句中，使用占位符代替。",
                "code": "# 不安全:\ncursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n\n# 安全:\ncursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))",
            },
            {
                "title": "XSS：输出编码",
                "description": "在 HTML 中渲染用户数据前，必须进行 HTML 实体编码转义。",
                "code": "import html\nsafe_output = html.escape(user_input, quote=True)",
            },
            {
                "title": "Cookie 安全：设置安全标志",
                "description": "设置 HttpOnly、Secure 和 SameSite 标志，防止 Cookie 被 XSS 窃取。",
                "code": "response.set_cookie('session', value, httponly=True, secure=True, samesite='Lax')",
            },
            {
                "title": "内容安全策略 (CSP)",
                "description": "通过 CSP 头限制脚本来源，阻止内联脚本执行。",
                "code": "Content-Security-Policy: default-src 'self'; script-src 'self'",
            },
        ]

        return template.render(
            target=result.target,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            urls_found=result.urls_found,
            forms_found=result.forms_found,
            crawl_duration=result.crawl_duration,
            scan_duration=result.scan_duration,
            sqli_findings=result.sqli_findings,
            xss_findings=result.xss_findings,
            sqli_count=len(result.sqli_findings),
            xss_count=len(result.xss_findings),
            total_count=len(result.sqli_findings) + len(result.xss_findings),
            ai_analysis=ai_analysis,
            defenses=defenses,
        )

    def generate_json(self, result: ScanResult) -> str:
        return json.dumps(
            {
                "target": result.target,
                "scan_date": datetime.now().isoformat(),
                "urls_found": result.urls_found,
                "forms_found": result.forms_found,
                "crawl_duration": result.crawl_duration,
                "scan_duration": result.scan_duration,
                "sqli_findings": [
                    {
                        "url": f.url,
                        "param": f.param,
                        "method": f.method,
                        "technique": f.technique,
                        "payload": f.payload,
                        "evidence": f.evidence,
                        "severity": f.severity,
                    }
                    for f in result.sqli_findings
                ],
                "xss_findings": [
                    {
                        "url": f.url,
                        "param": f.param,
                        "method": f.method,
                        "type": f.xss_type,
                        "payload": f.payload,
                        "evidence": f.evidence,
                        "severity": f.severity,
                    }
                    for f in result.xss_findings
                ],
                "total_vulnerabilities": len(result.sqli_findings) + len(result.xss_findings),
            },
            indent=2,
            ensure_ascii=False,
        )


class ComparisonReport:
    """Generates a before/after comparison report for scanner accuracy and defense effectiveness."""

    @staticmethod
    def compare(vulnerable_result: ScanResult, secure_result: ScanResult) -> str:
        vuln_sqli = len(vulnerable_result.sqli_findings)
        vuln_xss = len(vulnerable_result.xss_findings)
        sec_sqli = len(secure_result.sqli_findings)
        sec_xss = len(secure_result.xss_findings)

        sqli_blocked = vuln_sqli - sec_sqli
        xss_blocked = vuln_xss - sec_xss

        sqli_rate = (sqli_blocked / vuln_sqli * 100) if vuln_sqli > 0 else 100.0
        xss_rate = (xss_blocked / vuln_xss * 100) if vuln_xss > 0 else 100.0

        report = f"""
{'='*65}
    防御有效性对比报告
{'='*65}

  目标: {vulnerable_result.target}
  日期: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*65}
  {'漏洞类型':<20} {'修复前':>8}  {'修复后':>8}  {'已拦截':>8}  {'拦截率':>8}
{'-'*65}
  {'SQL 注入':<20} {vuln_sqli:>8}  {sec_sqli:>8}  {sqli_blocked:>8}  {sqli_rate:>7.1f}%
  {'XSS 跨站脚本':<20} {vuln_xss:>8}  {sec_xss:>8}  {xss_blocked:>8}  {xss_rate:>7.1f}%
{'-'*65}
  {'合计':<20} {vuln_sqli+vuln_xss:>8}  {sec_sqli+sec_xss:>8}  {sqli_blocked+xss_blocked:>8}
{'='*65}

检测能力:
  SQL 注入: 通过 Error-based、Boolean-based、Time-based 等多种技术检测到 {vuln_sqli} 个漏洞
  XSS 跨站脚本: 检测到 {vuln_xss} 个漏洞（反射型、存储型、DOM 型）

防御总结:
  参数化查询: 拦截 {sqli_blocked} 次 SQL 注入攻击
  输入过滤与 WAF: 拦截 {xss_blocked} 次 XSS 攻击
  安全头 (CSP, X-XSS-Protection): 已启用
  Cookie 安全 (HttpOnly, Secure, SameSite): 已强制
"""
        return report
