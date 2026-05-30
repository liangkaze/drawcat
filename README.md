# Drawcat — 自动化 Web 漏洞扫描器

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-30%2F30-green.svg)]()

开箱即用的 Web 安全扫描器，支持 **SQL 注入** 和 **XSS 跨站脚本** 的自动化检测，可选 AI 增强分析报告。内置漏洞测试台和安全对照版本，方便验证扫描器准确性和防御效果。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 扫描目标
python drawcat.py scan http://target.com

# 3. (可选) AI 分析需要安装 anthropic
pip install anthropic
python drawcat.py scan http://target.com --ai
```

## 功能

### 爬虫引擎
- 自动发现同域页面和表单（链接深度可配置）
- 支持 Cookie / 登录表单认证（自动提取 CSRF token）
- 可指定种子 URL 列表引导爬取路径

### SQL 注入检测 (4 种技术)
| 技术 | 原理 | 准确度 |
|------|------|:---:|
| Error-based | 触发数据库错误，比对基线排除页面自带错误文本 | 高 |
| Boolean-based | true/false 二元 payload 对比响应差异，三层级判定（大幅/中等/微小差异 + 语义分析） | 中 |
| Time-based | SLEEP/BENCHMARK 延迟注入，多次采样中位数基线 | 中 |
| Union-based | UNION SELECT 扩展结果集，多重过滤（PHP 错误排除、payload 回显检测、结构相似性、DB 信息泄露） | 高 |

### XSS 检测 (3 种类型)
| 类型 | 原理 |
|------|------|
| Reflected | 注入 payload 检测响应回显，分析 HTML 上下文（标签内/外、属性值、事件处理器、标签 breakout） |
| Stored | POST 注入后 GET 二次验证确认持久化，区分静态文档示例 |
| DOM-based | 检测 JavaScript 中 DOM sink 函数（innerHTML、document.write、eval 等）是否受参数控制 |

### AI 分析
- 支持 Anthropic Claude / DeepSeek / OpenAI / 自定义 OpenAI 兼容 API
- 自动生成风险评估摘要、根因分析和优先修复建议（中文输出）
- HTML + JSON 双格式报告，包含防御代码示例

### 防御参考模块
- `SimpleWAF` — 请求级防火墙（速率限制 + 输入检测 + 安全头注入）
- `InputFilter` — SQLi/XSS 模式检测 + HTML 实体编码 + 参数白名单验证
- `ParamQuery` — 参数化查询封装（SQLite），强制占位符接口
- `CookieSecurity` — HttpOnly / Secure / SameSite 安全配置 + 审计

### 漏洞测试台
- 内置有漏洞版本（`drawcat testbed`）和安全版本（`drawcat testbed --secure`）
- `drawcat compare` 一键对比扫描结果，验证防御有效性

## 用法

### 基础扫描
```bash
python drawcat.py scan http://example.com
```

### 深度扫描 + AI 报告
```bash
python drawcat.py scan http://example.com -dp 5 -pg 1000 --ai -o report.html
```

### 带 Cookie 扫描
```bash
python drawcat.py scan http://example.com -c "PHPSESSID=xxx; security=low"
```

### 带登录表单扫描
```bash
python drawcat.py scan http://example.com -u admin -p password -L /login.php
```

### 指定种子 URL
```bash
python drawcat.py scan http://example.com --urls "/admin,/api/users?id=1,/search?q=test"
```

### 对比漏洞版 vs 安全版
```bash
python drawcat.py compare
```

### 配置 AI 提供商
```bash
python drawcat.py config
```

### 启动测试台
```bash
python drawcat.py testbed               # 漏洞版 (port 5000)
python drawcat.py testbed --secure      # 安全版 (port 5001)
```

## 参数速查

| 短参数 | 长参数 | 说明 | 默认值 |
|--------|--------|------|--------|
| `-dp` | `--depth` | 爬取深度 | 2 |
| `-pg` | `--pages` | 最大页面数 | 50 |
| `-t` | `--timeout` | 请求超时(秒) | 10 |
| `-dy` | `--delay` | 请求间隔(秒) | 0.15 |
| `-u` | `--username` | 登录用户名 | — |
| `-p` | `--password` | 登录密码 | — |
| `-L` | `--login-url` | 登录页面路径 | — |
| `-ld` | `--login-data` | 自定义 POST 数据 | — |
| `-lm` | `--login-method` | GET 或 POST | POST |
| `-c` | `--cookie` | Session Cookie 字符串 | — |
| `-ai` | `--ai` | 启用 AI 分析 | — |
| `-o` | `--output` | 报告输出路径 | 自动生成 |
| | `--urls` | 逗号分隔的种子 URL | — |

## AI 提供商

| 提供商 | 预置模型 | 说明 |
|--------|----------|------|
| Anthropic Claude | Haiku 4.5 / Sonnet 4.6 / Opus 4.7 | 通过 Anthropic SDK |
| DeepSeek | deepseek-chat / deepseek-reasoner | OpenAI 兼容 API |
| OpenAI | gpt-4o-mini / gpt-4o / gpt-4.1 | OpenAI 兼容 API |
| 自定义 | 任意模型 | 兼容 `/chat/completions` 端点即可 |

配置方式（三选一）：

```bash
python drawcat.py config                           # 交互式向导
export ANTHROPIC_API_KEY="sk-..."                 # 环境变量
```

或直接编辑 `config.json`：
```json
{
  "ai": {
    "provider": "deepseek",
    "api_key": "sk-你的密钥",
    "model": "deepseek-chat",
    "max_tokens": 1000,
    "base_url": "https://api.deepseek.com/v1"
  }
}
```

## 检测流程

```
 Crawler                 Scanner                Reporter
 ┌──────────┐           ┌──────────┐           ┌──────────┐
 │ 发现 URL  │ ───────→ │ SQLi 检测 │ ───────→ │ HTML 报告 │
 │ 发现表单  │           │ XSS 检测  │           │ JSON 报告 │
 │ 登录认证  │           │ Payload库 │           │ AI 分析   │
 └──────────┘           └──────────┘           └──────────┘
```

对每个 URL 参数和表单输入，SQLi 扫描器按 Error → Boolean → Time → Union 顺序依次检测。XSS 扫描器按 Reflected → DOM → Stored 顺序检测。任一技术发现漏洞即停止对该参数的后续检测，减少请求量。

### 误报控制

- Error-based: 双重基线（原始值 + 安全值）排除页面自带错误文本，文档页 `<pre>/<code>` 过滤，SQL 上下文关键词验证
- Boolean-based: 三层级判定，HTML 噪声剥离，语义差异分析，交叉验证
- Time-based: 三次采样取中位数基线，2.5x 基线阈值 + 2s 绝对最小延迟
- Union-based: PHP 错误排除，payload 回显检测，结构相似性验证，DB 函数原样回显过滤
- XSS: HTML 上下文分析（属性值安全封装 vs breakout），实体编码检测，SQL 错误上下文排除，CSP 头评估降权
- 跨页面过滤: XSS 页面自动跳过 SQLi 检测，SQLi 页面 XSS 需排除 SQL 错误回显

## 项目结构

```
drawcat/
├── drawcat.py              # CLI 入口
├── pyproject.toml           # 包配置
├── config.example.json      # AI 配置模板（不含密钥）
├── requirements.txt         # 依赖清单
├── scanner/                 # 扫描引擎
│   ├── scanner.py           # 调度器
│   ├── crawler.py           # 爬虫
│   ├── sql_injection.py     # SQLi 检测 (4 种技术)
│   ├── xss.py               # XSS 检测 (3 种类型)
│   ├── payloads.py          # Payload 加载
│   └── payloads/            # JSON Payload 库（可定制）
├── reporter/                # 报告生成
│   └── report_generator.py  # HTML/JSON + AI 分析 + 对比报告
├── defense/                 # 防御参考实现
│   ├── waf.py               # 简易 WAF
│   ├── input_filter.py      # 输入过滤
│   ├── cookie_security.py   # Cookie 安全
│   └── param_query.py       # 参数化查询
├── testbed/                 # 漏洞测试台
│   ├── app.py               # 漏洞版 (port 5000)
│   ├── app_secure.py        # 安全版 (port 5001)
│   └── templates/
└── tests/                   # 30 个单元测试
```

## Payload 定制

扫描器的攻击 payload 存储在 JSON 文件中，无需修改 Python 代码即可定制：

- `scanner/payloads/sqli.json` — Error-based / Boolean-based / Time-based / Union-based / Stacked / OOB / DVWA-specific
- `scanner/payloads/xss.json` — Basic / IMG variants / SVG vectors / Event handlers / Bypass / Polyglot / DOM-based
- `scanner/payloads/db_errors.json` — MySQL / MariaDB / PostgreSQL / SQLite / Oracle / SQL Server / DB2 错误特征

## 依赖

| 类型 | 包 | 用途 |
|------|----|------|
| 核心 | `requests` `beautifulsoup4` `lxml` `jinja2` | HTTP / HTML 解析 / 报告模板 |
| 可选 | `anthropic` | Claude AI 分析 |
| 测试台 | `flask` `werkzeug` | 漏洞测试台 |

## License

MIT
