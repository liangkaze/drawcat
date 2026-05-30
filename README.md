# Drawcat — 自动化 Web 漏洞扫描器

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

开箱即用的 Web 安全扫描器，支持 **SQL 注入** 和 **XSS 跨站脚本** 的自动化检测，可选 AI 增强分析报告。

## 快速开始

```bash
# 1. 安装
pip install -e ".[full]"

# 2. 扫描
drawcat scan http://target.com

# 3. (可选) 配置 AI 分析
drawcat config
drawcat scan http://target.com --ai
```

## 功能

- **爬虫引擎**: 自动发现页面和表单，支持登录认证（含 CSRF token）
- **SQL 注入检测**: Error-based / Boolean-based / Time-based / Union-based 四种技术
- **XSS 检测**: Reflected / Stored / DOM-based 三种类型
- **AI 分析**: 可选 Anthropic Claude / DeepSeek / OpenAI，自动生成风险评估和修复建议
- **报告输出**: HTML + JSON 双格式，中文界面
- **漏洞测试台**: 内置有漏洞和安全版本对比环境
- **Payload 可定制**: JSON 文件独立维护，无需改代码

## 用法

```bash
# 基础扫描
drawcat scan http://example.com

# 深度扫描 + AI 报告
drawcat scan http://example.com -dp 5 -pg 1000 --ai

# 带登录扫描
drawcat scan http://example.com -u admin -p password -L /login.php

# Session Cookie 扫描
drawcat scan http://example.com -c "PHPSESSID=xxx; security=low"

# 配置 AI 提供商
drawcat config

# 启动漏洞测试台
drawcat testbed

# 对比防御效果
drawcat compare
```

### 参数速查

| 短参数 | 长参数 | 说明 | 默认值 |
|--------|--------|------|--------|
| `-dp` | `--depth` | 爬取深度 | 2 |
| `-pg` | `--pages` | 最大页面数 | 50 |
| `-t` | `--timeout` | 请求超时(秒) | 10 |
| `-dy` | `--delay` | 请求间隔(秒) | 0.15 |
| `-u` | `--username` | 登录用户名 | - |
| `-p` | `--password` | 登录密码 | - |
| `-L` | `--login-url` | 登录页面路径 | - |
| `-c` | `--cookie` | Session Cookie | - |
| `-ai` | `--ai` | 启用 AI 分析 | - |
| `-o` | `--output` | 报告输出路径 | - |

## AI 提供商

| 提供商 | 预置模型 | 命令 |
|--------|----------|------|
| Anthropic Claude | Haiku 4.5 / Sonnet 4.6 / Opus 4.7 | `drawcat config` |
| DeepSeek | deepseek-chat / deepseek-reasoner | `drawcat config` |
| OpenAI | gpt-4o-mini / gpt-4o / gpt-4.1 | `drawcat config` |
| 自定义 | 任意 OpenAI 兼容 API | `drawcat config` |

或直接编辑 `config.json`:
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

## 项目结构

```
drawcat/
├── drawcat.py              # 入口
├── pyproject.toml        # 包配置
├── config.example.json   # AI 配置模板
├── scanner/              # 扫描引擎
│   ├── crawler.py        # 爬虫
│   ├── sql_injection.py  # SQLi 检测
│   ├── xss.py            # XSS 检测
│   ├── scanner.py        # 调度器
│   ├── payloads.py       # Payload 加载
│   └── payloads/         # JSON Payload 库
├── reporter/             # 报告生成
│   └── report_generator.py
├── testbed/              # 漏洞测试台
├── defense/              # 防御参考实现
└── tests/                # 测试
```

## 依赖

核心依赖: `requests` `beautifulsoup4` `lxml` `jinja2`

可选: `anthropic` (AI 分析) `flask` (测试台)
