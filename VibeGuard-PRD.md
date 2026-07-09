# VibeGuard 🛡️ — 产品开发需求文档 v1.0

> AI 生成代码安全检测插件
> 文档类型：Product Requirements Document | 日期：2026-07-09 | 状态：Draft

---

## 一、产品概述

### 1.1 产品定位

VibeGuard 是一个开源（MIT）的 IDE 插件，在 AI 生成代码的**当时**就检测漏洞——而不是等到 CI/CD 或生产环境出事。

**核心差异**：传统 SAST 检测"代码写错了什么"，VibeGuard 检测"AI 没写什么"+"AI 幻觉出了什么"。

### 1.2 品牌信息

| 项 | 内容 |
|------|------|
| 名称 | VibeGuard 🛡️ |
| 口号（英） | Guard your vibe. Catch what AI missed. |
| 口号（中） | 守住 Vibe，补上 AI 漏的。 |
| 仓库 | github.com/vibeguard/vibeguard |
| 域名 | vibeguard.dev / vibeguard.io |

### 1.3 解决的问题

| 数据 | 来源 |
|------|------|
| 92% 的 AI 生成代码库含高危漏洞 | Sherlock Forensics 2026 |
| 平均每个 vibe-coded 应用 8.3 个可利用漏洞 | Sherlock Forensics 2026 |
| 78% 明文存储密钥 | Sherlock Forensics 2026 |
| 34% Node.js 项目含幻觉依赖包 | Sherlock Forensics 2026 |
| 18 天从部署到首次攻击尝试 | Sherlock Forensics 2026 |

### 1.4 与竞品的本质区别

| 维度 | SonarQube/Snyk/Semgrep | VibeGuard |
|------|:--:|:--:|
| 检测哲学 | 检测"代码写错了什么" | 检测"AI 没写什么" + "AI 幻觉了什么" |
| 检测时机 | CI/CD / 提交时 | **AI 生成代码当时**（IDE 内实时） |
| 幻觉依赖包检测 | ❌ | ✅ |
| 安全维度缺失检测 | ❌ | ✅ |
| AI 常见错误模式库 | ❌ | ✅ |
| 通用 SAST | ✅ 深度 | ⚠ 快速检测（互补） |

---

## 二、目标用户

### 2.1 用户画像

| 画像 | 占比 | 痛点 | 付费意愿 |
|------|:--:|------|:--:|
| **个人开发者（VibeCoder）** | 70% | 用 Copilot/Cursor 写代码，不知道有没有漏洞 | 低（免费为主，部分转 $9/月） |
| **团队技术负责人** | 20% | 团队都开始用 AI 写代码，但没人做安全审查 | 中（$29/人/月） |
| **企业安全团队** | 10% | 需要在 CI/CD 中自动检测 AI 代码安全问题 | 高（企业版定制报价） |

### 2.2 核心使用场景

```
场景一：个人开发者用 Copilot 写代码
  → AI 吐出 import "react-virtualized-auto-sizer"
  → VibeGuard 立即弹窗："这个包不存在，Slopsquatting 风险"
  → 开发者一键替换为真实包

场景二：团队用 Cursor 重构老代码
  → 保存文件
  → VibeGuard 侧边栏列出 3 个 AI 引入的安全问题
  → 开发者点击修复建议，一键应用

场景三：PR 提交到 GitHub
  → VibeGuard GitHub Action 自动扫描 AI 提交的代码
  → PR 里标注 2 个幻觉包 + 1 个 SQL 注入
  → 必须修复才能 merge
```

---

## 三、核心功能规格

### 3.1 三层检测架构

```
┌──────────────────────────────────────────┐
│           VibeGuard 检测架构              │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  L1 实时检测（同步，<50ms）         │  │
│  │  ├ 幻觉依赖包检测                   │  │
│  │  ├ 密钥硬编码检测                   │  │
│  │  ├ 过于宽松配置检测                 │  │
│  │  └ AI 常见错误模式库                 │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  L2 通用 SAST（异步，防抖 500ms）   │  │
│  │  ├ SQL 注入                         │  │
│  │  ├ XSS                              │  │
│  │  ├ SSRF                             │  │
│  │  ├ 路径遍历                         │  │
│  │  ├ 不安全反序列化                   │  │
│  │  └ 命令注入                         │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  L3 LLM 语义分析（异步，防抖 2s）   │  │
│  │  ├ 安全维度缺失检测                 │  │
│  │  ├ 函数意图理解                     │  │
│  │  ├ 数据流追踪                       │  │
│  │  └ 修复建议生成                     │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

### 3.2 L1 实时检测（P0 — MVP 核心）

#### 3.2.1 幻觉依赖包检测

**功能描述**：实时校验 `import` / `require` / `pip install` 中的包名是否在 npm/PyPI/Cargo 真实存在。

**检测流程**：

```
AI 生成代码 → LSP 检测到 import 语句
  │
  ├─ 本地缓存查询（SQLite，<1ms）
  │    ├─ 命中（包存在/不存在）→ 直接返回结果
  │    └─ 未命中 → 异步查询远程 API
  │
  ├─ 远程查询（npm registry API / PyPI JSON API）
  │    ├─ 包存在 → 更新缓存，清除告警
  │    ├─ 包不存在 → 标红 + 弹窗告警
  │    └─ 查询失败 → 标黄「无法验证」
  │
  └─ 模糊匹配（编辑距离 ≤ 2）
       └─ 找到相似包名 → 建议「你是不是想用 xxx？」
```

**支持的语言/包管理器**：

| 语言 | 包管理器 | 检测语法 |
|------|----------|----------|
| JavaScript/TypeScript | npm | `import`, `require`, `package.json` |
| Python | pip | `import`, `from x import`, `requirements.txt`, `pyproject.toml` |
| Rust | Cargo | `use`, `Cargo.toml` |
| Go | go mod | `import`, `go.mod` |
| Java | Maven/Gradle | `import`, `pom.xml`, `build.gradle` |

**本地缓存策略**：

| 数据源 | 更新频率 | 大小 | 方法 |
|--------|----------|------|------|
| npm 包名全量 | 每日 | ~500MB 压缩 | `replicate.npmjs.com/_all_docs` |
| PyPI 包名全量 | 每日 | ~50MB | Simple API 遍历 |
| Cargo crates | 每周 | ~10MB | `crates.io/api/v1/crates` 分页 |
| Go modules | 每周 | ~20MB | `proxy.golang.org` |
| Maven artifacts | 每周 | ~100MB | Maven Central search API |

**性能指标**：
- 缓存命中率目标：>99%
- 本地查询延迟：<1ms
- 远程查询并发：max 5 in-flight
- 远程查询超时：3s → 标记「无法验证」

#### 3.2.2 密钥硬编码检测

**检测方法**：熵值分析 + 上下文语义

```python
# 检测逻辑伪代码
def detect_secrets(code: str) -> List[Finding]:
    findings = []
    
    # 1. 正则模式匹配（高置信度）
    for pattern in SECRET_PATTERNS:  # API key / JWT / AWS key / private key
        for match in pattern.finditer(code):
            findings.append(Finding(
                type="secret_pattern",
                severity="critical",
                line=match.line,
                evidence=redact(match.text)
            ))
    
    # 2. 熵值分析（高熵字符串）
    for string in extract_strings(code):
        entropy = shannon_entropy(string)
        if entropy > 4.5 and len(string) > 20:
            if is_likely_secret(string):  # 排除 base64 编码的正常数据
                findings.append(Finding(
                    type="high_entropy_string",
                    severity="high",
                    line=string.line
                ))
    
    # 3. 上下文语义（变量名暗示密钥）
    for assignment in find_assignments(code):
        if re.match(r"(?i)(api_key|secret|password|token|private_key)", assignment.var_name):
            if not is_env_var_reference(assignment.value):  # 排除 os.getenv()
                findings.append(Finding(
                    type="secret_in_assignment",
                    severity="critical",
                    line=assignment.line
                ))
    
    return findings
```

**支持的密钥类型**：
- AWS Access Key / Secret Key
- GitHub Token / PAT
- JWT Token
- OpenAI / Anthropic / DeepSeek API Key
- 私钥（RSA / ECDSA / Ed25519）
- 通用高熵字符串
- 数据库连接串（含密码）

#### 3.2.3 过于宽松配置检测

**检测项**：

| 配置项 | 危险值 | 语言/框架 |
|--------|--------|-----------|
| `DEBUG = True` | 生产环境 | Django / Flask / FastAPI |
| `app.debug = True` | 生产环境 | Express / Flask |
| `ALLOWED_HOSTS = ['*']` | 任意主机 | Django |
| `CORS_ALLOW_ALL = True` | 任意来源 | Django CORS |
| `Access-Control-Allow-Origin: *` | 任意来源 | 通用 HTTP |
| `DANGEROUSLY_DISABLE_HOST_CHECK` | 关闭主机检查 | React |
| `csrf_exempt` | 关闭 CSRF | Django |
| `permitAll()` | 允许所有 | Spring Security |
| `security.disable=true` | 关闭安全 | Spring |
| `@CrossOrigin(origins = "*")` | 任意来源 | Spring |
| `eval()` | 执行任意代码 | JavaScript |
| `pickle.loads()` | 反序列化 | Python |
| `yaml.load()` 不加 Loader | 不安全加载 | Python |
| `exec()` | 执行任意代码 | Python |

#### 3.2.4 AI 常见错误模式库

**持续收集的 AI 工具高频安全错误**：

| AI 工具 | 高频错误模式 | 检测规则 |
|---------|-------------|----------|
| GitHub Copilot | 拼接 SQL 字符串 | 检测 `f"SELECT ... {var}"` 模式 |
| Claude | 过度信任 `dangerouslySetInnerHTML` | 检测未经过滤的 HTML 注入 |
| ChatGPT | 不安全反序列化 | 检测 `pickle.loads(user_input)` |
| Cursor | API key 暴露在前端 | 检测前端代码中的 key |
| 通用 | 默认密码 `admin/admin` | 检测硬编码默认凭证 |
| 通用 | JWT secret 硬编码 | 检测 `JWT_SECRET = "xxx"` |

### 3.3 L2 通用 SAST（P1 — Pro 版）

| 检测项 | 检测方法 | 严重性 |
|--------|----------|:--:|
| SQL 注入 | 字符串拼接 SQL + 用户输入追踪 | 高 |
| XSS | `innerHTML` / `dangerouslySetInnerHTML` / 未转义输出 | 高 |
| SSRF | URL 参数直接传入 HTTP 请求 | 中 |
| 路径遍历 | 用户输入拼接到文件路径 | 高 |
| 不安全反序列化 | `pickle.loads()` / `yaml.load()` 不安全加载器 | 高 |
| 命令注入 | `os.system()` / `subprocess` 拼接用户输入 | 高 |
| 开放重定向 | 用户输入直接作为重定向 URL | 中 |
| 信息泄露 | 错误信息含堆栈/SQL/敏感数据 | 低 |

**与现有 SAST 去重策略**：

```
检测到 SQL 注入
  │
  ├─ 检查当前文件是否已有 SonarQube/Snyk 的 annotation
  │    ├─ 有 → 静默记录，不弹窗（避免重复告警）
  │    └─ 无 → 正常告警
  └─ 在设置中可配置「与现有工具去重」开关
```

### 3.4 L3 LLM 语义分析（P2 — Pro 版）

#### 3.4.1 安全维度缺失检测

**触发条件**：代码保存时（防抖 2s）

**Prompt 设计**：

```
Analyze this function and check if it's missing critical security measures.

Function code:
{code}

Function context:
- File: {filename}
- Framework: {detected_framework}
- Function name: {function_name}

Check for missing:
1. Input validation (if accepts user input)
2. Rate limiting (if is an API endpoint)
3. Parameterized queries (if touches database)
4. Error handling (if performs IO)
5. Authentication (if accesses sensitive data)
6. Output encoding (if returns HTML)

Return JSON:
{
  "missing": ["rate_limiting", "input_validation"],
  "severity": "high|medium|low",
  "suggestion": "Add @rate_limit decorator..."
}
```

#### 3.4.2 修复建议生成

**功能**：不只告诉你有问题，一键生成安全版本的代码。

```
检测到：SQL 注入（字符串拼接）
原代码：
  query = f"SELECT * FROM users WHERE id = {user_id}"
  cursor.execute(query)

修复建议（一键应用）：
  query = "SELECT * FROM users WHERE id = ?"
  cursor.execute(query, (user_id,))
```

**模型选择**：
- 默认：DeepSeek V4-Flash（快速、便宜）
- 高精度模式：Claude Haiku
- 本地模式：Ollama + 小模型（完全离线）

### 3.5 与现有 SAST 工具的集成

| 检测类型 | VibeGuard | SonarQube/Snyk/Semgrep |
|----------|:--:|:--:|
| 幻觉依赖包 | ✅ 独家 | ❌ |
| 安全维度缺失 | ✅ 独家 | ❌ |
| AI 常见错误模式 | ✅ 独家 | ❌ |
| 过于宽松配置 | ✅ 优先级高 | ⚠ 有规则但优先级低 |
| SQL 注入 / XSS | ⚠ 快速检测 | ✅ 深度分析 |
| CVE 依赖漏洞 | ❌ 不做 | ✅ |
| 许可证合规 | ❌ 不做 | ✅ |

**Semgrep 规则互操作**：VibeGuard 的 AI 专属规则可导出为 Semgrep 规则格式，用户可在 CI/CD 中用 Semgrep 跑 VibeGuard 的规则。

---

## 四、产品形态与分发

### 4.1 三层产品形态

**第一层：IDE 插件（核心入口，免费）**

```
VSCode Marketplace → 搜索 "VibeGuard" → 安装 → 自动生效
JetBrains Marketplace → 同上
```

免费版包含：L1 实时检测（幻觉包 + 密钥 + 配置 + AI 错误模式）。装上就能用，不需要注册账号、不需要配置服务端。

**第二层：GitHub Action（CI/CD 集成，免费）**

```yaml
# .github/workflows/vibeguard.yml
name: VibeGuard Security Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 需要完整 git 历史
      - uses: vibeguard/action@v1
        with:
          mode: ai-code-scan  # 只扫描 AI 提交的代码
```

PR 里自动标注 AI 代码的安全问题。免费。

**AI 代码识别方案：**

GitHub Action 如何判断哪些代码是 AI 生成的？三层检测：

```python
# 1. Git Author / Committer 检测（高置信度）
ai_authors = {
    "github-actions[bot]",        # Copilot
    "cursor-bot",                  # Cursor
    "claude[bot]",                 # Claude Code
    "noreply@anthropic.com",
}

# 2. Commit Message 模式匹配（中置信度）
ai_patterns = [
    r"(?i)co-authored-by.*copilot",
    r"(?i)generated.*by.*ai",
    r"(?i)cursor.*generated",
    r"(?i)claude.*code",
    r"(?i)\bgpt\b.*generated",
]

# 3. Diff 特征分析（辅助）
# - 大段新增代码（>50行）且作者不是人类
# - 新增文件且作者匹配 AI bot
# - Copilot 建议接受标记（GitHub API 可查）
```

| 检测方式 | 置信度 | 方法 |
|----------|:--:|------|
| Git Author | 高 | commit author email 匹配已知 AI bot |
| Co-Authored-By | 高 | commit message 中的 trailer |
| Commit Message 模式 | 中 | 正则匹配 AI 相关关键词 |
| Diff 特征 | 低 | 大段新增 + 作者可疑 → 标记为「可能 AI」 |

**配置选项：**

```yaml
- uses: vibeguard/action@v1
  with:
    mode: ai-code-scan          # 只扫 AI 代码
    # mode: full-scan           # 扫全部代码
    # ai_detection: author      # 只用 git author 检测
    # ai_detection: aggressive   # 激进模式（author + message + diff）
    fail_on: critical           # critical 级别问题阻断 merge
    # fail_on: high             # high+ 阻断
    # fail_on: none              # 只报告不阻断
```

**第三层：团队管理面板（Pro / 团队版，付费）**

Web Dashboard，面向团队管理者：
- 全团队 AI 代码安全趋势
- 哪些开发者的高危率偏高
- CI/CD 集成配置统一管理
- 自定义规则（公司内部的安全规范）

### 4.2 跨编辑器策略

底层用 **Language Server Protocol（LSP）**，一套核心检测逻辑同时支持 VSCode 和 JetBrains。未来可扩展到 Vim / Neovim / Sublime 等支持 LSP 的编辑器。

```
┌────────────┐  ┌────────────┐  ┌────────────┐
│  VSCode    │  │  JetBrains │  │  Neovim    │
│  Extension │  │  Plugin    │  │  LSP Client│
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │
      └───────────────┼───────────────┘
                      │ LSP Protocol
              ┌───────┴───────┐
              │ VibeGuard LSP │
              │  Server       │
              │ (Rust/Node)   │
              └───────────────┘
```

---

## 五、交互设计

### 5.1 核心原则

> 不打搅用户，但在关键时刻拦住。

### 5.2 实时模式（L1 检测）

```
┌─────────────────────────────────────────┐
│ 🔴 Hallucinated Package                  │
│                                         │
│ "react-virtualized-auto-sizer"          │
│ 这个包在 npm 上不存在。                  │
│                                         │
│ ⚠ 这是 Slopsquatting 风险：              │
│ 攻击者可能已注册此名称并植入恶意代码。    │
│                                         │
│ 你是不是想用：                           │
│ • react-virtualized                      │
│ • react-window                           │
│                                         │
│ [替换为 react-virtualized] [忽略] [了解更多]│
└─────────────────────────────────────────┘
```

### 5.3 批量扫描模式（L2/L3 检测）

保存文件时触发，结果写入侧边栏问题列表：

```
VibeGuard 问题列表
├── 🔴 Critical (2)
│   ├── 幻觉依赖包：torch-vision-utils (line 12)
│   └── SQL 注入：用户输入直接拼接 (line 45)
├── 🟡 Warning (3)
│   ├── 密钥硬编码：API_KEY (line 8)
│   ├── 过于宽松配置：DEBUG=True (line 2)
│   └── 安全维度缺失：注册接口缺少速率限制 (line 23)
└── 🔵 Info (1)
    └── 建议添加错误处理 (line 67)

点击任意问题 → 跳转代码位置 + 显示修复建议
```

### 5.4 异步检测架构

```
代码变更事件流：

  用户打字/AI 生成代码
       │
       ├─ [同步] L1 实时检测 (<50ms)
       │    ├─ 幻觉包检测 → 立即标红
       │    ├─ 密钥硬编码 → 立即标红
       │    ├─ 过于宽松配置 → 立即标黄
       │    └─ AI 常见错误模式 → 立即标黄
       │
       ├─ [异步] L2 SAST 检测 (防抖 500ms 后触发)
       │    └─ 结果写入侧边栏问题列表
       │
       └─ [异步] L3 LLM 分析 (防抖 2s 后触发)
            ├─ 安全维度缺失检测
            ├─ 函数意图分析
            └─ 修复建议生成
            → 结果延迟显示（先标黄 → L3 确认后升级为红）
```

**防抖策略**：

| 层级 | 防抖时间 | 触发条件 |
|------|----------|----------|
| L1 | 0ms（即时） | 每行变更 |
| L2 | 500ms | 用户停止打字 500ms |
| L3 | 2000ms | 用户停止打字 2s 或代码保存时 |

### 5.5 性能预算

| 指标 | 目标 |
|------|------|
| L1 检测延迟 | <50ms/行 |
| L1 不影响打字帧率 | 60fps 不掉帧 |
| L2 异步检测延迟 | <2s |
| L3 LLM 分析延迟 | <5s |
| 内存占用 | <100MB |
| 启动时间 | <2s |

### 5.6 首次安装冷启动体验

**问题：** 用户安装插件后首次打开项目，包名缓存（~600MB）还没下载，幻觉包检测无法工作。

**解决方案：分级加载策略**

```
插件安装后首次启动
  │
  ├─ [0s] 插件激活，显示欢迎引导
  │    └─ 「正在准备安全检测能力，预计 2-3 分钟…」
  │
  ├─ [0s] L1 其他检测立即生效（密钥/配置/AI 错误模式）
  │    └─ 不依赖包名缓存，立刻工作
  │
  ├─ [0s] 包名缓存下载（后台静默）
  │    ├─ 优先下载当前项目语言的包名（如检测到 package.json → 先下 npm）
  │    ├─ 其他语言后台排队下载
  │    └─ 下载完成后自动激活幻觉包检测
  │
  ├─ [可选] 轻量模式：只下载 Top 10万包名（~20MB，30秒）
  │    └─ 覆盖 95% 常见包名，不够的再远程查
  │
  └─ 下载进度在状态栏显示：「VibeGuard: 包名库同步中 45%」
```

**进度策略：**

| 阶段 | 包名覆盖 | 下载量 | 时间 | 检测能力 |
|------|----------|--------|------|----------|
| Tier 1（即时） | Top 10万热门包 | ~20MB | ~30s | 覆盖 95% 常见包名 |
| Tier 2（后台） | 全量包名 | ~600MB | 2-3min | 覆盖 100% |

**离线场景：**

- 首次下载失败 → 提示用户「包名库未就绪，幻觉包检测暂不可用，其他检测正常」
- 后续启动时检测本地缓存是否过期，后台增量更新

### 5.7 误报处理与忽略机制

**单个 Finding 忽略：**

```
用户点击 [忽略] 按钮
  │
  ├─ 当前 finding 标记为 dismissed = true
  ├─ 记录忽略规则：file + line + rule_id
  └─ 同文件同规则不再弹窗（但侧边栏仍显示，标记为已忽略）
```

**全局忽略规则：**

```yaml
# ~/.vibeguard/ignore-rules.yml
ignore:
  # 按规则 ID 忽略
  - rule: "insecure_config_debug_true"
    scope: "file:*/test_*"  # 只在测试文件中忽略
    
  # 按文件路径忽略
  - path: "**/migrations/**"  # 忽略数据库迁移文件
    rules: ["sql_injection"]
    
  # 按包名忽略（误报的幻觉包）
  - package: "my-private-package"
    registry: "npm"
    reason: "内部私有包，不在公开 registry 中"
```

**「不再提示此规则」交互：**

```
弹窗中的 [忽略] 按钮下拉菜单：
  ├─ 忽略此问题（仅当前文件当前行）
  ├─ 忽略此规则（当前文件）
  ├─ 忽略此规则（所有文件）
  └─ 管理忽略规则…（打开 ignore-rules.yml）
```

**误报反馈闭环：**

- 忽略时可选填原因：「误报 / 不是问题 / 内部包」
- 匿名上报误报数据（可关闭）
- 定期分析误报率高的规则，优化规则精度

---

## 六、数据模型

### 6.1 核心数据结构

```typescript
interface Finding {
  id: string;                    // 唯一 ID
  type: FindingType;             // 检测类型
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;               // 问题描述
  file: string;                  // 文件路径
  line: number;                  // 行号
  column: number;                // 列号
  evidence: string;              // 问题代码片段（脱敏后）
  suggestion?: string;           // 修复建议
  fix?: CodeFix;                 // 可应用的修复
  detection_layer: "L1" | "L2" | "L3";
  detection_rule: string;        // 触发的规则 ID
  timestamp: number;
  dismissed: boolean;            // 用户是否忽略
}

type FindingType =
  | "hallucinated_package"       // 幻觉依赖包
  | "hardcoded_secret"           // 硬编码密钥
  | "insecure_config"            // 过于宽松配置
  | "ai_pattern_error"           // AI 常见错误
  | "sql_injection"              // SQL 注入
  | "xss"                        // XSS
  | "ssrf"                       // SSRF
  | "path_traversal"             // 路径遍历
  | "insecure_deserialization"   // 不安全反序列化
  | "command_injection"          // 命令注入
  | "missing_security_measure"   // 安全维度缺失
  | "other";                     // 其他

interface CodeFix {
  description: string;           // 修复描述
  edits: TextEdit[];             // 代码编辑操作
}

interface PackageCache {
  registry: "npm" | "pypi" | "cargo" | "gomod" | "maven";
  package_name: string;
  exists: boolean;
  last_verified: number;         // timestamp
  similar_packages?: string[];   // 模糊匹配建议
}

interface VibeGuardConfig {
  enabled: boolean;
  detection_layers: {
    l1: boolean;
    l2: boolean;
    l3: boolean;
  };
  llm_provider?: "deepseek" | "claude" | "openai" | "local";
  llm_api_key?: string;          // 加密存储，见 6.3
  dedup_with_existing_tools: boolean;
  custom_rules: string[];        // 自定义规则路径
  ignored_findings: string[];    // 忽略的 finding ID
  package_cache: {
    languages: ("npm" | "pypi" | "cargo" | "gomod" | "maven")[];
    update_interval: "daily" | "weekly";
    lightweight_mode: boolean;   // 只下载 Top 10万包名
  };
  telemetry: boolean;            // 匿名误报数据上报
}
```

### 6.2 本地存储

| 数据 | 存储 | 大小 |
|------|------|------|
| 配置 | JSON 文件 (~/.vibeguard/config.json) | <10KB |
| LLM API Key | 系统 Keychain（macOS Keychain / Windows Credential Manager / Linux Secret Service） | <1KB |
| 检测结果 | SQLite (~/.vibeguard/findings.db) | <100MB |
| 包名缓存 | SQLite (~/.vibeguard/packages.db) | ~600MB |
| 自定义规则 | YAML 文件 | 按需 |
| 忽略规则 | YAML (~/.vibeguard/ignore-rules.yml) | <10KB |

### 6.3 LLM API Key 安全存储

**问题：** 用户在 VibeGuard 配置中填入 DeepSeek / Claude / OpenAI API Key，不能明文存在 JSON 配置文件中。

**方案：使用操作系统原生 Keychain**

```typescript
// 使用 keytar (Node.js) 或操作系统原生 API
import keytar from "keytar";

// 存储
await keytar.setPassword("VibeGuard", "llm_api_key", userApiKey);

// 读取
const key = await keytar.getPassword("VibeGuard", "llm_api_key");

// 删除
await keytar.deletePassword("VibeGuard", "llm_api_key");
```

| 平台 | 存储位置 |
|------|----------|
| macOS | Keychain Access → VibeGuard |
| Windows | Credential Manager → VibeGuard |
| Linux | Secret Service (libsecret) / GNOME Keyring |

**配置文件中只存标记，不存 key：**

```json
// ~/.vibeguard/config.json
{
  "llm_provider": "deepseek",
  "llm_api_key_stored": true,  // 标记 key 已存入 Keychain
  "llm_api_key": null           // 永远为 null
}
```

**Fallback（Keychain 不可用时）：**

- 提示用户风险
- 使用 AES-256 加密存储到配置文件
- 加密密钥基于机器 ID + 用户安装时设置的 PIN

### 6.4 配置文件完整示例

```json
// ~/.vibeguard/config.json
{
  "enabled": true,
  "detection_layers": {
    "l1": true,
    "l2": true,
    "l3": false
  },
  "llm_provider": "deepseek",
  "llm_api_key_stored": true,
  "llm_api_key": null,
  "dedup_with_existing_tools": true,
  "package_cache": {
    "languages": ["npm", "pypi"],
    "update_interval": "daily",
    "lightweight_mode": true
  },
  "telemetry": true,
  "custom_rules": [],
  "ignored_findings": []
}
```

```yaml
# ~/.vibeguard/ignore-rules.yml
ignore:
  - rule: "insecure_config_debug_true"
    scope: "file:*/test_*"
    reason: "测试文件允许 DEBUG=True"

  - path: "**/migrations/**"
    rules: ["sql_injection"]
    reason: "数据库迁移文件由工具生成"

  - package: "@company/private-utils"
    registry: "npm"
    reason: "内部私有包"
```

### 6.5 开源版 L3 使用说明

**设计决策：** L3 LLM 分析能力不锁在 Pro 版后面——开源用户自带 API Key 即可使用。

| 用户类型 | L1 | L2 | L3 | 说明 |
|----------|:--:|:--:|:--:|------|
| 开源版（无 API Key） | ✅ | ✅ | ❌ | L1+L2 完全免费，L3 需要 LLM |
| 开源版（自带 API Key） | ✅ | ✅ | ✅ | 用户自配 DeepSeek/Claude/Ollama key，L3 免费使用 |
| Pro 版 | ✅ | ✅ | ✅ | 包含 L3 + 修复建议 + 官方 LLM 额度 |

**Pro 版的 L3 差异化：**

- Pro 版内置 LLM 额度（用户不需要自己申请 API Key）
- Pro 版的修复建议质量更高（用更好的模型）
- Pro 版支持批量修复（一键修复整个文件的所有问题）
- 开源版用户自带 key 也能用 L3，但模型选择和额度自己负责

---

## 七、技术栈

| 层 | 选型 | 理由 |
|------|------|------|
| **LSP Server** | Rust (tower-lsp) | 零 GC 延迟，<1ms 响应，内存安全 |
| **L1 检测引擎** | Rust regex + Aho-Corasick | 多模式匹配，亚毫秒级 |
| **L2 SAST 引擎** | Rust + tree-sitter | AST 解析，数据流追踪 |
| **L3 LLM 调用** | TypeScript (Node.js sidecar) | LLM SDK 生态成熟 |
| **VSCode Extension** | TypeScript | 官方推荐 |
| **JetBrains Plugin** | Kotlin | 官方推荐 |
| **GitHub Action** | TypeScript (Docker) | 跨平台 CI |
| **包名缓存** | SQLite (rusqlite) | 嵌入式，零配置 |
| **Dashboard（团队版）** | React + FastAPI | 快速开发 |
| **CI/CD** | GitHub Actions | 开源项目标配 |

---

## 八、开发路线图

### Phase 1：MVP — L1 实时检测（M1-M2）

**目标**：可用的 VSCode 插件，有核心差异化能力

```
M1（第1-4周）：L1 检测核心
  □ LSP Server 基础架构（Rust + tower-lsp）
  □ 幻觉依赖包检测（npm + PyPI）
  □ 本地包名缓存系统（SQLite + 每日同步）
  □ 密钥硬编码检测（正则 + 熵值）
  □ 过于宽松配置检测
  □ VSCode Extension 包装

M2（第5-8周）：发布
  □ AI 常见错误模式库（30+ 规则）
  □ Cargo / Go modules / Maven 包检测
  □ 模糊匹配建议
  □ 完整的交互 UI（弹窗 + 侧边栏）
  □ VSCode Marketplace 发布
  □ GitHub 开源 + README + Demo 视频
  □ 目标：1000 Marketplace 安装量
```

### Phase 2：L2 SAST + GitHub Action（M3-M4）

```
M3（第9-12周）：L2 SAST
  □ tree-sitter AST 解析
  □ SQL 注入 / XSS / SSRF / 命令注入检测
  □ 与现有 SAST 去重策略
  □ Semgrep 规则导出

M4（第13-16周）：GitHub Action
  □ GitHub Action Docker 镜像
  □ PR 中 AI 代码识别（git blame + commit author）
  □ PR 评论自动标注问题
  □ JetBrains Plugin（基于同一 LSP）
  □ 目标：5000 Marketplace 安装量
```

### Phase 3：L3 LLM + 商业化（M5-M8）

```
M5-M6（第17-24周）：L3 LLM 分析
  □ DeepSeek V4-Flash 集成
  □ 安全维度缺失检测
  □ 修复建议生成
  □ 本地 Ollama 模式
  □ Pro 版订阅系统

M7-M8（第25-32周）：团队版
  □ Web Dashboard
  □ 团队安全趋势分析
  □ 自定义规则引擎
  □ SSO + RBAC
  □ 企业版私有化部署
  □ 目标：50 付费用户，MRR $5K+
```

---

## 九、MVP 功能优先级矩阵

| 功能 | 优先级 | 阶段 | 理由 |
|------|:--:|------|------|
| LSP Server 基础架构 | P0 | M1 | 无此无产品 |
| 幻觉依赖包检测（npm + PyPI） | P0 | M1 | 核心差异化，竞品无 |
| 本地包名缓存系统 | P0 | M1 | 性能必须 |
| 密钥硬编码检测 | P0 | M1 | 高频问题（78%） |
| 过于宽松配置检测 | P0 | M1 | 高频问题（67%） |
| VSCode Extension 包装 | P0 | M1 | 主分发渠道 |
| AI 常见错误模式库 | P1 | M2 | 持续积累 |
| Cargo / Go / Maven 包检测 | P1 | M2 | 扩展语言覆盖 |
| 模糊匹配建议 | P1 | M2 | 体验提升 |
| L2 通用 SAST | P1 | M3 | 互补能力 |
| GitHub Action | P1 | M4 | CI/CD 场景 |
| JetBrains Plugin | P1 | M4 | 扩大覆盖 |
| L3 LLM 分析 | P2 | M5 | Pro 卖点 |
| 修复建议生成 | P2 | M5 | Pro 卖点 |
| 团队 Dashboard | P2 | M7 | 团队版卖点 |
| 企业版私有化 | P3 | M8 | 企业客户 |

---

## 十、商业模式

### 10.1 定价

| 版本 | 功能 | 定价 |
|------|------|------|
| **免费版** | L1 实时检测（幻觉包 + 密钥 + 配置 + AI 错误模式）、VSCode/JetBrains | 免费 |
| **Pro 版** | L2 通用 SAST + L3 LLM 分析 + 修复建议 | $9/月 |
| **团队版** | Pro + 团队管理面板 + 安全趋势 + CI/CD 集成 | $29/人/月 |
| **企业版** | 全部 + 私有化部署 + SSO + 合规报告 + 自定义规则 | 按需报价 |

### 10.2 定价策略

- 免费版包含幻觉包检测（核心差异化，形成口碑传播，类似 Snyk freemium）
- Pro 版 $9/月面向个人开发者，卖 L3 LLM 分析和修复建议
- 团队版 $29/人/月面向团队，卖管理面板和 CI/CD 集成（团队管理者付费，开发者免费用）
- 路径：个人免费 → 团队付费 → 企业私有化

### 10.3 增长指标

| 阶段 | 时间 | 指标 |
|------|------|------|
| MVP | M2 | 1000 Marketplace 安装 |
| 增长 | M4 | 5000 安装 + 100 GitHub Stars |
| 商业化验证 | M6 | 50 Pro 付费用户 |
| 团队版 | M8 | 10 团队客户，MRR $5K |
| 规模化 | M12 | 50000 安装 + 500 付费 + MRR $30K |

---

## 十一、风险与应对

| 风险 | 影响 | 概率 | 应对 |
|------|:--:|:--:|------|
| VSCode API 限制 | 中 | 中 | 核心能力用 LSP（跨编辑器） |
| 误报率过高导致用户关闭 | 高 | 中 | L1 只做高置信度检测，不确定的不弹窗 |
| SonarQube/Snyk 跟进 AI 专项 | 中 | 高 | 它们是大而全的工具，我们是专注 AI 代码的精瘦工具 |
| 幻觉包检测的 npm 查询延迟 | 低 | 低 | 本地缓存，命中率 >99% |
| GitHub Copilot 自己加安全检测 | 中 | 中 | 它们做通用安全，我们做 AI 专属——互补不竞争 |
| L3 LLM 延迟影响体验 | 中 | 中 | 异步执行 + 防抖 + 用户可关闭 L3 |
| 包名缓存磁盘占用过大 | 低 | 中 | 增量同步 + 压缩 + 可配置只缓存常用语言 |

---

## 十二、与 AgentShield / SafeArena 的协同

### 12.1 产品矩阵

```
SafeArena    →  定义安全标准（Benchmark，行业话语权）
VibeGuard    →  开发时安全（IDE 插件，面向开发者）
AgentShield  →  运行时安全（Sidecar 平台，面向企业）
```

### 12.2 技术复用

| 共享组件 | VibeGuard 用法 | AgentShield 用法 | SafeArena 用法 |
|----------|:--:|:--:|:--:|
| L1 静态规则引擎 | 代码检测 | 流量检测 | 评测规则 |
| LLM 语义分析后端 | 代码分析 | 注入检测 | 评测场景 |
| 幻觉包数据集 | 包检测 | - | 评测题目 |
| 攻击场景库 | - | Agent 攻击检测 | 评测题目 |

### 12.3 交叉销售

```
VibeGuard 用户："我发现了 AI 代码漏洞"
  → "想知道你的 Agent 运行时安全吗？试试 AgentShield"

AgentShield 用户："我的 Agent 被攻击了"
  → "Agent 写的代码安全吗？试试 VibeGuard"

SafeArena 用户："我选的模型安全得分 72"
  → "这个模型的代码还需要 VibeGuard 检测"
```

---

## 十三、附录

### A. 术语表

| 术语 | 定义 |
|------|------|
| Slopsquatting | 攻击者注册 AI 幻觉出的包名，植入恶意代码 |
| LSP | Language Server Protocol，跨编辑器的语言服务协议 |
| SAST | Static Application Security Testing，静态应用安全测试 |
| 幻觉依赖包 | AI 生成的代码中引用了实际不存在的包名 |
| 安全维度缺失 | AI 代码系统性跳过整个安全层级（如速率限制、输入校验） |

### B. 参考项目

| 项目 | 参考价值 |
|------|----------|
| GitHub Copilot | AI 代码生成的接受率心理研究 |
| Semgrep | 规则引擎架构、社区规则贡献模式 |
| Snyk | Freemium 模式、Marketplace 分发策略 |
| Snyk Code | 实时 SAST 在 IDE 中的 UX 设计 |
| tree-sitter | 多语言 AST 解析 |
| ModSecurity | 规则社区贡献模式参考 |