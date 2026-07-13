# VibeGuard 独立面板 + L3 AI 深度扫描按钮 — 升级设计文档

> 版本: v0.2.0 规划稿
> 日期: 2026-07-13
> 状态: 修订版，待评审

---

## 1. 背景与动机

### 1.1 现状分析

VibeGuard 目前在两个 IDE 上的 UI 集成存在明显缺口：

| 维度 | VSCode | JetBrains |
|------|--------|-----------|
| 活动栏图标 | ✅ 有（侧边栏 VibeGuard 图标） | ❌ 无 |
| Findings 面板 | ✅ 有（TreeDataProvider，按严重级别分组） | ❌ 无 |
| 诊断波浪线 | ✅ 有（LSP DiagnosticCollection） | ✅ 有（LSP 诊断） |
| Quick Fix | ✅ 有（CodeActionProvider） | ✅ 有（LSP CodeAction） |
| 手动扫描入口 | ✅ 有命令（`vibeguard.scanCurrentFile` / `vibeguard.scanWorkspace`），但无专门 UI 按钮 | ❌ 无 |
| L3 触发方式 | 保存时自动触发；现有手动命令在 L3 已启用且已配置时也会运行 L3 | 保存时自动触发；无插件 UI 入口 |
| L3 状态可见性 | 仅 Output Channel 日志，用户不知道是否在跑 | 仅 LSP console 日志 |

### 1.2 核心痛点

1. **L3 是"隐形功能"** — 用户不知道 VibeGuard 有 AI 深度分析能力，因为没有可发现、可解释的 UI 入口
2. **L3 手动工作流不明确** — 虽然已有命令，但用户无法在发起前确认范围、远程提供商、代码外发与预计成本
3. **L3 成本与结果来源不透明** — 调用 LLM 花钱花时间，但用户看不到"正在分析"、是否真的走了远程模型、用的哪个模型，以及 usage 是否由提供商返回
4. **JetBrains 完全没有面板** — 纯 LSP 诊断，连 Findings 列表都没有，用户体验远差于 VSCode
5. **扫描结果无分层展示** — L1/L2/L3 的发现混在一起，用户无法区分"快速检测"和"AI 深度分析"的结果

### 1.3 为什么现在做

- L3 分析器代码已成熟（`src/l3/analyzer.ts` 本地语义分析 + `src/l3/llm.ts` 多 LLM 提供商）
- 多 LLM 支持已完成（DeepSeek / Claude / OpenAI / Ollama / VibeGuard Pro）
- API Key 管理已就绪（VSCode SecretStorage + OS Keychain + 环境变量）
- 缺的只是 UI 层的触发入口和结果展示

---

## 2. 目标

### 2.1 核心目标

1. **VSCode 有独立的 VibeGuard 面板**；JetBrains ToolWindow 在通信 spike 通过后交付，均包含扫描按钮和结果列表
2. **用户可一键发起 L3 AI 深度扫描**；v0.2.0 交付当前文件，工作区扫描在预算与取消机制完成后再开放
3. **扫描过程可见** — 状态、模型信息、耗时、远程/本地回退来源；仅在提供商返回 usage 时展示 token 消耗
4. **L3 结果与 L1/L2 分层展示**，用户能区分发现来源
5. **面板内可直接操作** — 跳转代码、应用修复、忽略发现

### 2.2 非目标

- 不改变 L1/L2 的实时检测行为（仍然自动运行）
- 不替换现有 Quick Fix 机制（面板是补充，不是替代）
- 不引入新的 LLM 提供商（复用现有 5 个）
- 不做 Teams Dashboard 的集成（那是独立的 Web 仪表板）
- 不在 v0.2.0 对远程 LLM 做无提示的全工作区扫描

---

## 3. 架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────┐
│                  IDE 面板                        │
│  ┌───────────────────────────────────────────┐  │
│  │  Toolbar: [Scan with AI ▾] [⚙ Settings]   │  │
│  ├───────────────────────────────────────────┤  │
│  │  Scope: Current File                      │  │
│  │  Model: DeepSeek-v4-flash                 │  │
│  ├───────────────────────────────────────────┤  │
│  │  Status: ● Ready / ● Scanning... / ● Done │  │
│  │  Last scan: 2.3s · 1,240 tokens · 3 finds │  │
│  ├───────────────────────────────────────────┤  │
│  │  Findings List                            │  │
│  │  ┌─ 🔴 HIGH ──────────────────────────┐  │  │
│  │  │  L3  l3_missing_authentication      │  │  │
│  │  │  POST /api/login: no auth middleware│  │  │
│  │  │  app.ts:42  [Open] [Fix] [Ignore]   │  │  │
│  │  └────────────────────────────────────┘  │  │
│  │  ┌─ 🟡 MEDIUM ────────────────────────┐  │  │
│  │  │  L3  l3_missing_rate_limiting       │  │  │
│  │  │  POST /api/login: no rate limiter   │  │  │
│  │  │  app.ts:42  [Open] [Ignore]         │  │  │
│  │  └────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### 3.2 数据流

```
用户点击 "Scan with AI"
        │
        ▼
┌─ 平台适配层 ────────────────────────────────────────────┐
│ VSCode：WebviewViewProvider → Extension scan session   │
│ JetBrains：ToolWindow → 已验证的 LSP command adapter    │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─ Manual L3 Review Service ──────────────────────────────┐
│ 1. 预检：L3 开关、密钥、远程代码授权、扫描预算          │
│ 2. 创建可取消的 review session（带 scanId）             │
│ 3. 调用 LlmSemanticAnalyzer 或本地模式                  │
│ 4. 返回 L3ReviewOutcome（findings、来源、usage、状态）  │
└─────────────────────────────────────────────────────────┘
        │
        ▼
平台适配层合并 L3 层 findings、更新诊断与面板；过期 scanId 的结果被丢弃。
```

### 3.3 与现有系统的集成点

| 组件 | 集成方式 |
|------|---------|
| `scanner.ts` | 复用 `scanSourceFile()`，传入 `{ detectionLayers: { l1: false, l2: false, l3: true } }` 只跑 L3 |
| `l3/manualReview.ts`（新增） | 统一预检、远程授权、预算、取消与 `L3ReviewOutcome`；不把面板逻辑复制到两个 IDE |
| `l3/llm.ts` | 复用 `LlmSemanticAnalyzer`，扩展为可返回远程/本地回退来源和可选 usage |
| `extension.ts` | 新增 WebviewViewProvider 注册面板，调用共享 review service；密钥继续由 VSCode SecretStorage 管理 |
| `lspServer.ts` | 仅在 JetBrains 通信 spike 成功后暴露 `vibeguard.scanWithAi`；命令响应是主结果通道 |
| `types.ts` | 新增 `L3ReviewOutcome`，保持现有 `ScanResult` 兼容 |
| `layers.ts` | 复用 `mergeFindingsForExecutedLayers`，仅替换 L3 层 findings |

---

## 4. VSCode 扩展实现方案

### 4.1 面板类型选择：WebviewView

**选择 WebviewView 而非 TreeView 的原因：**

| 维度 | TreeView | WebviewView |
|------|----------|-------------|
| 自定义 UI | 仅树形列表 + 图标 | 完整 HTML/CSS/JS |
| 扫描按钮 | 只能通过 command/title bar | 可内嵌在面板顶部 |
| 进度条 | 仅 `$(sync~spin)` 文字 | 真实进度条 |
| 状态信息 | 受限 | 自由布局 |
| 结果卡片 | 只能一行文字 + 图标 | 富文本卡片 |
| 开发成本 | 低 | 中 |
| 交互体验 | 一般 | 优秀 |

**决定：使用 WebviewView**，因为 L3 面板需要展示模型选择、进度条、token 统计等富信息，TreeView 太受限。

### 4.2 package.json 新增配置

```jsonc
{
  "contributes": {
    "viewsContainers": {
      "activitybar": [
        {
          "id": "vibeguard",
          "title": "VibeGuard",
          "icon": "media/vibeguard.svg"
        }
      ]
    },
    "views": {
      "vibeguard": [
        {
          "id": "vibeguardFindings",
          "name": "Findings",
          "type": "tree"
        },
        {
          "id": "vibeguardL3Panel",
          "name": "AI Deep Scan",
          "type": "webview"
        }
      ]
    },
    "commands": [
      // ...existing commands...
      {
        "command": "vibeguard.scanWithAi",
        "title": "VibeGuard: Scan with AI",
        "icon": "$(sparkle)"
      },
    ],
    "menus": {
      "view/title": [
        {
          "command": "vibeguard.scanWithAi",
          "when": "view == vibeguardL3Panel",
          "group": "navigation"
        }
      ]
    }
  }
}
```

### 4.3 面板布局（Webview HTML）

```
┌─────────────────────────────────────┐
│  VibeGuard AI Deep Scan             │
├─────────────────────────────────────┤
│  ┌─────────────────────────────┐    │
│  │  [Scan with AI]  [Settings] │    │
│  └─────────────────────────────┘    │
│                                     │
│  Scope: Current File                │
│  Model: [DeepSeek-v4-flash    ▾]    │
│                                     │
│  ─────────────────────────────────  │
│                                     │
│  ● Ready                            │
│  Last: 2.3s · 1,240 tok · 3 finds   │
│                                     │
│  ─────────────────────────────────  │
│                                     │
│  Findings (3)                       │
│                                     │
│  ┌─────────────────────────────┐    │
│  │ 🔴 HIGH · L3                │    │
│  │ Missing authentication      │    │
│  │ POST /api/login             │    │
│  │ app.ts:42                   │    │
│  │ [Open] [Apply Fix] [Ignore] │    │
│  └─────────────────────────────┘    │
│                                     │
│  ┌─────────────────────────────┐    │
│  │ 🟡 MEDIUM · L3              │    │
│  │ Missing rate limiting       │    │
│  │ POST /api/login             │    │
│  │ app.ts:42                   │    │
│  │ [Open] [Ignore]             │    │
│  └─────────────────────────────┘    │
│                                     │
│  ┌─────────────────────────────┐    │
│  │ 🔵 LOW · L3                 │    │
│  │ Missing error handling      │    │
│  │ GET /api/users              │    │
│  │ app.ts:78                   │    │
│  │ [Open] [Ignore]             │    │
│  └─────────────────────────────┘    │
│                                     │
└─────────────────────────────────────┘
```

**状态轮转：**

```
Ready ──click Scan──▶ Consent / Preflight ──▶ Scanning ──done──▶ Results
  │                      │                    │
  │                      │                    ├──click Open──▶ 跳转代码行
  │                      │                    ├──click Fix──▶ 应用修复
  │                      │                    └──click Ignore──▶ 添加忽略规则
  │                      │
  │                      ├──no API Key──▶ Not configured: "Set API Key"
  │                      ├──remote consent declined──▶ Ready: "Remote scan not started"
  │                      ├──cancel──▶ Cancelled: retain the previous completed result
  │                      ├──timeout──▶ Error: "Timeout, try again"
  │                      └──LLM error──▶ Local fallback / Error（明确显示实际来源）
```

### 4.4 Webview 安全与状态约束

- 使用严格 CSP（`default-src 'none'`）、nonce 脚本和 `localResourceRoots`；不得加载远程脚本、样式或图片。
- Finding 的 message、evidence、文件名全部按纯文本渲染；不得将 LLM 或源码内容插入 `innerHTML`。
- 所有 Webview → Extension 消息在运行时按白名单 schema 校验。`findingId` 只用于查找当前 review session 中的服务端对象，不能作为可执行数据。
- 扫描状态由 Extension 端持有，Webview 隐藏后可重建；默认不使用 `retainContextWhenHidden`。
- 面板中的 L3 修复必须调用现有源码匹配校验和显式确认流程，不能绕过 LLM replacement review。

### 4.5 新增源文件

```
src/
├── panel/
│   ├── l3PanelProvider.ts    # WebviewViewProvider 实现
│   ├── l3PanelHtml.ts        # HTML 模板生成
│   ├── l3PanelMessages.ts    # Webview ↔ Extension 消息协议
│   └── l3PanelTypes.ts       # 面板状态类型定义
```

### 4.6 extension.ts 集成

```typescript
// 新增导入
import { L3PanelProvider } from "./panel/l3PanelProvider";

// activate() 中新增注册
const l3Panel = new L3PanelProvider(context, findingsByUri, output);
context.subscriptions.push(
  vscode.window.registerWebviewViewProvider("vibeguardL3Panel", l3Panel),
  vscode.commands.registerCommand("vibeguard.scanWithAi", () => l3Panel.triggerScan("file"))
);
```

### 4.7 消息协议（Webview ↔ Extension）

```typescript
// Extension → Webview
type PanelMessage =
  | { type: "scanStarted"; scanId: string; scope: "file" }
  | { type: "scanProgress"; scanId: string; message: string }
  | { type: "scanComplete"; scanId: string; findings: PanelFinding[]; outcome: L3ReviewOutcome }
  | { type: "scanCancelled"; scanId: string }
  | { type: "scanError"; scanId: string; code: "notConfigured" | "budgetExceeded" | "remoteFailed"; message: string }
  | { type: "configUpdated"; config: PanelConfig };

// Webview → Extension
type PanelRequest =
  | { type: "scan"; scope: "file" }
  | { type: "cancelScan"; scanId: string }
  | { type: "openFinding"; findingId: string }
  | { type: "applyFix"; findingId: string }
  | { type: "ignoreFinding"; findingId: string; scope: "line" | "file" | "global" }
  | { type: "openSettings" };

interface PanelFinding {
  id: string;
  severity: Severity;
  ruleId: string;
  message: string;
  file: string;
  line: number;
  evidence: string;
  suggestion?: string;
  hasFix: boolean;
}

interface PanelConfig {
  provider: LlmProvider;
  model: string;
  hasApiKey: boolean;
  remoteReviewApproved: boolean;
}
```

---

## 5. JetBrains 插件实现方案

### 5.1 ToolWindow 方案

JetBrains 使用 `ToolWindow` API 创建面板：

```
┌─ VibeGuard ──────────────────────────────┐
│  [Scan with AI]  [Settings]              │
├──────────────────────────────────────────┤
│  Scope: Current File                     │
│  Model: DeepSeek-v4-flash                │
├──────────────────────────────────────────┤
│  Status: Ready                           │
│  Last: 2.3s · 3 finds                    │
├──────────────────────────────────────────┤
│  ┌─ Findings ────────────────────────┐   │
│  │  🔴 HIGH  Missing authentication  │   │
│  │         app.ts:42                 │   │
│  │         [Open] [Fix] [Ignore]     │   │
│  ├──────────────────────────────────┤   │
│  │  🟡 MEDIUM  Missing rate limit   │   │
│  │         app.ts:42                 │   │
│  │         [Open] [Ignore]           │   │
│  └──────────────────────────────────┘   │
└──────────────────────────────────────────┘
```

### 5.2 plugin.xml 新增

```xml
<extensions defaultExtensionNs="com.intellij">
  <platform.lsp.serverSupportProvider
      implementation="dev.vibeguard.jetbrains.VibeGuardLspServerSupportProvider"/>

  <toolWindow id="VibeGuard"
              anchor="right"
              icon="dev.vibeguard.jetbrains.icons.VibeGuardIcons.ToolWindow"
              factoryClass="dev.vibeguard.jetbrains.ui.VibeGuardToolWindowFactory"/>
</extensions>
```

### 5.3 新增 Java/Kotlin 文件

```
jetbrains/src/main/java/dev/vibeguard/jetbrains/
├── VibeGuardLspServerDescriptor.java        (existing)
├── VibeGuardLspServerSupportProvider.java   (existing)
├── ui/
│   ├── VibeGuardToolWindowFactory.java      # ToolWindow 工厂
│   ├── VibeGuardPanel.java                  # 主面板 (JBPanel)
│   ├── ScanResultList.java                  # 结果列表 (JBList)
│   ├── ScanResultCellRenderer.java          # 列表项渲染器
│   └── ScanAction.java                      # 扫描按钮 Action
├── icons/
│   └── VibeGuardIcons.java                  # 图标定义
└── lsp/
    └── VibeGuardLspBridge.java               # 仅在通信 spike 成功后实现
```

`ToolWindowFactory` 应实现 `DumbAware`，所有扫描在后台线程执行；UI 更新通过 ToolWindow 生命周期绑定的 `Disposable` 回到 EDT。ToolWindow 打开时才创建内容，项目关闭时必须取消活动扫描。

### 5.4 前置技术验证：JetBrains ↔ LSP 通信

JetBrains 不能直接调用 Node.js 扫描逻辑，但当前插件只负责启动 `ProjectWideLspServerDescriptor`，并没有文稿中假定的 `descriptor.sendCustomCommand(...)` API。LSP 的 `workspace/executeCommand` 能力可用，不代表插件端已有调用和订阅自定义 notification 的封装。

在 UI 实现前完成一个针对 IntelliJ 2025.2.4 的 spike，并将结果作为 Phase 2 的准入条件：

1. 从 ToolWindow action 获取该项目的活动 VibeGuard LSP 会话。
2. 发送 `workspace/executeCommand`，参数为当前已打开文档 URI；命令响应返回类型化的 `L3ReviewOutcome`。不要将自定义 notification 作为唯一结果通道。
3. 验证取消、服务未启动、项目关闭、文档版本变化和多项目并发时的行为。
4. 为 bridge 写集成测试；如果 2025.2.4 无法提供稳定客户端调用入口，则 JetBrains v0.2.0 只交付 ToolWindow 壳和现有诊断入口，不承诺手动 L3。

### 5.5 JetBrains 密钥与结果生命周期

- JetBrains 不复用 VSCode SecretStorage。v0.2.0 先复用 LSP 的环境变量 / OS 凭据读取路径，并在 ToolWindow 明确显示“已配置 / 未配置”。
- 若要在 ToolWindow 内设置 API Key，必须另行设计 JetBrains 的安全存储与删除路径；不能把明文放入项目设置或 LSP notification。
- 命令响应返回当前文件的 L3 findings。插件在本地保留 scanId，只有仍是最新 scanId 且文档版本未变化时才更新列表与诊断。

---

## 6. L3 扫描流程详细设计

### 6.1 扫描触发方式

| 触发方式 | 当前 | 升级后 |
|---------|------|--------|
| 打开文件 | L1 自动 | L1 自动（不变） |
| 编辑代码 | L1 实时 + L2 防抖 | L1 实时 + L2 防抖（不变） |
| 保存文件 | L1 + L2 + L3 自动 | L1 + L2 + L3 自动（不变） |
| 面板按钮 | ❌ 无 | ✅ 一键 L3 扫描 |
| 命令面板 | ❌ 无 | ✅ `VibeGuard: Scan with AI` |

### 6.2 面板扫描与自动扫描的关系

```
                 ┌──────────────────┐
                 │   scanSourceFile  │
                 │   (scanner.ts)    │
                 └────────┬─────────┘
                          │
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
     自动扫描          面板扫描      命令触发
     (onSave)        (panel button) (cmd palette)
     L1+L2+L3        L3 only        L3 only
     结果→诊断        结果→面板+诊断   结果→面板+诊断
```

面板扫描只跑 L3，不重复 L1/L2（L1/L2 已经在实时运行）。扫描完成后：
1. 仅当 scanId 仍是最新且文档版本未变化时，才将 L3 结果合并到 `findingsByUri`（通过 `mergeFindingsForExecutedLayers`）
2. 更新编辑器诊断（波浪线）
3. 更新面板的“本次 AI 深度扫描”结果列表；当前文件的 L1/L2 仅作为分层摘要或独立筛选视图，不能与本次会话结果混为一组

### 6.3 工作区扫描策略

工作区远程 L3 不属于 v0.2.0 的必交付功能。它在后续版本或 feature flag 下开放，前提是以下预算契约完成：

1. 使用与当前 `scanWorkspace` 相同的排除规则和文件上限；候选文件按风险信号、文件大小和稳定路径排序，而不是目录遍历顺序。
2. 先做本地预筛，再向用户展示“候选数、将扫描的文件、provider、预计上限”，由用户确认后才发送远程请求。
3. 同时限制候选文件数、单文件 prompt 大小、总 prompt 字符数 / token 预算、最大请求数和并发度（默认串行）。
4. 支持取消与部分完成；取消后保留已完成结果并标记范围不完整。任何文件版本变化或新 scanId 都使旧结果失效。
5. 远程模型不可用时不自动扩大到全工作区本地扫描；明确显示“未远程扫描 / 本地回退”的文件数。

### 6.4 API Key 与远程授权缺失处理

```
用户点击 "Scan with AI"
    │
    ├── Local (Ollama) ──▶ 正常本地扫描
    │
    └── 远程 Provider
         ├── 无 API Key ──▶ 面板显示提示：
                        "No API key configured for {provider}.
                         [Set API Key] [Open Settings] [Use Local (Ollama)]"

                         点击 [Set API Key] → 触发 vibeguard.setLlmApiKey 命令
                         点击 [Open Settings] → 打开平台对应设置
         └── 未授权远程代码外发 ──▶ 展示 provider / model / endpoint / 范围，
                                     用户确认后才发起请求；拒绝时不扫描
```

---

## 7. 数据模型扩展

### 7.1 types.ts 新增

```typescript
export interface LlmUsageStats {
  provider: LlmProvider;
  model: string;
  tokensIn?: number;
  tokensOut?: number;
}

export type L3ReviewStatus = "remote" | "local" | "localFallback" | "notConfigured" | "cancelled" | "failed";

export interface L3ReviewOutcome {
  status: L3ReviewStatus;
  findings: Finding[];
  provider: LlmProvider;
  model: string;
  elapsedMs: number;
  usage?: LlmUsageStats;
  errorCode?: "notConfigured" | "budgetExceeded" | "remoteFailed";
  filesScanned: number;
}
```

### 7.2 设置归属

- v0.2.0 不向共享 `VibeGuardConfig` 添加 UI 专属 `l3_panel` 字段，避免 CLI、LSP、VSCode 与 JetBrains 产生不一致的 schema、迁移和写回行为。
- VSCode 面板状态使用 VSCode Settings；JetBrains 面板状态使用项目级 `PersistentStateComponent`。两者均不保存 API Key。
- 后续工作区远程扫描的预算属于共享扫描策略，需单独设计 schema、默认值、迁移、上限校验与 CLI 兼容性后再加入配置文件。

---

## 8. 去重与合并策略

### 8.1 L3 与 L1/L2 结果去重

L3 面板扫描的结果需要与现有 L1/L2 发现合并，避免重复报告：

```typescript
// 复用现有 mergeFindingsForExecutedLayers
const merged = mergeFindingsForExecutedLayers(
  existingFindings,    // 包含 L1/L2 结果
  l3Findings,          // 仅 L3 结果
  { l1: false, l2: false, l3: true },  // 只替换 L3 层
  true                 // replaceAll
);
```

合并操作不负责语义层面的“相同漏洞”去重：L1/L2 与 L3 即使指向同一行，也保留各自来源并由 UI 分层显示。它只保证新会话替换旧 L3 层，绝不清空未执行的 L1/L2 层。

### 8.2 面板显示分层

面板中每个 Finding 显示检测层标签：

```
┌─────────────────────────────┐
│ 🔴 HIGH · L3                │  ← AI 深度分析
│ Missing authentication      │
│ app.ts:42                   │
│ [Open] [Review & Apply Fix] │
└─────────────────────────────┘

┌─────────────────────────────┐
│ 🔴 HIGH · L1                │  ← 实时检测
│ Hardcoded OpenAI API key    │
│ app.ts:15                   │
│ [Open] [Fix] [Ignore]       │
└─────────────────────────────┘
```

---

## 9. 实现计划

### Phase 0: 约束与 JetBrains 通信 Spike（~1 天）

| 任务 | 说明 |
|------|------|
| 手动 L3 outcome 合约 | 定义 `L3ReviewOutcome`、scanId、取消、远程/本地回退与可选 usage |
| 远程扫描授权 | 明确 provider、model、endpoint、范围、预算与按工作区授权的状态机 |
| JetBrains bridge spike | 在 2025.2.4 验证 ToolWindow → `workspace/executeCommand` → 类型化响应；失败即调整 JetBrains v0.2.0 承诺 |

### Phase 1: VSCode 当前文件面板（核心，~3 天）

| 任务 | 文件 | 说明 |
|------|------|------|
| 手动 review service | `src/l3/manualReview.ts` | 预检、授权、预算、取消和 outcome；当前文件 L3 only |
| WebviewViewProvider 骨架 | `src/panel/l3PanelProvider.ts` | 注册 Webview，持有 scanId 与可恢复状态 |
| HTML 模板 + CSS | `src/panel/l3PanelHtml.ts` | 使用 VSCode 主题变量；Finding 仅纯文本渲染 |
| 消息协议实现 | `src/panel/l3PanelMessages.ts` | Webview ↔ Extension 双向通信和运行时 schema 校验 |
| 扫描逻辑接入 | `src/panel/l3PanelProvider.ts` | 调用共享 review service，丢弃过期结果 |
| 结果展示 + 操作按钮 | `src/panel/l3PanelHtml.ts` | Open / Ignore / Review & Apply Fix，复用现有安全流程 |
| package.json 注册 | `package.json` | 新增 view、commands、menus |
| extension.ts 集成 | `src/extension.ts` | 注册 Provider 和 Commands |

### Phase 2: 安全、兼容与自动化验证（~2 天）

| 任务 | 说明 |
|------|------|
| 远程 provider mock 测试 | 覆盖 usage 可用/缺失、超时、错误、本地回退和不泄露 API Key |
| 并发与取消测试 | 覆盖重复点击、取消、文件变化、关闭面板与过期 scanId |
| Webview 安全测试 | 验证 CSP、消息校验、HTML escaping 和 L3 修复确认 |
| VSCode 集成验证 | 当前文件扫描、诊断合并、不清空 L1/L2、无密钥与授权拒绝路径 |

### Phase 3: JetBrains 当前文件面板（~4 天，需通过 Phase 0）

| 任务 | 文件 | 说明 |
|------|------|------|
| ToolWindow Factory | `ui/VibeGuardToolWindowFactory.java` | 注册 ToolWindow |
| 面板 UI (Swing) | `ui/VibeGuardPanel.java` | JBPanel + ScanResultList |
| 扫描按钮 Action | `ui/ScanAction.java` | 通过已验证 bridge 触发当前文件扫描 |
| LSP 命令扩展 | `lspServer.ts` | 新增 `vibeguard.scanWithAi`，返回 `L3ReviewOutcome` |
| 结果合并 | `lspServer.ts` + `ui/VibeGuardPanel.java` | 仅接受最新 scanId 与当前文档版本的结果 |
| plugin.xml 注册 | `plugin.xml` | ToolWindow 扩展注册 |
| 图标资源 | `icons/VibeGuardIcons.java` | ToolWindow 图标 |
| 生命周期测试 | `jetbrains/` | 覆盖项目关闭、服务未启动和 indexing 状态 |

### Phase 4: 后续版本 / Feature Flag

| 任务 | 说明 |
|------|------|
| 工作区远程扫描 | 候选预览、确认、总预算、取消、部分完成和文件排序后再开放 |
| 扫描历史记录 | 只存聚合元数据，不保存源码、证据或 API Key |
| 自定义快捷键 | 仅提供可配置 keybinding；不占用 VSCode 默认的 `Ctrl+Shift+V` |
| 文档与发布 | README 截图、隐私说明、provider 数据外发说明、CHANGELOG |

---

## 10. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 代码外发与合规 | 远程 LLM 会接收用户代码，即使其中密钥已脱敏 | 每工作区显式授权，展示 provider/model/endpoint/范围；拒绝即不发送；README 说明数据流 |
| LLM 调用成本 | 工作区扫描可能消耗大量 token | v0.2.0 仅当前文件；后续同时限制文件数、单文件 prompt、总预算、请求数和并发 |
| LLM 超时或失败 | 用户误以为得到了远程审查 | 复用 8s 超时，但 outcome 必须显示 `localFallback` 或 `failed`，不伪装为远程结果 |
| API Key 安全 | Webview 或项目设置泄露 Key | Key 只由平台安全存储 / OS 凭据读取；Webview 只显示 `hasApiKey`；JetBrains 设置路径单独设计 |
| 过期扫描结果 | 文件改变后旧 finding 覆盖新诊断 | scanId + 文档版本检查；取消和关闭项目时中止请求 |
| JetBrains LSP 限制 | 自定义命令客户端不可用或不稳定 | Phase 0 在目标版本做 bridge spike 和集成测试；失败时降级范围 |
| Webview 注入 | Finding 或 LLM 内容注入脚本 | 严格 CSP、无远程资源、纯文本渲染、消息 schema 校验 |

---

## 11. 与现有功能的关系

### 11.1 不改动的部分

- `scanner.ts` 的 L1/L2/L3 检测规则 — 复用，不改变规则语义
- `l3/analyzer.ts` 本地语义分析规则 — 复用，不改变规则语义
- L1/L2 实时检测流程 — 不改动
- Quick Fix 机制 — 不改动（面板通过同一套源码校验和 L3 人工确认流程应用修复）
- 忽略规则系统 — 不改动（面板的 Ignore 按钮调用 `appendIgnoreRule`）
- CLI 扫描器 — 不受影响
- GitHub Action — 不受影响
- Team Dashboard — 不受影响

### 11.2 新增的部分

- 共享：`src/l3/manualReview.ts` 与 outcome / 取消合约；`l3/llm.ts` 增加 usage 和来源适配
- VSCode：`src/panel/` 下的 Provider、HTML、消息协议和类型；`package.json` 注册 view 与 command
- JetBrains：仅在 bridge spike 通过后增加 ToolWindow、bridge、生命周期管理和 LSP command
- 类型与测试：`L3ReviewOutcome`、provider mocks、Webview 安全、并发取消和跨端契约测试

### 11.3 向后兼容

- 面板是新增功能，不影响任何现有行为
- 用户不打开面板时，VibeGuard 行为与 v0.1.x 完全一致
- L3 自动扫描（onSave）仍然保留，面板是额外的手动入口
- v0.2.0 不引入共享配置文件的 UI 专属字段；面板偏好由各 IDE 的设置系统保存，密钥仍留在安全存储

---

## 12. 用户体验流程

### 12.1 首次使用

```
1. 用户安装 VibeGuard v0.2.0
2. 打开代码文件，L1 实时检测开始工作（波浪线）
3. 点击侧边栏 VibeGuard 图标 → 看到 "AI Deep Scan" 面板
4. 面板显示: "Ready · Configure L3 provider to enable AI deep scan"
5. 用户点击 [Settings] → 选择 Provider → 输入 API Key
6. 面板状态变为: "Ready · DeepSeek-v4-flash · API Key configured"
7. 用户点击 [Scan with AI]
8. 首次远程扫描前，面板展示 provider、model、endpoint、当前文件范围与代码外发说明；用户确认后才开始
9. 面板显示: "Scanning... Analyzing current file with DeepSeek"，可取消
10. 完成后显示: "Remote complete · 2.3s · 3 findings"；只有 provider 返回 usage 时才附带 token 数
11. 结果列表展示 L3 发现，可点击 Open、Ignore 或 Review & Apply Fix
```

### 12.2 日常使用

```
1. 写代码 → L1 实时检测自动运行（无需操作）
2. 保存文件 → L1+L2 自动运行；若 L3 已启用且配置完成，再执行 L3
3. 想手动深度扫描 → 点击面板 [Scan with AI] 按钮
4. v0.2.0 范围为当前文件；工作区远程扫描在后续版本的预算确认流程中开放
5. 查看结果 → 面板列表显示本次 L3 结果，并可查看当前文件 L1/L2 分层摘要
6. 应用修复 → 面板 [Review & Apply Fix] → 源码匹配校验与用户确认后才编辑
7. 忽略误报 → 面板 [Ignore] → 添加忽略规则
```

---

## 13. 商业价值

### 13.1 提升 Pro 转化

| 维度 | 现状 | 升级后 |
|------|------|--------|
| L3 可见性 | 隐形功能，用户不知道存在 | 面板醒目展示 AI 能力 |
| L3 触发 | 命令入口不易发现 | 有明确的当前文件手动扫描入口 |
| Pro 价值感知 | 结果来源与远程状态不清晰 | 面板显示模型、来源、耗时和可用 usage |
| 升级引导 | 仅命令面板 | 面板内 "Upgrade to Pro" 提示 |

### 13.2 差异化竞争力

对外材料不使用未注明日期和来源的竞品功能对照表。发布前应逐项核对官方资料并标注采集日期；当前文档只保留可验证的产品主张：VibeGuard 提供可见的手动 L3 审查入口、审查来源标记和双 IDE 的一致工作流。

---

## 14. 验收标准

- [ ] VSCode 侧边栏显示 "AI Deep Scan" Webview 面板
- [ ] 面板的 "Scan with AI" 只扫描当前文件，并在远程 provider 的首次调用前要求工作区级显式授权
- [ ] 授权页显示 provider、model、endpoint、范围；拒绝授权时不发送网络请求
- [ ] 扫描过程可见、可取消；重复点击、文件修改、关闭面板或项目后，旧结果不得覆盖新状态
- [ ] 扫描完成后显示 severity、rule、message、file:line 和 `remote` / `local` / `localFallback` 来源
- [ ] token 仅在 provider 返回 usage 时展示；usage 缺失时 UI 明确标记为不可用
- [ ] 无 API Key、超时、远程失败、本地回退均有不同且可测试的状态
- [ ] 结果项可点击 Open、Ignore、Review & Apply Fix；L3 修复必须经过源码匹配校验和显式确认
- [ ] 面板结果只替换 L3 层，不清空当前 L1/L2 diagnostics；所有 finding 文本被安全转义
- [ ] CSP、`localResourceRoots` 和 Webview 消息 schema 校验有自动化测试；API Key 不进入 Webview 或项目设置
- [ ] JetBrains ToolWindow 仅在 Phase 0 bridge 通过后承诺当前文件扫描，并覆盖服务未启动、取消、项目关闭和文档版本变化
- [ ] 暗色/亮色主题正确渲染，不影响 L1/L2 现有实时检测行为
- [ ] 工作区远程扫描不属于 v0.2.0 验收范围
