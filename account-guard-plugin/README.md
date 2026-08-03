# grok2api-account-guard

> 纯 [CLIProxyAPI (CPA)](https://github.com/router-for-me/CLIProxyAPI) 原生插件：**被动、以账号为中心**的质量守护 —— 盯住每个账号的输出 Token/s 与失败情况，命中阈值就自动停用或删除该账号。
> **零出口节点配置** —— 不需要 proxy_url、不做迁号、不做主动探测。

| | |
|---|---|
| 插件名 | `grok2api-account-guard` |
| 当前版本 | **1.0.0** |
| 语言 | Go (`-buildmode=c-shared` → `.so`) |
| CPA SDK | `CLIProxyAPI/v7` (`pluginabi` / `pluginapi`) |
| 能力 | Management UI + Usage Plugin |
| 菜单名 | **账号守护** |
| License | MIT（见仓库根目录 `LICENSE`） |

---

## 它解决什么问题

同仓库的 [`grok2api-egress`](../cpa-plugin/README.md) 以**出口节点**为中心：账号必须先绑定到节点，判定与动作都围绕节点（隔离 / 迁号）。

但很多部署根本不建模出口节点，只想要一件事：

> **某个账号降智了（Token/s 异常飙升）或连续失败，就把它停掉/删掉，别再往里灌流量。**

本插件就只做这一件事：

- 订阅 CPA usage hook，**仅在账号被实际调用时**评估它
- 用与 egress 插件相同的判定语义（`computeTPS` / `classifyTPS`，**Token/s 越高越差**）
- 命中软 / 硬 / 连续失败三档中任意一档 → 执行该档配置的动作（停用 / 删除 / 不处理）
- 无节点、无 `proxy_url`、无主动探测、无后台 worker

---

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│  CLIProxyAPI (host)                                         │
│   ├─ Management UI  ──► /v0/resource/plugins/.../status     │
│   ├─ Management API ──► /v0/management/grok2api-account-guard│
│   ├─ Usage hook     ──► MethodUsageHandle（唯一驱动来源）    │
│   └─ Auth files     ──► xai-*.json（读 / 停用 / 删除）       │
│                                                             │
│  plugin: grok2api-account-guard.so                          │
│   ├─ store.go   状态持久化（policy / accounts / events）     │
│   ├─ auth.go    list/get/save auth、删除守卫、启用账号计数    │
│   ├─ guard.go   TPS 分类 · strikes 计数 · 安全阀 · 动作      │
│   ├─ main.go    ABI · UI 代理 · API 路由                     │
│   └─ page.html  管理台（go:embed）                           │
└─────────────────────────────────────────────────────────────┘
```

**状态文件**（默认）：

```text
/CLIProxyAPI/plugin-data/account-guard/state.json
```

可通过插件配置字段 `state_file` 覆盖。请把该路径挂进容器可写卷。

---

## 判定逻辑

每条 usage 事件按下面的顺序处理：

1. **定位账号** —— 用 usage 记录里的 auth 标识经 Host API 取账号文件。取不到 → 只记 `usage_unmapped` 事件和统计，**绝不动任何账号**。
2. **分类**：

   | 分类 | 条件 |
   |---|---|
   | `failed` | usage 记录 `failed = true` |
   | `hard` | Token/s ≥ `hard_tps` |
   | `soft` | `soft_tps` ≤ Token/s < `hard_tps` |
   | `healthy` | Token/s < `soft_tps` |
   | `unknown` | 无法算出 Token/s（无输出 / 时长过短） |

3. **计数**：

   | 观测 | soft_strikes | fail_strikes | 触发 |
   |---|---|---|---|
   | `healthy` | 清零 | 清零 | — |
   | `soft` | +1 | 清零 | ≥ `consecutive_soft` → 软档动作 |
   | `hard` | 不变 | 清零 | **立即**触发硬档动作 |
   | `failed` | 不变 | +1 | ≥ `consecutive_fail` → 失败档动作 |
   | `unknown` | 不变 | 清零 | — |

4. **执行动作**：安全阀 → 观测模式 → 幂等 → 停用 / 删除。

### 两道防误判保护

- **最小生成窗口 200ms**：短回复常有 `firstToken ≈ duration`，会把 Token/s 算爆。窗口不足时回退用整段时长，仍不足则判定为无信号（TPS = 0）。
- **小输出保护**：单次输出 token < 32 时，即使算出的 Token/s 达到硬阈值也降级为 `healthy`，**永不触发不可逆的删除**。

---

## 三档动作

三档**互相独立**，每档都可以单独选 `disable` / `delete` / `none`：

| 档位 | 触发条件 | 配置项 | 默认动作 |
|---|---|---|---|
| 软阈值 | 连续 `consecutive_soft` 次 `soft` | `soft_action` | `disable` 停用 |
| 硬阈值 | **单次**命中 `hard` | `hard_action` | `delete` 删除 |
| 连续失败 | 连续 `consecutive_fail` 次 `failed` | `fail_action` | `disable` 停用 |

动作语义：

| 动作 | 行为 |
|---|---|
| `disable` | 经 Host API 写入 `disabled: true` + `disabled_reason` / `disabled_at`。**保留原 `proxy_url`**，不动任何出口绑定。 |
| `delete` | 先下线再删除本地账号文件。复用安全删除守卫：文件名合法、路径与文件名一致、必须是常规文件，否则拒绝并记 `account_delete_skipped`。 |
| `none` | 只记 `action_none` 事件，不动账号。 |

> **删除不可逆。** 建议：先把 `hard_action` 设为 `disable`，或开 `dry_run` 跑一段时间看事件流，确认判定符合预期后再改成 `delete`。

---

## 安全阀 `min_keep_accounts`

**用途**：某个出口整体降智时，用它的每个账号 Token/s 都会飙 —— 被动逐个判定会把账号池删空。

**行为**：执行任何 `disable` / `delete` 前，统计当前启用（未 disabled）的 xAI 账号数。若**执行本次动作后**启用账号数会低于 `min_keep_accounts`，则抑制动作，只记一条 `action_suppressed` 事件。

```
启用账号数 - 1 < min_keep_accounts  →  抑制
```

默认 `2`。设为 `0` 关闭安全阀（不推荐配合 `delete` 使用）。

另外：**统计启用账号数失败时也会抑制动作** —— 无法确认账号池规模时，不执行不可逆操作。

---

## 观测模式 `dry_run`

`dry_run: true` 时，插件照常完成分类、计数与阈值判定，命中后记一条 **`dry_run_would_act`** 事件（标注本应执行的档位与动作），但**不实际停用或删除任何账号**，也不会给账号打上已处理标记。

上线建议流程：

1. `dry_run: true` 跑 1–2 天
2. 看管理台事件流：命中的是不是真降智账号？阈值是不是太紧/太松？
3. 调 `soft_tps` / `hard_tps` / `consecutive_*`
4. 确认无误 → `dry_run: false`

注意：安全阀在观测模式**之前**执行，所以 dry-run 也会如实反映"这次会被安全阀抑制"。

---

## 幂等与人工恢复

- **不重复动作**：已执行过动作（`action != ""`）的账号不会被重复处理。
- **人工恢复**：账号被人工在 CPA 面板改回启用（或被重新添加）后，插件下次观测到它处于启用状态时会**清除历史动作标记**并记 `account_action_cleared`；此后再次命中阈值可以重新触发。
- **已删除账号**：文件已不存在，残留 usage 事件无法映射到账号，自然不会再动作。

> **停用不会自动恢复。** 这是被动语义的必然结果：账号被停用后拿不到流量 → 不再产生 usage 事件 → 插件没有依据判定它已恢复。需要放回请人工启用，或改用 `grok2api-egress` 的主动探测。

---

## 配置字段

插件 YAML 只有一项：

```yaml
state_file: /CLIProxyAPI/plugin-data/account-guard/state.json
```

策略在**管理台界面**里配置（持久化进状态文件）：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `soft_tps` | float | `500` | 软阈值 Token/s，必须 > 0 且 < `hard_tps` |
| `hard_tps` | float | `1000` | 硬阈值 Token/s |
| `consecutive_soft` | int | `2` | 连续多少次 `soft` 触发软档动作 |
| `consecutive_fail` | int | `3` | 连续多少次 `failed` 触发失败档动作 |
| `soft_action` | enum | `disable` | `disable` / `delete` / `none` |
| `hard_action` | enum | `delete` | `disable` / `delete` / `none` |
| `fail_action` | enum | `disable` | `disable` / `delete` / `none` |
| `min_keep_accounts` | int | `2` | 最低保留启用账号数；`0` 关闭安全阀 |
| `dry_run` | bool | `false` | 观测模式：只记录不执行 |

校验规则：`soft_tps` 与 `hard_tps` 均须大于 0 且 `soft_tps < hard_tps`；三档 action 必须是 `disable` / `delete` / `none` 之一。非法提交会被拒绝并返回错误，**原策略保持不变**。

---

## 管理 UI

菜单名：**账号守护** · 路径：CPA 管理台 → 插件资源 `/status`

- 概览指标：守护状态、可用账号数、已处理账号数、执行/观测模式
- **账号表**：每账号的分类、Token/s、软/失败计数、动作、原因、最近观测时间与观测次数
- 策略表单：三档阈值与动作下拉、连续次数、最低保留账号数、观测模式开关（校验错误就地显示）
- 事件流 + 观测统计面板

UI 经 management 代理，请求头需 `X-Grok2API-Account-Guard-UI: 1`（页面已内置）。

### 事件类型

| 事件 | 含义 |
|---|---|
| `account_disabled` | 账号已停用 |
| `account_deleted` | 账号已删除 |
| `action_suppressed` | 安全阀抑制了动作 |
| `dry_run_would_act` | 观测模式下"本应执行"的动作 |
| `account_delete_skipped` | 删除被守卫拒绝或失败 |
| `account_disable_failed` | 停用写入失败 |
| `action_none` | 命中阈值但该档策略为 `none` |
| `account_action_cleared` | 账号已恢复启用，清除历史动作标记 |
| `usage_unmapped` | usage 事件无法定位到账号 |

事件保留最近 **100** 条（环形缓冲，随状态文件持久化）。

---

## 与 `grok2api-egress` 的关系

两个插件是**独立的 `.so`**，插件名、菜单、状态文件全部隔离，互不读写对方状态，可以同时加载。

| | `grok2api-egress` | `grok2api-account-guard` |
|---|---|---|
| 中心概念 | 出口节点（proxy_url） | 账号 |
| 判定来源 | 被动 usage + **主动探测** | **仅**被动 usage |
| 动作对象 | 节点（隔离）+ 账号（迁移/删除） | 账号（停用/删除） |
| 需要配置节点 | ✅ 必须 | ❌ 不需要 |
| 覆盖闲置账号 | ✅ 主动探测能覆盖 | ❌ 没流量就不评估 |
| 自动恢复 | ✅ 复测通过后恢复 | ❌ 需人工启用 |

### ⚠️ 同时启用的注意事项

两个插件都订阅 `MethodUsageHandle`，CPA 会**分别派发**给它们。同一条 usage 事件会被各自独立判定，因此可能对**同一个账号并发动作** —— 例如 egress 正在把它迁到健康节点，account-guard 同时把它删了。

建议：

- **二选一**是最省心的做法。
- 确实要共存：把 account-guard 三档动作里的 `delete` 全部改成 `disable`（或 `none`），把删除权交给 egress 一侧；或者反过来，让 egress 只做隔离迁号（`isolate_only`），account-guard 负责淘汰账号。
- 两者阈值建议保持一致，避免判定打架。

### 选型建议

- 有多出口代理、需要主动探测覆盖、希望账号在通道间流转 → **`grok2api-egress`**
- 单出口或不管出口、只想自动淘汰降智/坏账号、零配置起步 → **`grok2api-account-guard`**

---

## 目录结构

```text
account-guard-plugin/
└── go/
    ├── main.go        # CGO ABI、注册、Management/Usage 入口、API 路由
    ├── store.go       # state.json 读写、策略校验、账号记录、事件、统计
    ├── auth.go        # list/get/save auth、安全删除守卫、启用账号计数
    ├── guard.go       # TPS 计算与分类、字段抽取、strikes 计数、安全阀、动作
    ├── page.html      # 管理 UI（go:embed）
    ├── tokens.css     # 设计 token（go:embed）
    ├── main_test.go
    ├── go.mod
    └── go.sum
```

---

## 构建

依赖：Go 1.22+（开发环境用 1.26）、CGO、与目标 CPA 同架构的 libc。

```bash
cd account-guard-plugin/go
go mod tidy
go build -buildmode=c-shared -o grok2api-account-guard.so .
```

产物：

- `grok2api-account-guard.so`
- `grok2api-account-guard.h`（可忽略，host 不依赖此头）

交叉编译注意：`.so` 必须与 **CPA 进程架构 / libc** 一致（常见 `linux/amd64`）。

测试：

```bash
go test ./...
```

---

## 安装（CPA）

1. 复制插件：

```bash
cp grok2api-account-guard.so /path/to/CLIProxyAPI/plugins/
```

2. 确保可写状态目录（compose 示例）：

```yaml
volumes:
  - ./plugin-data/account-guard:/CLIProxyAPI/plugin-data/account-guard
```

3. 插件配置（CPA 插件 YAML，仅一项）：

```yaml
state_file: /CLIProxyAPI/plugin-data/account-guard/state.json
```

4. 重启 CPA，管理台左侧应出现 **账号守护** 菜单。

5. **首次上线建议先开 `dry_run`**，观察几天事件流再切执行模式。

---

## 已知边界

- **闲置账号永不被评估**：纯被动语义的必然结果。需要主动覆盖请用 `grok2api-egress`。
- **strikes 不随时间衰减**：很久以前的一次 `soft` 会一直留在计数里，直到该账号下次被观测为 `healthy` 才清零。
- **不区分失败原因**：被动 usage 记录不含 HTTP 状态码，只有 `failed` 布尔值，所以 429 / 5xx / 网络错误一视同仁。
- **删除仅对本地文件生效**：非文件型凭据会被删除守卫拒绝并记 `account_delete_skipped`。
