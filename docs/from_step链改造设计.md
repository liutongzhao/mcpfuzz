# from_step 链改造设计（阶段二序列构建/回放）

> 范围：目标工具参数里"值来自前置响应"（from_step）这条链的**判定 → 回放抽取 → 兜底**。
> 目标：修掉前一次检测里量化到的两类损失——A 裂缝2（字面量↔动态值误判）、B（回放时从响应里抽错值）。
> 原则：全局通用、schema/JSON 结构驱动，不对任何具体服务特判；最坏情况只退化、不变差。

## 背景（问题与实测）

阶段二把"有状态的探索过程"压成一串"无状态调用清单"，回放到另一个会话里重放。from_step 这条链上有两个独立缺陷：

- **A 裂缝2 分类误判**：现在用"值长度≥6 且作为子串出现在某前置响应文本里"判 from_step。假阳——固定枚举值（如 `action="current"`）碰巧在响应文本里出现过被误判为动态值，回放取不到→整台工具判死；假阴——短值/被改形的值/布尔漏判为字面量，回放用陈旧值。
- **B 抽错值**：`extract.py` 用"关键词子串匹配 + 拍平取第一个"从响应里挑值，`id` 子串命中 `owner.id` 而取不到 `repos[0].id`，**静默取错**；取不到还会在回放阶段掉进 LLM，破坏确定性。

实测（44 样本 pos+neg，899 个 tool-run）：101 个参数因 from_step"未能取值"被硬 SKIP（整台工具全丢），83 个集中在 from_step 密集的服务器。多前置参数的工具最惨——6 个 from_step 只要 1 个崩，整台报废（AND 条件）。

## 核心改动：探索时记"路径+原值"，回放时按路径取、兜底退回原值

from_step 规格从"只记自然语言提示"升级为"记精确 JSON 路径 + 原值"：

```
旧：{"src":"from_step","step":1,"extract":"repo_id (value looks like '99887766')"}
新：{"src":"from_step","step":1,"path":["repos",0,"id"],"value":"99887766","extract":"repo_id"}
```

一条改动同治三处：
1. **判定更准**（A 裂缝2）：判据从"值是响应文本子串"收紧为"值等于前置响应 JSON 里某个叶子、且能定位路径"。只是文本里出现过一个词（`"current"`）但不是某叶子值 → 不再误判为 from_step。
2. **抽取更准**（B）：回放按 `path` 直接读，不子串猜、不拍平取第一个。
3. **兜底不塌**：path 取不到时退回 `value`，而不是判 missing→SKIP 整台工具。

## 各处改动

### 1. `agent._arg_spec` + `_build_plan_from_calls`（判定）

- **记路径**：发现"值出现在前置响应"时，解析该响应 JSON，定位 `value` 所在叶子路径；定位到 → from_step 带 `path`+`value`+`extract`；定位不到（纯文本子串巧合）→ 判字面量。
- **schema 护栏**：目标参数**有 enum** 的一律字面量、绝不 from_step（枚举是固定选项，不可能来自前置响应）。`_build_plan_from_calls` 把目标参数 schema 传给 `_arg_spec`。
- 前置步参数无 schema，照新"路径定位"判，不加枚举护栏（够用）。

### 2. `extract.py`（回放抽取）

`extract_value(response_text, extract_desc="", path=None, value=None)` 分层：
1. **按路径取**：有 `path` → 重解析响应、读该路径；读到非空即返回（确定性，无 LLM）。
2. **打分字段匹配**（无 path 时，主要给 planner 路径/schema 漂移兜底）：键名与关键词都按驼峰/下划线**切词**，算**词级**重合而非裸子串；候选按 `精确键名 > 整词命中 > 路径含更多关键词` 打分，**取最高分**，不取第一个。
3. **兜底**：有 `value`（智能体路径）→ 退回 `value`（确定性，智能体路径回放全程不碰 LLM）；无 `value`（planner 路径）→ 才用收敛后的 LLM（让其返回可验证子串、校验存在）。

### 3. `executor._resolve_args`（解析）

from_step 调 `extract_value(resp, extract, path, value)`。因兜底会退回 `value`，智能体路径的 from_step 基本不再进 `missing`——消除"一个抽不到连累整台工具"。

## 覆盖与不覆盖

| 问题 | 本次（线一） |
|---|---|
| A 裂缝2 字面量↔动态误判 | 根治（路径定位 + enum 护栏） |
| B 抽错值 / 回放不确定 | 根治（按路径取 + 打分 + 智能体路径不碰 LLM） |
| A 硬 SKIP（101个） | 根治（退回原值兜底） |
| A 裂缝1 会话态丢 / 裂缝3 目标自身状态 | **不覆盖**，留给线二（活会话攻击） |

## 兼容性

- from_step 规格新增 `path`/`value` 字段，JSON 可序列化，进计划缓存无碍；旧缓存无这些字段 → `extract_value` 退化为旧行为（字段匹配→LLM），不报错。
- planner 路径仍只产 `extract`（LLM 不知路径），走打分匹配 + LLM 兜底，与现状等价或更好。

## 验证

线一上线后在 486 冻结快照跑 before/after：重点看 from_step"未能取值"SKIP 数（期望 101→大幅下降）、召回（期望小涨）、精确（期望持平，须确认无新误报）。

## 线二：活会话攻击（已实现）

探索+攻击并进**一个 session、一个 loop**，智能体建的状态是活的、攻击就地打、**不重放前置**，根治裂缝1/3 并恢复 besteffort 工具的 differential/timing 通道。已确认会话类型通用（`load_mcp_tools` 与 `driver.call_on` 同吃 `mcp.ClientSession`，无需适配层）。

实现要点：
- `agent.explore_on_session(session, tools, target_tool, settings, reporter)`：在**已打开的会话**上跑 ReAct，不再自己开 `client.session`；删除旧的 `_run_langgraph` / `build_sequence`（两会话路径）。
- `core._explore_and_attack`：开一个 `open_session` → 命中缓存则重放配方（`live=False`）/否则 `explore_on_session` 建活状态（`live=True`）→ 同一会话 `run_tool(..., live=live)`。智能体失败则 `fallback_plan` 就地单步攻击。
- `executor.run_tool(..., live=True)`：**跳过前置重放**（状态已活），目标 from_step 参数靠记录值解析（线一的 value 兜底）。
- 事件循环统一：探索+攻击同跑持久 agent loop；`core._explore_and_attack_sync` 捕获真实错误时 `_reset_agent_loop_after_abort()` 重建 loop 防跨工具污染，但预算/超时（含 anyio 包成的 group）与全模型不可用照常上抛各自处理器。
- **仅改智能体路径**：直达（~52%）与 planner 兜底仍走原 `_attack_tool` 重放，不动已经工作良好的那半。

取舍（允许不完美）：活会话中途掉线无法像重放路径那样换新会话重试（状态会丢），该工具记 SKIPPED；属罕见瞬断，接受。

## 验证现状

单元级已验证：live=True 不重放前置且 from_step 靠记录值解析、live=False 仍重放前置（回归）、三模块编译 + 自检通过。**真实靶机的 before/after 统一留到后面一起跑。**
