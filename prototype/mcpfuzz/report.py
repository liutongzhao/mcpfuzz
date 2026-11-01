"""报告渲染：把一次扫描的 Finding 列表写成人读 Markdown，说清楚每个确认漏洞的触发流程。"""
from __future__ import annotations

import time

from mcpfuzz.orchestrator import CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED


def render_markdown(catalog, findings: list, meta: dict | None = None) -> str:
    meta = meta or {}
    # 可用性/DoS 是整工具级观测，单列一节，不混入 per-param 五态与覆盖率
    dos = [f for f in findings if f.sink == DOS]
    params = [f for f in findings if f.sink != DOS]
    confirmed = [f for f in params if f.status == CONFIRMED]
    suspected = [f for f in params if f.status == SUSPECTED]
    clean = [f for f in params if f.status == LIKELY_CLEAN]
    unreached = [f for f in params if f.status == UNREACHED]
    skipped = [f for f in params if f.status == SKIPPED]
    tested = len(confirmed) + len(suspected) + len(clean) + len(unreached)

    lines = [
        f"# MCPFuzz 检测报告 — {catalog.server_name or '?'} {catalog.server_version or ''}".rstrip(),
        "",
        f"- 目标：`{catalog.url}`",
        f"- 协议版本：{catalog.protocol_version}",
        f"- 工具数：{len(catalog.tools)}",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"## 结论总览",
        "",
        f"> 实际测试覆盖：{tested}/{len(params)} 个参数（“未测成”不计入）。",
        "",
        f"| 状态 | 数量 | 含义 |",
        f"|---|---|---|",
        f"| ● 确认漏洞 | {len(confirmed)} | 铁证命中，或可证经复测 |",
        f"| 疑似有 | {len(suspected)} | 仅弱证据（错误指纹 / 回连未越边界），**需人工复核** |",
        f"| 疑似无漏洞 | {len(clean)} | 本参数探针已触达 sink，全套无命中 |",
        f"| 未触达 | {len(unreached)} | 本参数探针全被输入/schema 校验挡下，未触达 sink |",
        f"| 未测成 | {len(skipped)} | 工具侧原因未能发出有效测试，**不代表无漏洞** |",
        f"| 总计 | {len(params)} | |",
        "",
    ]
    if dos:
        lines.append(f"> ⚠ 另有 **{len(dos)}** 个工具在整套测试后存活探测持续失败（疑似 DoS/可用性），详见下节。")
        lines.append("")

    if confirmed:
        lines.append("## 确认漏洞（含触发流程）")
        lines.append("")
        for i, f in enumerate(confirmed, 1):
            lines += _render_confirmed(i, f)
    else:
        lines.append("## 确认漏洞")
        lines.append("")
        lines.append("（本次运行未确认任何漏洞）")
        lines.append("")

    if dos:
        lines.append("## 可用性 / 拒绝服务（疑似 DoS，需人工复核）")
        lines.append("")
        lines.append("> 整套载荷打完后，连续多次存活探测（复用会话心跳 + 新开会话）均失败，"
                     "服务器疑似被打到崩溃/无响应。需人工复测确认是稳定可复现的 DoS 还是环境抖动。")
        lines.append("")
        for f in dos:
            lines.append(f"- `{f.tool}`：{f.note or '无说明'}")
        lines.append("")

    if suspected:
        lines.append("## 疑似有（仅弱证据，需人工复核）")
        lines.append("")
        for f in suspected:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink})｜通道 {f.channel}｜载荷 `{f.payload}`"
                         f"｜证据 `{f.evidence}`")
        lines.append("")

    if unreached:
        lines.append("## 未触达（载荷已发出，但全部被目标工具拒绝/报错）")
        lines.append("")
        for f in unreached:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink})：{f.note or '无说明'}")
        lines.append("")

    if skipped:
        lines.append("## 未测成（工具侧原因，未能发出有效测试 —— 不代表无漏洞，建议复测）")
        lines.append("")
        for f in skipped:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink})：{f.note or '无说明'}")
        lines.append("")

    if clean:
        lines.append("## 疑似无漏洞")
        lines.append("")
        for f in clean:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink})")
        lines.append("")

    return "\n".join(lines)


def _render_confirmed(i: int, f) -> list[str]:
    out = [f"### {i}. `{f.tool}.{f.param}` — {f.sink}", ""]
    out.append(f"- **判定通道**：{f.channel}")
    out.append(f"- **命中载荷**：`{f.payload}`")
    out.append(f"- **证据**：`{f.evidence}`")
    if f.sequence:
        out.append("- **触发流程**（可直接按此序列复现）：")
        out.append("")
        for step_i, step in enumerate(f.sequence, 1):
            tool = step.get("tool")
            args = step.get("args")
            if step.get("is_error"):
                out.append(f"  {step_i}. `{tool}` {args}  → 调用报错（前置步骤）")
            elif "payload_param" in step:
                out.append(f"  {step_i}. `{tool}` {args}  ← **注入点**（参数 `{step['payload_param']}`）")
            else:
                out.append(f"  {step_i}. `{tool}` {args}")
    out.append("")
    return out


def render_dry_run_markdown(catalog, plans: list[dict]) -> str:
    """recon/dry-run 的报告：只列攻击面与计划，不含任何判定结果。"""
    lines = [
        f"# MCPFuzz 攻击面预览 — {catalog.server_name or '?'} {catalog.server_version or ''}".rstrip(),
        "",
        f"- 目标：`{catalog.url}`",
        f"- 工具数：{len(catalog.tools)}",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "本次为 dry-run：只预览将要测试的工具/参数与调用计划，未发送任何载荷。",
        "",
        "## 计划",
        "",
    ]
    for p in plans:
        reach = "" if not p.get("reachable", True) else ""
        lines.append(f"- `{p.get('tool')}`：{p.get('steps')} 步，{p.get('param_count')} 个参数待测"
                     f"{'（不可达：' + p.get('note', '') + '）' if not p.get('reachable', True) else ''}")
    lines.append("")
    return "\n".join(lines)
