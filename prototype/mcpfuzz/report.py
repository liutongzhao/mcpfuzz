"""报告渲染：把一次扫描的 Finding 列表写成人读 Markdown，说清楚每个确认漏洞的触发流程。"""
from __future__ import annotations

import time

from mcpfuzz.orchestrator import CONFIRMED, LIKELY_CLEAN, UNREACHED


def render_markdown(catalog, findings: list, meta: dict | None = None) -> str:
    meta = meta or {}
    confirmed = [f for f in findings if f.status == CONFIRMED]
    clean = [f for f in findings if f.status == LIKELY_CLEAN]
    unreached = [f for f in findings if f.status == UNREACHED]

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
        f"| 状态 | 数量 |",
        f"|---|---|",
        f"| ● 确认漏洞 | {len(confirmed)} |",
        f"| 疑似无漏洞 | {len(clean)} |",
        f"| 未触达 | {len(unreached)} |",
        f"| 总计 | {len(findings)} |",
        "",
    ]

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

    if unreached:
        lines.append("## 未触达（可能需要更强的前置取值 / 不同基线）")
        lines.append("")
        for f in unreached:
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
