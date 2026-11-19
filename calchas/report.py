"""Report rendering: turn a scan's Finding list into human-readable Markdown.

Three concerns handled here (all pure rendering/aggregation over the Finding list — no detection logic, nothing
server-specific):
- Per confirmed vulnerability: an explanation of HOW it was confirmed (the detection method behind the channel)
  plus a replayable PoC (the exact ordered MCP calls, the last one being the injection point).
- Grouping: findings are rolled up per tool (one server = one report), so a tool hit on several parameters reads
  as one block instead of scattered lines.
- Cross-MCP summary (render_summary): aggregate many servers' findings into one overview table.
"""
from __future__ import annotations

import json
import time

from calchas.__about__ import APP_NAME
from calchas.orchestrator import CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED


def _group_by_tool(findings: list) -> list[tuple]:
    """Group findings by tool, preserving first-seen order. Returns [(tool, [findings])]."""
    order: list[str] = []
    buckets: dict[str, list] = {}
    for f in findings:
        if f.tool not in buckets:
            buckets[f.tool] = []
            order.append(f.tool)
        buckets[f.tool].append(f)
    return [(t, buckets[t]) for t in order]


def _detection_method(f) -> str:
    """A one-paragraph, human-readable explanation of why this finding was confirmed, derived generically from
    the verdict channel and evidence (no server-specific wording)."""
    ch = f.channel or ""
    ev = f.evidence or {}
    if ch == "inband":
        marker = ev.get("marker", "")
        sig = f"`{marker}`" if marker else "the expected signature"
        return ("In-band evidence: the tool response contained " + sig + ", which is not a substring of the sent "
                "payload and can only appear if the server actually executed/read the injected value "
                "(reflection-immune) — hence confirmed.")
    if ch == "timing":
        base, obs, tgt = ev.get("baseline"), ev.get("observed"), ev.get("target")
        return (f"Timing evidence: a benign baseline call took ~{base}s while the injected delay payload took "
                f"~{obs}s (intended +{tgt}s), and the delay held across repeated re-tests (every retest stayed "
                "slow) — so the injected sleep genuinely ran, ruling out one-off network jitter.")
    if ch == "oob":
        return ("Out-of-band evidence: the target called back to our collector carrying this probe's unique "
                "token, proving the injected command/request actually executed and reached the network — a "
                "signal that cannot be produced by merely echoing the input.")
    if ch == "differential":
        marker = ev.get("marker", "")
        sig = f"`{marker}`" if marker else "a parser/usage/version banner"
        return ("Differential evidence: the feature-option payload made the response show " + sig + " that is "
                "absent from the benign baseline, so the value was parsed by the backend program as a CLI option "
                "(argument injection).")
    if ch == "cross_tool":
        return ("Cross-tool evidence: the injection wrote a canary and it was read back through a paired read "
                "tool; the read-back content contains the computed canary (not the literal input), proving the "
                "write/execution truly landed.")
    return f"Confirmed via the {ch or 'oracle'} channel; see the evidence below."


def _poc_calls(f) -> list[dict]:
    """The replayable proof-of-concept: the finding's reproducible sequence as an ordered list of MCP tool calls.
    Each entry is {"tool", "arguments"} (MCP tools/call shape); the last call is the injection point."""
    calls = []
    for step in f.sequence or []:
        calls.append({"tool": step.get("tool"), "arguments": step.get("args") or {}})
    if not calls:
        # no recorded sequence (e.g. direct single-step) -> at least emit the injection call itself
        calls.append({"tool": f.tool, "arguments": {f.param: f.payload}})
    return calls


def render_markdown(catalog, findings: list, meta: dict | None = None) -> str:
    meta = meta or {}
    # Availability/DoS is a whole-tool observation, given its own section, not mixed into the per-param five-state or coverage
    dos = [f for f in findings if f.sink == DOS]
    params = [f for f in findings if f.sink != DOS]
    confirmed = [f for f in params if f.status == CONFIRMED]
    suspected = [f for f in params if f.status == SUSPECTED]
    clean = [f for f in params if f.status == LIKELY_CLEAN]
    unreached = [f for f in params if f.status == UNREACHED]
    skipped = [f for f in params if f.status == SKIPPED]
    tested = len(confirmed) + len(suspected) + len(clean) + len(unreached)

    lines = [
        f"# {APP_NAME} detection report — {catalog.server_name or '?'} {catalog.server_version or ''}".rstrip(),
        "",
        f"- Target: `{catalog.url}`",
        f"- Protocol version: {catalog.protocol_version}",
        f"- Tools: {len(catalog.tools)}",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"## Summary",
        "",
        f"> Actual test coverage: {tested}/{len(params)} parameters (\"not tested\" excluded).",
        "",
        f"| Status | Count | Meaning |",
        f"|---|---|---|",
        f"| ● Confirmed | {len(confirmed)} | hard-evidence hit, or provable on retest |",
        f"| Suspected | {len(suspected)} | weak evidence only (error fingerprint / callback not crossing the boundary), **needs manual review** |",
        f"| Likely clean | {len(clean)} | this parameter's probes reached the sink, full battery got no hit |",
        f"| Unreached | {len(unreached)} | this parameter's probes were all blocked by input/schema validation, did not reach the sink |",
        f"| Not tested | {len(skipped)} | a tool-side reason prevented a valid test, **does not mean no vulnerability** |",
        f"| Total | {len(params)} | |",
        "",
    ]
    # Tool-level roll-up: which tools carry confirmed/suspected hits (one row per affected tool)
    affected = _group_by_tool(confirmed + suspected)
    if affected:
        lines += ["### Affected tools", "",
                  "| Tool | Confirmed | Suspected | Classes |", "|---|---|---|---|"]
        for tool, fs in affected:
            c = sum(1 for x in fs if x.status == CONFIRMED)
            s = sum(1 for x in fs if x.status == SUSPECTED)
            classes = ", ".join(sorted({x.sink for x in fs}))
            lines.append(f"| `{tool}` | {c} | {s} | {classes} |")
        lines.append("")

    if dos:
        lines.append(f"> ⚠ Additionally, **{len(dos)}** tool(s) kept failing the liveness probe after the full battery (suspected DoS/availability), see the section below.")
        lines.append("")

    if confirmed:
        lines.append("## Confirmed vulnerabilities (grouped by tool, with detection method and replayable PoC)")
        lines.append("")
        n = 0
        for tool, fs in _group_by_tool(confirmed):
            lines.append(f"### `{tool}` — {len(fs)} confirmed")
            lines.append("")
            for f in fs:
                n += 1
                lines += _render_confirmed(n, f)
    else:
        lines.append("## Confirmed vulnerabilities")
        lines.append("")
        lines.append("(this run confirmed no vulnerabilities)")
        lines.append("")

    if dos:
        lines.append("## Availability / Denial of Service (suspected DoS, needs manual review)")
        lines.append("")
        lines.append("> After the full payload battery, consecutive liveness probes (session-heartbeat reuse + a new session) "
                     "all failed; the server is suspected to have been beaten to a crash/unresponsiveness. Manual retest is needed "
                     "to confirm whether it is a stable, reproducible DoS or environmental jitter.")
        lines.append("")
        for f in dos:
            lines.append(f"- `{f.tool}`: {f.note or 'no detail'}")
        lines.append("")

    if suspected:
        lines.append("## Suspected (weak evidence only, needs manual review)")
        lines.append("")
        for tool, fs in _group_by_tool(suspected):
            lines.append(f"- `{tool}`")
            for f in fs:
                lines.append(f"  - `{f.param}` ({f.sink}) | channel {f.channel} | payload `{f.payload}`"
                             f" | evidence `{f.evidence}`")
        lines.append("")

    if unreached:
        lines.append("## Unreached (payloads were sent, but all rejected/errored by the target tool)")
        lines.append("")
        for tool, fs in _group_by_tool(unreached):
            lines.append(f"- `{tool}`")
            for f in fs:
                lines.append(f"  - `{f.param}` ({f.sink}): {f.note or 'no detail'}")
        lines.append("")

    if skipped:
        lines.append("## Not tested (tool-side reason, no valid test was sent — does not mean no vulnerability, retest recommended)")
        lines.append("")
        for tool, fs in _group_by_tool(skipped):
            lines.append(f"- `{tool}`")
            for f in fs:
                lines.append(f"  - `{f.param}` ({f.sink}): {f.note or 'no detail'}")
        lines.append("")

    if clean:
        lines.append("## Likely clean")
        lines.append("")
        for tool, fs in _group_by_tool(clean):
            lines.append(f"- `{tool}`: " + ", ".join(f"`{f.param}` ({f.sink})" for f in fs))
        lines.append("")

    return "\n".join(lines)


def _render_confirmed(i: int, f) -> list[str]:
    out = [f"#### {i}. `{f.tool}.{f.param}` — {f.sink}", ""]
    out.append(f"- **Verdict channel**: {f.channel}")
    out.append(f"- **Hitting payload**: `{f.payload}`")
    out.append(f"- **How it was detected**: {_detection_method(f)}")
    out.append(f"- **Evidence**: `{f.evidence}`")
    if f.sequence:
        out.append("- **Trigger flow** (reproducible directly by following this sequence):")
        out.append("")
        for step_i, step in enumerate(f.sequence, 1):
            tool = step.get("tool")
            args = step.get("args")
            if step.get("is_error"):
                out.append(f"  {step_i}. `{tool}` {args}  -> call errored (prerequisite step)")
            elif "payload_param" in step:
                out.append(f"  {step_i}. `{tool}` {args}  <- **injection point** (parameter `{step['payload_param']}`)")
            else:
                out.append(f"  {step_i}. `{tool}` {args}")
        out.append("")
    # Replayable PoC: the ordered MCP calls (tools/call shape); replay them in order against the server's MCP
    # endpoint — the last call is the injection point.
    out.append("- **PoC** (replay these MCP `tools/call` requests in order; the last one is the injection point):")
    out.append("")
    out.append("```json")
    out.append(json.dumps(_poc_calls(f), ensure_ascii=False, indent=2))
    out.append("```")
    out.append("")
    return out


def render_summary(servers: list, meta: dict | None = None) -> str:
    """Cross-MCP aggregate overview. `servers` is a list of dicts:
        {"name", "version", "url", "findings": [Finding]}
    Produces: an overview table (one row per MCP) + a flat confirmed table + a flat suspected table, so a whole
    batch can be read at a glance (which MCP, which tool, which class)."""
    meta = meta or {}
    rows = []
    for s in servers:
        fs = s.get("findings") or []
        conf = [f for f in fs if f.status == CONFIRMED and f.sink != DOS]
        susp = [f for f in fs if f.status == SUSPECTED and f.sink != DOS]
        dos = [f for f in fs if f.sink == DOS]
        rows.append({"name": s.get("name") or "?", "version": s.get("version") or "",
                     "url": s.get("url") or "", "conf": conf, "susp": susp, "dos": dos})
    n_vuln = sum(1 for r in rows if r["conf"])
    lines = [
        f"# {APP_NAME} cross-MCP summary",
        "",
        f"- MCP servers: {len(rows)}",
        f"- With confirmed vulnerabilities: {n_vuln}",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Overview",
        "",
        "| MCP | Version | Confirmed | Suspected | DoS | Affected tools |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        tools = sorted({f.tool for f in r["conf"]})
        tool_cell = ", ".join(f"`{t}`" for t in tools) if tools else "—"
        lines.append(f"| {r['name']} | {r['version']} | {len(r['conf'])} | {len(r['susp'])} | "
                     f"{len(r['dos'])} | {tool_cell} |")
    lines.append("")

    # Flat confirmed table across all MCPs
    all_conf = [(r, f) for r in rows for f in r["conf"]]
    lines += ["## Confirmed vulnerabilities (all MCPs)", ""]
    if all_conf:
        lines += ["| MCP | Tool | Parameter | Class | Channel | Payload |", "|---|---|---|---|---|---|"]
        for r, f in all_conf:
            pay = " ".join((f.payload or "").split()).replace("|", "\\|")   # collapse newlines/tabs so the table row stays on one line
            lines.append(f"| {r['name']} | `{f.tool}` | `{f.param}` | {f.sink} | {f.channel} | `{pay}` |")
    else:
        lines.append("(no confirmed vulnerabilities across the scanned MCPs)")
    lines.append("")

    # Flat suspected table across all MCPs
    all_susp = [(r, f) for r in rows for f in r["susp"]]
    if all_susp:
        lines += ["## Suspected (all MCPs, needs manual review)", "",
                  "| MCP | Tool | Parameter | Class | Channel |", "|---|---|---|---|---|"]
        for r, f in all_susp:
            lines.append(f"| {r['name']} | `{f.tool}` | `{f.param}` | {f.sink} | {f.channel} |")
        lines.append("")
    return "\n".join(lines)


def render_dry_run_markdown(catalog, plans: list[dict]) -> str:
    """Report for recon/dry-run: only lists the attack surface and plans, no verdict results."""
    lines = [
        f"# {APP_NAME} attack-surface preview — {catalog.server_name or '?'} {catalog.server_version or ''}".rstrip(),
        "",
        f"- Target: `{catalog.url}`",
        f"- Tools: {len(catalog.tools)}",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "This is a dry-run: only previews the tools/parameters to be tested and the call plans, no payload was sent.",
        "",
        "## Plans",
        "",
    ]
    for p in plans:
        lines.append(f"- `{p.get('tool')}`: {p.get('steps')} steps, {p.get('param_count')} parameters to test"
                     f"{' (unreachable: ' + p.get('note', '') + ')' if not p.get('reachable', True) else ''}")
    lines.append("")
    return "\n".join(lines)
