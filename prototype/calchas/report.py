"""Report rendering: write a scan's Finding list into human-readable Markdown, making each confirmed vulnerability's trigger flow clear."""
from __future__ import annotations

import time

from calchas.__about__ import APP_NAME
from calchas.orchestrator import CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED


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
    if dos:
        lines.append(f"> ⚠ Additionally, **{len(dos)}** tool(s) kept failing the liveness probe after the full battery (suspected DoS/availability), see the section below.")
        lines.append("")

    if confirmed:
        lines.append("## Confirmed vulnerabilities (with trigger flow)")
        lines.append("")
        for i, f in enumerate(confirmed, 1):
            lines += _render_confirmed(i, f)
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
        for f in suspected:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink}) | channel {f.channel} | payload `{f.payload}`"
                         f" | evidence `{f.evidence}`")
        lines.append("")

    if unreached:
        lines.append("## Unreached (payloads were sent, but all rejected/errored by the target tool)")
        lines.append("")
        for f in unreached:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink}): {f.note or 'no detail'}")
        lines.append("")

    if skipped:
        lines.append("## Not tested (tool-side reason, no valid test was sent — does not mean no vulnerability, retest recommended)")
        lines.append("")
        for f in skipped:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink}): {f.note or 'no detail'}")
        lines.append("")

    if clean:
        lines.append("## Likely clean")
        lines.append("")
        for f in clean:
            lines.append(f"- `{f.tool}.{f.param}` ({f.sink})")
        lines.append("")

    return "\n".join(lines)


def _render_confirmed(i: int, f) -> list[str]:
    out = [f"### {i}. `{f.tool}.{f.param}` — {f.sink}", ""]
    out.append(f"- **Verdict channel**: {f.channel}")
    out.append(f"- **Hitting payload**: `{f.payload}`")
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
    return out


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
        reach = "" if not p.get("reachable", True) else ""
        lines.append(f"- `{p.get('tool')}`: {p.get('steps')} steps, {p.get('param_count')} parameters to test"
                     f"{' (unreachable: ' + p.get('note', '') + ')' if not p.get('reachable', True) else ''}")
    lines.append("")
    return "\n".join(lines)
