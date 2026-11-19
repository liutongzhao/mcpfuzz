"""Scan orchestration: drive the six modules through one detection, send the process to the reporter, and land products in an independent run directory.

Single-target scan_target() is the minimal unit; the batch (the CLI's scan --batch/--all) loops over multiple
targets outside it, each target getting an independent run directory, not affecting or interrupting each other.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from pathlib import Path

from calchas.__about__ import APP_NAME
from calchas.driver import fetch_catalog_sync
from calchas.oracle import Oracle
from calchas.orchestrator import (CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED,
                                   Orchestrator)
from calchas.report import render_markdown
from calchas.sink import SinkInferencer
from calchas.targetcfg import resolve_target


class GatewayNotReady(RuntimeError):
    """When going via the gateway, the target backend failed to deploy (never reached tools>0 / could not connect).
    Batch mode judges "deploy failure" on this, and retries one round after the whole batch finishes (see
    cli.main.cmd_scan) — deploy failures are often transient (slow download, gateway-connection blip)."""


def slugify(name: str) -> str:
    return re.sub(r"[^\w.-]", "_", name or "server")


def make_run_dir(out_dir: Path, run_name: str | None, server_hint: str) -> Path:
    """Build an independent run directory; also maintain <out_dir>/latest pointing back to it, for a quick look at the most recent result."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    name = run_name or f"{ts}__{slugify(server_hint)}"
    run_dir = Path(out_dir) / name
    run_dir.mkdir(parents=True, exist_ok=True)
    latest = Path(out_dir) / "latest"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(run_dir.name)
    except OSError:
        pass   # the symlink may fail on some filesystems/permissions, which does not affect this run itself
    return run_dir


def _param_sink_dict(p) -> dict:
    d = {"tool": p.tool, "param_path": p.param_path, "param_type": p.param_type,
         "inert": p.inert, "inert_reason": p.inert_reason,
         "classes": list(p.classes),
         "operations": list(getattr(p, "operations", [])),
         "provenance": p.provenance}
    if getattr(p, "declared_domain", ""):
        d["declared_domain"] = p.declared_domain
        d["domain_evidence"] = p.domain_evidence
    return d


def scan_target(target_arg: str, name: str | None, run_dir: Path, settings, reporter,
                extra_headers: dict | None = None):
    """Run one target's full detection. run_dir is pre-built by the caller (the CLI) — so the caller can attach
    the run.log / events.jsonl persistence sinks to the reporter before the run.start event is emitted.
    Returns findings_list. settings: config.Settings. reporter: cli.events.Reporter.
    """
    url, headers = resolve_target(target_arg, name)
    if extra_headers:
        headers = {**(headers or {}), **extra_headers}

    reporter.emit("run.start", target=target_arg, url=url, run_dir=str(run_dir))
    t0 = time.time()

    # Gateway integration (optional, does not affect the detection logic): enable only during detection + cold-start adaptation
    gw, gw_server = _gateway_setup(settings, url, reporter)
    # The "add -> scan -> delete" mode is only enabled when a launch-command table is given (only large-scale whole-ecosystem batches); dataset scanning does not give one and uses the enable/disable below
    launch_map = _load_launch_map(settings.gateway_launch_map) if gw else None
    adhoc = launch_map is not None
    try:
        if adhoc:
            entry = launch_map.get(gw_server) or {}
            launch = entry.get("launch") or []
            if not launch:
                raise GatewayNotReady(f"gateway backend {gw_server} is not in the launch-command table, cannot register")
            try:
                gw.add(gw_server, launch[0], launch[1:])
                reporter.emit("gateway.add", server=gw_server)
            except Exception as e:
                raise GatewayNotReady(f"failed to register gateway backend {gw_server}: {str(e)[:200]}") from e
        # Activation: under gateway_lifecycle "enable only during detection" — enable spawns the stdio backend on
        # the spot (disconnected -> connected), disabled in the finally to free resources; outside that mode it keeps the old reload reset semantics (gateway_reset).
        elif gw and settings.gateway_lifecycle:
            try:
                gw.enable(gw_server)
                reporter.emit("gateway.enable", server=gw_server)
            except Exception as e:
                reporter.emit("gateway.error", error=f"failed to enable backend {gw_server}: {str(e)[:200]}")
        elif gw and settings.gateway_reset in ("before", "both"):
            _gateway_reset(gw, gw_server, "before", reporter)
        if gw:
            # After connecting, wait for the backend to truly be ready (connected and tools>0), otherwise the
            # gateway answers with its own identity + an empty tool list, taking "0 tools" as a successful scan.
            # The budget is tied to the cold-start timeout, capped at 180s.
            budget = max(60.0, min(settings.gateway_idle_ms / 1000.0, 180.0))
            ready, ntools = gw.wait_ready(gw_server, timeout=budget)
            reporter.emit("gateway.wait", server=gw_server, ready=ready, tools=ntools)

        # Cold-start budget: via the gateway, the first call (catalog) triggers the backend to spawn, so give the read a generous timeout
        cat_timeout = settings.timeout
        if settings.gateway_base:
            cat_timeout = max(settings.timeout, settings.gateway_idle_ms / 1000.0)

        try:
            catalog = fetch_catalog_sync(url, headers, retries=settings.retries, timeout=cat_timeout)
        except Exception as e:
            reporter.emit("connect.fail", error=str(e)[:300])
            if gw:   # unable to connect via the gateway = the backend did not deploy
                raise GatewayNotReady(f"gateway backend {gw_server} connection failed: {str(e)[:200]}") from e
            raise

        # Via the gateway, 0 tools almost certainly means the backend is not ready (the gateway answers with its own identity), do not silently produce an empty report
        if gw and len(catalog.tools) == 0:
            reporter.emit("gateway.error",
                          error=f"backend {gw_server} is not ready (tool count is 0, may still be cold-starting / not connected), this scan is aborted; please retry later")
            raise GatewayNotReady(f"gateway backend {gw_server} is not ready: tools=0")

        reporter.emit("connect.ok", server_name=catalog.server_name, server_version=catalog.server_version,
                      protocol_version=catalog.protocol_version, tool_count=len(catalog.tools))
        (run_dir / "catalog.json").write_text(json.dumps(catalog.to_dict(), ensure_ascii=False, indent=2))

        sink_cache = (run_dir / ".sink_cache") if settings.use_cache else None
        inferencer = SinkInferencer(use_llm=settings.llm_sink, cache_dir=sink_cache,
                                    workers=settings.llm_workers, reporter=reporter)
        param_sinks = inferencer.infer(catalog)
        (run_dir / "sinks.json").write_text(
            json.dumps([_param_sink_dict(p) for p in param_sinks], ensure_ascii=False, indent=2))

        if settings.stage1_only:
            hot = sum(1 for p in param_sinks if not p.inert and p.classes)
            reporter.emit("run.end", duration=time.time() - t0, confirmed=0, suspected=0,
                          clean=0, unreached=0, skipped=0, dos=0, stage1_only=True,
                          param_count=len(param_sinks), hot_count=hot)
            return []   # scan_target contract: return findings (none at stage 1)

        only_tools = set(settings.only_tools) if settings.only_tools else None
        exclude_tools = set(settings.exclude_tools) if settings.exclude_tools else set()
        only_sinks = set(settings.only_sinks) if settings.only_sinks else None
        if exclude_tools or only_sinks:
            param_sinks = [p for p in param_sinks
                          if p.tool not in exclude_tools
                          and (only_sinks is None or any(c in only_sinks for c in p.classes))]

        oracle = Oracle(settings.oob_callback, settings.oob_query)
        # The Orchestrator internally creates a .plan_cache/ subdirectory under cache_dir; just pass run_dir itself
        orch = Orchestrator(url, headers, catalog, oracle, cache_dir=run_dir if settings.use_cache else None,
                            reporter=reporter, settings=settings)
        try:
            findings = orch.run(param_sinks, only_tools=only_tools, dry_run=settings.dry_run)
        finally:
            orch.close()   # release the agent's persistent event loop

        # Availability/DoS findings are a whole-tool observation, not counted in the per-param five-state (otherwise it pollutes parameter coverage)
        dos = sum(f.sink == DOS for f in findings)
        param_findings = [f for f in findings if f.sink != DOS]
        confirmed = sum(f.status == CONFIRMED for f in param_findings)
        suspected = sum(f.status == SUSPECTED for f in param_findings)
        clean = sum(f.status == LIKELY_CLEAN for f in param_findings)
        unreached = sum(f.status == UNREACHED for f in param_findings)
        skipped = sum(f.status == SKIPPED for f in param_findings)

        # findings.json is written in full (incl. DoS availability findings), for machine reading/tracking
        (run_dir / "findings.json").write_text(
            json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))

        if not settings.dry_run:
            report_path = run_dir / "report.md"
            report_path.write_text(render_markdown(catalog, findings))
            reporter.emit("report.saved", path=str(report_path))

        reporter.emit("run.end", duration=time.time() - t0, confirmed=confirmed, suspected=suspected,
                      clean=clean, unreached=unreached, skipped=skipped, dos=dos,
                      total=len(param_findings), dry_run=settings.dry_run)
        return findings
    finally:
        # Finish (executed even if detection errors midway):
        #   add -> scan -> delete mode: delete this temporarily-registered backend (ending its process), so the gateway always holds only the current one;
        #   dataset mode: only disable (end the process, the backend stays in the gateway), never delete; outside lifecycle, keep the after-reload behavior
        if adhoc:
            try:
                gw.delete(gw_server)
                reporter.emit("gateway.delete", server=gw_server)
            except Exception as e:
                reporter.emit("gateway.error", error=f"failed to delete backend {gw_server}: {str(e)[:200]}")
        elif gw and settings.gateway_lifecycle:
            try:
                gw.disable(gw_server)
                reporter.emit("gateway.disable", server=gw_server)
            except Exception as e:
                reporter.emit("gateway.error", error=f"failed to disable backend {gw_server}: {str(e)[:200]}")
        elif gw and settings.gateway_reset in ("after", "both"):
            _gateway_reset(gw, gw_server, "after", reporter)


_LAUNCH_MAPS: dict[str, dict] = {}


def _load_launch_map(path: str | None) -> dict | None:
    """Read the "backend name -> {launch: [command, args...]}" table (i.e. the namemap.json produced by the batch unit's provision); read once per process."""
    if not path:
        return None
    if path not in _LAUNCH_MAPS:
        _LAUNCH_MAPS[path] = json.loads(Path(path).read_text(encoding="utf-8"))
    return _LAUNCH_MAPS[path]


def _gateway_setup(settings, url, reporter):
    """Build a GatewayClient per settings and locate the backend name; return (None, None) if not configured or it cannot be located."""
    if not settings.gateway_base:
        return None, None
    from calchas.gateway import GatewayClient, server_name_from_url
    server = settings.gateway_server or server_name_from_url(url)
    if not server:
        reporter.emit("gateway.error", error=f"cannot parse the backend name from the URL, and --gateway-server was not given: {url}")
        return None, None
    try:
        gw = GatewayClient(settings.gateway_base, token=settings.gateway_token,
                           user=settings.gateway_user, password=settings.gateway_password)
    except Exception as e:
        reporter.emit("gateway.error", error=f"failed to connect to the gateway: {str(e)[:200]}")
        return None, None
    return gw, server


def _gateway_reset(gw, server, when, reporter):
    """Reset the backend via reload (stdio = kill and respawn = clean state). A failure does not interrupt detection, only records an event."""
    try:
        gw.reload(server)
        time.sleep(1.5)   # let the gateway register "backend disconnected / reconnecting"; the actual readiness wait is handled by wait_ready
        reporter.emit("gateway.reset", server=server, when=when)
    except Exception as e:
        reporter.emit("gateway.error", error=f"failed to reset backend {server}: {str(e)[:200]}")


def read_batch_file(path: str) -> list[str]:
    """Batch list: one target per line (a URL or an mcpServers config-file path), lines starting with # and blank lines ignored."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def write_batch_summary(out_dir: Path, results: list[dict]) -> Path:
    """results: [{"target":..,"run_dir":..,"confirmed":..,"clean":..,"unreached":..,"error":..}]"""
    lines = [f"# {APP_NAME} batch scan summary", "",
            f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- Targets: {len(results)}", "",
            "| Target | Confirmed | Suspected | Likely clean | Unreached | Not tested | Products |",
            "|---|---|---|---|---|---|---|"]
    for r in results:
        tries = r.get("attempt", 1)
        if r.get("error"):
            kind = "deploy failure" if r.get("deploy_failed") else "failure"
            extra = f" (tried {tries} times)" if tries > 1 else ""
            lines.append(f"| `{r['target']}` | — | — | — | — | — | {kind}{extra}: {r['error'][:100]} |")
        else:
            extra = f" (succeeded on deploy attempt {tries})" if tries > 1 else ""
            lines.append(f"| `{r['target']}` | {r['confirmed']} | {r.get('suspected', 0)} | {r['clean']} | "
                         f"{r['unreached']} | {r.get('skipped', 0)} | `{r['run_dir']}`{extra} |")
    text = "\n".join(lines) + "\n"
    path = Path(out_dir) / "batch_summary.md"
    path.write_text(text)
    (Path(out_dir) / "batch_summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    return path
