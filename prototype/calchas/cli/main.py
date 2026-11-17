"""Calchas command-line entry: subcommand parsing, config merging, assembly of presentation and log persistence.

Subcommands:
  scan      full detection (single target / batch), has side effects (sends payloads)
  recon     dry-run: only connect + infer sinks + produce the plan, sends no payload
  report    re-render an existing findings.json into Markdown
  selftest  verdict / payload-synthesis self-check (wraps the existing scaffold scripts)
"""
from __future__ import annotations

import argparse
import json
import os
import time
import sys
from dataclasses import asdict, fields
from pathlib import Path

from calchas.__about__ import CLI_NAME
from calchas.config import Settings, build_settings
from calchas.report import render_markdown
from calchas.llm_failover import AllModelsUnavailable
from calchas.run import (GatewayNotReady, make_run_dir, read_batch_file, scan_target, slugify,
                         write_batch_summary)
from calchas.targetcfg import resolve_target

from .console import build_console
from .events import JsonlSink, LogFileSink, Reporter

PROTOTYPE_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def _add_common_scan_args(p: argparse.ArgumentParser) -> None:
    g_scope = p.add_argument_group("detection scope")
    g_scope.add_argument("--tool", dest="only_tools", action="append", metavar="NAME",
                        help="test only this tool (repeatable)")
    g_scope.add_argument("--exclude-tool", dest="exclude_tools", action="append", metavar="NAME",
                        help="exclude this tool (repeatable)")
    g_scope.add_argument("--sink", dest="only_sinks", action="append", metavar="TYPE",
                        help="test only this sink type (repeatable, e.g. command_injection)")
    g_scope.add_argument("--max-payloads", type=int, default=None, metavar="N",
                        help="send at most N payloads per parameter")

    g_llm = p.add_argument_group("LLM")
    g_llm.add_argument("--no-llm-sink", dest="llm_sink", action="store_false", default=None,
                       help="sink inference uses rules only (LLM off)")
    g_llm.add_argument("--no-agent", dest="sequence_agent", action="store_false", default=None,
                       help="disable the sequence-construction agent, fall back to one-shot planning")
    g_llm.add_argument("--agent-rounds", dest="agent_rounds", type=int, default=None, metavar="N",
                       help="max repair rounds for the sequence-construction agent (default 6)")
    g_llm.add_argument("--no-llm-plan", dest="llm_plan", action="store_false", default=None,
                       help="orchestration uses the fallback plan only (length 1, schema-filled values, LLM off)")
    g_llm.add_argument("--llm-workers", type=int, default=None, metavar="N",
                       help="sink-inference concurrency (default 6)")
    g_llm.add_argument("--no-cache", dest="use_cache", action="store_false", default=None,
                       help="do not read/write the sink/plan cache (for ablation/re-runs)")

    g_net = p.add_argument_group("verdict / network")
    g_net.add_argument("--oob-callback", default=None, metavar="URL", help="OOB callback base")
    g_net.add_argument("--oob-query", default=None, metavar="URL", help="OOB hit-query address")
    g_net.add_argument("--poll-rounds", type=int, default=None, metavar="N", help="OOB collection rounds")
    g_net.add_argument("--poll-interval", type=float, default=None, metavar="SEC", help="OOB collection interval")
    g_net.add_argument("--timeout", type=float, default=None, metavar="SEC", help="per-call timeout")
    g_net.add_argument("--tool-timeout", dest="tool_timeout", type=float, default=None, metavar="SEC",
                       help="per-tool total-time watchdog: if a tool's detection exceeds this many seconds, abandon it, record not-tested, move to the next"
                            " (default 900=15 minutes; <=0 to disable)")
    g_net.add_argument("--retries", type=int, default=None, metavar="N", help="connection/call retries")
    g_net.add_argument("--delay", type=float, default=None, metavar="SEC", help="interval between payloads (rate limit)")

    g_out = p.add_argument_group("output / logging")
    g_out.add_argument("-o", "--out-dir", default=None, metavar="DIR", help="product root directory (default runs/)")
    g_out.add_argument("--run-name", default=None, metavar="NAME", help="name of this run (default timestamp__server)")
    g_out.add_argument("--format", choices=["auto", "rich", "plain", "json"], default=None,
                       help="console presentation (default auto: rich on a TTY, else plain)")
    g_out.add_argument("-v", "--verbose", action="count", default=None,
                       help="more verbose (-vv prints every payload)")
    g_out.add_argument("-q", "--quiet", action="store_true", default=None, help="only key conclusions")
    g_out.add_argument("--config", default=None, metavar="FILE", help="TOML config file")

    g_safe = p.add_argument_group("safety / ethics")
    g_safe.add_argument("--yes", dest="assume_yes", action="store_true", default=None,
                       help="skip the confirmation before launching a side-effecting scan (required for batch/CI)")

    g_gw = p.add_argument_group("gateway (detect via mcphub, optional)")
    g_gw.add_argument("--gateway", dest="gateway_base", default=None, metavar="URL",
                      help="mcphub base, e.g. http://host:3000; given to enable gateway integration")
    g_gw.add_argument("--gateway-token", dest="gateway_token", default=None, metavar="TOKEN",
                      help="gateway admin token (x-auth-token), alternative to --gateway-password")
    g_gw.add_argument("--gateway-user", dest="gateway_user", default=None, metavar="USER",
                      help="gateway admin username (default admin)")
    g_gw.add_argument("--gateway-password", dest="gateway_password", default=None, metavar="PWD",
                      help="gateway admin password (logs in to exchange for a token)")
    g_gw.add_argument("--gateway-server", dest="gateway_server", default=None, metavar="NAME",
                      help="this target's backend name in the gateway (default parsed from the /mcp/{server} URL)")
    g_gw.add_argument("--gateway-reset", dest="gateway_reset",
                      choices=["off", "before", "after", "both"], default=None,
                      help="reset the backend to a clean state via reload before/after the scan (default off)")
    g_gw.add_argument("--gateway-idle-ms", dest="gateway_idle_ms", type=int, default=None, metavar="MS",
                      help="gateway idle-shutdown timeout (on-demand start), used as the first-connect cold-start budget (default 300000)")
    g_gw.add_argument("--gateway-keep-online", dest="gateway_lifecycle", action="store_false", default=None,
                      help="do not disable the backend after detection (default: enable it only during detection, disable to free resources afterwards)")
    g_gw.add_argument("--gateway-launch-map", dest="gateway_launch_map", default=None, metavar="FILE",
                      help="[only for large-scale whole-ecosystem batches] JSON of backend-name -> launch command (with a launch field). If given, each target "
                           "is temporarily registered to the gateway before its scan and deleted after; if not given (e.g. dataset scanning), it only enable/disables pre-registered backends, not delete")
    g_gw.add_argument("--after-target-cmd", dest="after_target_cmd", default=None, metavar="CMD",
                      help="a local command run after each target is scanned (backend already disabled); run at the safe moment when the process has stopped, "
                           "so it does not interrupt a cold start. Typical use: clear the gateway container cache to avoid filling the disk, e.g. "
                           "\"docker exec mcphub sh -c 'rm -rf /root/.npm/_cacache /app/.uv_cache /root/.cache/uv'\"")
    g_gw.add_argument("--after-target-cmd-timeout", dest="after_target_cmd_timeout", type=float,
                      default=None, metavar="SEC", help="timeout in seconds for the above cleanup command (default 120)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=CLI_NAME, description="Black-box injection vulnerability detection for MCP servers")
    sub = p.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="full detection (connect -> infer sinks -> attack orchestration -> verdict -> report)")
    p_scan.add_argument("targets", nargs="*", help="target URL or mcpServers config file (one or more)")
    p_scan.add_argument("--name", default=None, help="server name selected from the config file (default the first)")
    p_scan.add_argument("--all", action="store_true", help="test all servers in the config file")
    p_scan.add_argument("--batch", default=None, metavar="FILE", help="batch list file (one target per line)")
    p_scan.add_argument("--batch-name", default=None, metavar="NAME",
                        help="batch name: all results go under runs/<NAME>/ (default flat in runs/)")
    p_scan.add_argument("--header", action="append", default=[], metavar="'K: V'",
                        help="append an HTTP header, e.g. for auth (repeatable)")
    p_scan.add_argument("--fail-fast", action="store_true", help="in batch mode, abort immediately on a failure (default skip and continue)")
    p_scan.add_argument("--resume", action="store_true",
                        help="resume: skip targets already completed in this batch's runs/<NAME>/_done.jsonl (restart after a crash/interruption and continue directly)")
    p_scan.add_argument("--deploy-retry-rounds", dest="deploy_retry_rounds", type=int, default=1, metavar="N",
                        help="deploy-failure retry rounds: after the whole batch finishes, retry deploy-failed (backend won't start / can't connect) targets N more rounds (default 1; 0 to disable)")
    p_scan.add_argument("--dry-run", action="store_true", default=None,
                        help="equivalent to recon: only preview the attack surface, send no payload")
    _add_common_scan_args(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_recon = sub.add_parser("recon", help="recon: connect + list tools + infer sinks + produce the plan, send no payload")
    p_recon.add_argument("targets", nargs="*", help="target URL or mcpServers config file (one or more)")
    p_recon.add_argument("--name", default=None, help="server name selected from the config file (default the first)")
    p_recon.add_argument("--all", action="store_true", help="test all servers in the config file")
    p_recon.add_argument("--batch", default=None, metavar="FILE", help="batch list file (one target per line)")
    p_recon.add_argument("--batch-name", default=None, metavar="NAME",
                         help="batch name: all results go under runs/<NAME>/ (default flat in runs/)")
    p_recon.add_argument("--header", action="append", default=[], metavar="'K: V'")
    p_recon.add_argument("--fail-fast", action="store_true")
    _add_common_scan_args(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_report = sub.add_parser("report", help="re-render an existing findings.json into Markdown")
    p_report.add_argument("findings_path", help="findings.json path (usually runs/<run>/findings.json)")
    p_report.add_argument("catalog_path", help="the same run's catalog.json path")
    p_report.add_argument("-o", "--out", default=None, metavar="FILE", help="output path (default print to terminal)")
    p_report.set_defaults(func=cmd_report)

    p_self = sub.add_parser("selftest", help="verdict / payload-synthesis self-check")
    p_self.add_argument("which", nargs="?", choices=["oracle", "payload"], default=None,
                        help="run only this one (default both)")
    p_self.set_defaults(func=cmd_selftest)

    return p


def _parse_headers(raw: list[str]) -> dict:
    out = {}
    for item in raw:
        if ":" not in item:
            sys.exit(f"--header format should be 'K: V', got: {item!r}")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _resolve_targets(args) -> list[tuple[str, str | None]]:
    """Merge positional args + --batch + --all, returning [(target_arg, name_or_None), ...]."""
    raw = list(args.targets or [])
    if args.batch:
        raw += read_batch_file(args.batch)
    if not raw:
        sys.exit("specify at least one target, or provide a list file with --batch")

    pairs: list[tuple[str, str | None]] = []
    for t in raw:
        if args.all and t.endswith(".json") and Path(t).exists():
            cfg = json.loads(Path(t).read_text())
            servers = cfg.get("mcpServers", cfg)
            for key in servers:
                pairs.append((t, key))
        else:
            pairs.append((t, args.name))
    return pairs


# ---------------------------------------------------------------------------
# subcommand implementations
# ---------------------------------------------------------------------------

def _confirm_or_exit(settings: Settings, n_targets: int) -> None:
    if settings.dry_run or settings.assume_yes:
        return
    msg = (f"about to launch a side-effecting scan against {n_targets} target(s) (command/path/SSRF payloads, incl. out-of-band callbacks and file writes)."
          f" Continue? [y/N] ")
    if not sys.stdin.isatty():
        sys.exit("a non-interactive environment must pass --yes explicitly to launch a scan (or use --dry-run to only preview).")
    if input(msg).strip().lower() not in ("y", "yes"):
        sys.exit("cancelled.")


def _run_after_target_cmd(settings, label: str) -> None:
    """Run a user-specified cleanup command once after each target finishes (backend already disabled).

    Placed at the safe moment when "the backend process has stopped": it does not interrupt any cold-start
    install, and keeps the disk peak down to a single package. A failure only warns and does not affect the
    detection flow (cleanup is an ops aid and should not interrupt a batch run)."""
    cmd = getattr(settings, "after_target_cmd", None)
    if not cmd:
        return
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=getattr(settings, "after_target_cmd_timeout", 120.0) or 120.0)
        if r.returncode != 0:
            print(f"  [cleanup cmd] {label}: exit code {r.returncode}; {(r.stderr or r.stdout).strip()[:200]}")
    except subprocess.TimeoutExpired:
        print(f"  [cleanup cmd] {label}: timed out (skipped, does not affect detection)")
    except Exception as e:
        print(f"  [cleanup cmd] {label}: execution failed {str(e)[:150]} (skipped)")


def _run_one(target_arg, name, settings, console, extra_headers, dry_run_override=None):
    """Build the run directory, attach log sinks, run one target; returns (run_dir, findings), re-raising exceptions."""
    run_dir = make_run_dir(Path(settings.out_dir), settings.run_name, name or target_arg)
    reporter = Reporter()
    reporter.add_sink(console.handle)
    log_sink = LogFileSink(run_dir / "run.log")
    jsonl_sink = JsonlSink(run_dir / "events.jsonl")
    reporter.add_sink(log_sink)
    reporter.add_sink(jsonl_sink)

    local_settings = settings
    if dry_run_override is not None:
        import copy
        local_settings = copy.copy(settings)
        local_settings.dry_run = dry_run_override

    try:
        findings = scan_target(target_arg, name, run_dir, local_settings, reporter,
                               extra_headers=extra_headers)
        return run_dir, findings
    finally:
        log_sink.close()
        jsonl_sink.close()


def _target_key(target_arg: str, name: str | None) -> str:
    """The stable key identifying a target in the resume ledger: URL (or config-file path) + optional server name."""
    return f"{target_arg}||{name or ''}"


def _done_ledger_path(out_dir: str) -> Path:
    return Path(out_dir) / "_done.jsonl"


def _load_done_ledger(out_dir: str):
    """Read the resume ledger, returning (done_keys:set, latest:dict[key->result]). The same target may have
    several records (first-round deploy failure + retry); the **last** one wins; the dict keeps first-seen order.
    A missing file / a half-written line both degrade safely."""
    path = _done_ledger_path(out_dir)
    done, latest = set(), {}
    if not path.exists():
        return done, latest
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)   # tolerate a half-written line on a crash: skip the line on a parse error
        except json.JSONDecodeError:
            continue
        key = rec.get("_key")
        if not key:
            continue
        done.add(key)
        if rec.get("result"):
            latest[key] = rec["result"]
    return done, latest


def _append_done_ledger(out_dir: str, key: str, result: dict) -> None:
    """Append one line per completed target and flush+fsync immediately — so the completed part of the ledger is not lost on a crash."""
    path = _done_ledger_path(out_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    rec = {"_key": key, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "result": result}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def cmd_scan(args) -> int:
    settings = build_settings(args)
    batch_name = getattr(args, "batch_name", None)
    if batch_name:
        # batch name: all results (per-target subdir + batch_summary + latest + resume ledger) go under runs/<batch name>/
        settings.out_dir = str(Path(settings.out_dir) / slugify(batch_name))
    targets = _resolve_targets(args)
    extra_headers = _parse_headers(args.header)

    # resume: load completed targets from the ledger, filter them out, scan the rest; latest keeps the final summary complete
    resume = bool(getattr(args, "resume", False))
    done_keys, latest = (_load_done_ledger(settings.out_dir) if resume else (set(), {}))
    pending = [(t, n) for (t, n) in targets if _target_key(t, n) not in done_keys]
    skipped = len(targets) - len(pending)

    _confirm_or_exit(settings, len(pending))
    if resume and skipped:
        print(f"resume: {skipped} already completed in the ledger, skipped; {len(pending)} remaining this run.")

    from calchas.orchestrator import (CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED)
    console = build_console(settings.format, settings.verbose or 0, bool(settings.quiet))

    def scan_one(target_arg, name, attempt):
        """Scan one target and write the ledger. Returns False to stop the whole batch (pause / fail-fast)."""
        label = name or target_arg
        key = _target_key(target_arg, name)
        console.start(label)
        paused = None   # set to a pause reason to not record this target in the ledger and stop the whole batch
        try:
            run_dir, findings = _run_one(target_arg, name, settings, console, extra_headers)
            # exclude DoS/availability findings from the per-param five-state counts, matching report.md / run.end
            params = [f for f in findings if f.sink != DOS]
            result = {"target": label, "run_dir": str(run_dir),
                      "confirmed": sum(f.status == CONFIRMED for f in params),
                      "suspected": sum(f.status == SUSPECTED for f in params),
                      "clean": sum(f.status == LIKELY_CLEAN for f in params),
                      "unreached": sum(f.status == UNREACHED for f in params),
                      "skipped": sum(f.status == SKIPPED for f in params)}
        except AllModelsUnavailable as e:
            # all LLMs unavailable: **pause** the whole batch (do not record the current target, resume it with --resume after recovery).
            paused = str(e)[:160]
        except GatewayNotReady as e:
            result = {"target": label, "error": str(e)[:300], "deploy_failed": True}
        except Exception as e:
            result = {"target": label, "error": str(e)[:300]}
        finally:
            console.stop()
            # the backend was already disabled in scan_target's finally; cleanup now does not interrupt any cold start
            _run_after_target_cmd(settings, label)
        if paused is not None:
            print(f"\n⏸  all LLMs unavailable, detection paused ({paused}).")
            print(f"   the current target {label} was not recorded in the ledger; after the models recover, resume from here with --resume.")
            return False
        # which deploy attempt (1=first round, 2+=retry after the whole batch): used to distinguish "succeeded first try / succeeded on retry / still failed on retry"
        result["attempt"] = attempt
        # the ledger is written only after the finish (incl. cleanup): a restart-resume will not miss a target's cleanup. A crash before this -> that target re-runs once (idempotent, acceptable)
        latest[key] = result
        _append_done_ledger(settings.out_dir, key, result)
        if "error" in result and args.fail_fast:
            print(f"fail-fast: {label} failed, aborting. Completed ones are in the ledger, resume with --resume.")
            return False
        return True

    go_on = all(scan_one(t, n, 1) for (t, n) in pending)   # all() stops on the first False

    # Deploy-failure retry: after the first round finishes, retry the "deploy-failed" targets one more round
    # (spaced well apart from the first round, by which time a transient slow download / gateway-connection blip
    # has mostly passed). Only still-failing ones count as a true deploy failure.
    # Selection is based on each target's **latest** ledger record, so --resume can continue the retry after a mid-retry crash.
    retry_rounds = max(0, int(getattr(args, "deploy_retry_rounds", 1) or 0))
    for rnd in range(1, retry_rounds + 1):
        if not go_on:
            break
        todo = [(t, n) for (t, n) in targets
                if (r := latest.get(_target_key(t, n)))
                and r.get("deploy_failed") and r.get("attempt", 1) == rnd]
        if not todo:
            break
        print(f"\n↻ deploy-failure retry (round {rnd}): {len(todo)} targets")
        go_on = all(scan_one(t, n, rnd + 1) for (t, n) in todo)

    results = [latest[k] for k in (_target_key(t, n) for (t, n) in targets) if k in latest]
    if len(targets) > 1:
        summary_path = write_batch_summary(Path(settings.out_dir), results)
        print(f"\nbatch summary saved: {summary_path}")
    return 0


def cmd_recon(args) -> int:
    args.dry_run = True
    args.assume_yes = True
    return cmd_scan(args)


def cmd_report(args) -> int:
    from calchas.catalog import Target, Tool, Param
    from calchas.orchestrator.types import Finding

    cat_raw = json.loads(Path(args.catalog_path).read_text())
    tools = [Tool(t["name"], t.get("description"), t.get("raw_input_schema", {}),
                 [Param(**p) for p in t.get("params", [])]) for t in cat_raw.get("tools", [])]
    catalog = Target(cat_raw["url"], cat_raw.get("server_name"), cat_raw.get("server_version"),
                     cat_raw.get("protocol_version"), tools)

    findings_raw = json.loads(Path(args.findings_path).read_text())
    findings = [Finding(**f) for f in findings_raw]

    md = render_markdown(catalog, findings)
    if args.out:
        Path(args.out).write_text(md)
        print(f"saved: {args.out}")
    else:
        print(md)
    return 0


def cmd_selftest(args) -> int:
    import subprocess
    scripts = {"oracle": "selftest_oracle.py", "payload": "selftest_payload.py"}
    todo = [args.which] if args.which else list(scripts)
    rc = 0
    for name in todo:
        path = PROTOTYPE_ROOT / scripts[name]
        print(f"=== selftest: {name} ({path.name}) ===")
        r = subprocess.run([sys.executable, str(path)], cwd=str(PROTOTYPE_ROOT))
        rc = rc or r.returncode
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
