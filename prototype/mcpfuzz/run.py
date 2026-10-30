"""扫描编排：驱动六个模块跑完一次检测，把过程发给 reporter，产物落到独立的运行目录。

单目标 scan_target() 是最小单元；批量（CLI 的 scan --batch/--all）在外层对多个目标循环调用它，
每个目标独立一个运行目录，互不影响、互不中断。
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from pathlib import Path

from mcpfuzz.driver import fetch_catalog_sync
from mcpfuzz.oracle import Oracle
from mcpfuzz.orchestrator import CONFIRMED, LIKELY_CLEAN, SKIPPED, UNREACHED, Orchestrator
from mcpfuzz.report import render_markdown
from mcpfuzz.sink import SinkInferencer
from mcpfuzz.targetcfg import resolve_target


def slugify(name: str) -> str:
    return re.sub(r"[^\w.-]", "_", name or "server")


def make_run_dir(out_dir: Path, run_name: str | None, server_hint: str) -> Path:
    """建一个独立运行目录；同时维护 <out_dir>/latest 指回它，方便随手看最近一次结果。"""
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
        pass   # 符号链接在部分文件系统/权限下可能失败，不影响本次运行本身
    return run_dir


def _param_sink_dict(p) -> dict:
    return {"tool": p.tool, "param_path": p.param_path, "param_type": p.param_type,
            "sinks": [vars(s) for s in p.sinks]}


def scan_target(target_arg: str, name: str | None, run_dir: Path, settings, reporter,
                extra_headers: dict | None = None):
    """跑完一个目标的完整检测。run_dir 由调用方（CLI）先建好——这样调用方可以在
    run.start 事件发出之前，把 run.log / events.jsonl 的落盘 sink 挂到 reporter 上。
    返回 findings_list。settings: config.Settings。reporter: cli.events.Reporter。
    """
    url, headers = resolve_target(target_arg, name)
    if extra_headers:
        headers = {**(headers or {}), **extra_headers}

    reporter.emit("run.start", target=target_arg, url=url, run_dir=str(run_dir))
    t0 = time.time()

    # 网关集成（可选，不影响检测逻辑）：适配 reload 重置与按需启动
    gw, gw_server = _gateway_setup(settings, url, reporter)
    if gw and settings.gateway_reset in ("before", "both"):
        _gateway_reset(gw, gw_server, "before", reporter)

    # 冷启动预算：经网关按需启动时，首个调用(catalog)会触发后端拉起，给足读超时
    cat_timeout = settings.timeout
    if settings.gateway_base:
        cat_timeout = max(settings.timeout, settings.gateway_idle_ms / 1000.0)

    try:
        catalog = fetch_catalog_sync(url, headers, retries=settings.retries, timeout=cat_timeout)
    except Exception as e:
        reporter.emit("connect.fail", error=str(e)[:300])
        raise

    reporter.emit("connect.ok", server_name=catalog.server_name, server_version=catalog.server_version,
                  protocol_version=catalog.protocol_version, tool_count=len(catalog.tools))
    (run_dir / "catalog.json").write_text(json.dumps(catalog.to_dict(), ensure_ascii=False, indent=2))

    sink_cache = (run_dir / ".sink_cache") if settings.use_cache else None
    inferencer = SinkInferencer(use_llm=settings.llm_sink, cache_dir=sink_cache,
                                workers=settings.llm_workers, reporter=reporter)
    param_sinks = inferencer.infer(catalog)
    (run_dir / "sinks.json").write_text(
        json.dumps([_param_sink_dict(p) for p in param_sinks], ensure_ascii=False, indent=2))

    only_tools = set(settings.only_tools) if settings.only_tools else None
    exclude_tools = set(settings.exclude_tools) if settings.exclude_tools else set()
    only_sinks = set(settings.only_sinks) if settings.only_sinks else None
    if exclude_tools or only_sinks:
        param_sinks = [p for p in param_sinks
                      if p.tool not in exclude_tools
                      and (only_sinks is None or any(s.type in only_sinks for s in p.sinks))]

    oracle = Oracle(settings.oob_callback, settings.oob_query)
    # Orchestrator 内部会在 cache_dir 下建 .plan_cache/ 子目录；传 run_dir 本身即可
    orch = Orchestrator(url, headers, catalog, oracle, cache_dir=run_dir if settings.use_cache else None,
                        reporter=reporter, settings=settings)
    findings = orch.run(param_sinks, only_tools=only_tools, dry_run=settings.dry_run)

    confirmed = sum(f.status == CONFIRMED for f in findings)
    clean = sum(f.status == LIKELY_CLEAN for f in findings)
    unreached = sum(f.status == UNREACHED for f in findings)
    skipped = sum(f.status == SKIPPED for f in findings)

    (run_dir / "findings.json").write_text(
        json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))

    if not settings.dry_run:
        report_path = run_dir / "report.md"
        report_path.write_text(render_markdown(catalog, findings))
        reporter.emit("report.saved", path=str(report_path))

    reporter.emit("run.end", duration=time.time() - t0, confirmed=confirmed, clean=clean,
                  unreached=unreached, skipped=skipped, total=len(findings), dry_run=settings.dry_run)

    if gw and settings.gateway_reset in ("after", "both"):
        _gateway_reset(gw, gw_server, "after", reporter)
    return findings


def _gateway_setup(settings, url, reporter):
    """按 settings 建 GatewayClient 并定位后端名；未配置或无法定位则返回 (None, None)。"""
    if not settings.gateway_base:
        return None, None
    from mcpfuzz.gateway import GatewayClient, server_name_from_url
    server = settings.gateway_server or server_name_from_url(url)
    if not server:
        reporter.emit("gateway.error", error=f"无法从 URL 解析后端名，且未给 --gateway-server：{url}")
        return None, None
    try:
        gw = GatewayClient(settings.gateway_base, token=settings.gateway_token,
                           user=settings.gateway_user, password=settings.gateway_password)
    except Exception as e:
        reporter.emit("gateway.error", error=f"连接网关失败：{str(e)[:200]}")
        return None, None
    return gw, server


def _gateway_reset(gw, server, when, reporter):
    """用 reload 重置后端（stdio=杀进程重拉=干净态）。失败不中断检测，只记事件。"""
    try:
        gw.reload(server)
        time.sleep(2.0)   # 给网关拆解旧进程的时间；按需启动的后端会在下次调用时重拉
        reporter.emit("gateway.reset", server=server, when=when)
    except Exception as e:
        reporter.emit("gateway.error", error=f"重置后端 {server} 失败：{str(e)[:200]}")


def read_batch_file(path: str) -> list[str]:
    """批量清单：每行一个目标（URL 或 mcpServers 配置文件路径），# 开头和空行忽略。"""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def write_batch_summary(out_dir: Path, results: list[dict]) -> Path:
    """results: [{"target":..,"run_dir":..,"confirmed":..,"clean":..,"unreached":..,"error":..}]"""
    lines = ["# MCPFuzz 批量扫描汇总", "",
            f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- 目标数：{len(results)}", "",
            "| 目标 | 确认漏洞 | 疑似无 | 未触达 | 未测成 | 产物 |", "|---|---|---|---|---|---|"]
    for r in results:
        if r.get("error"):
            lines.append(f"| `{r['target']}` | — | — | — | — | 失败：{r['error'][:100]} |")
        else:
            lines.append(f"| `{r['target']}` | {r['confirmed']} | {r['clean']} | {r['unreached']} | "
                         f"{r.get('skipped', 0)} | `{r['run_dir']}` |")
    text = "\n".join(lines) + "\n"
    path = Path(out_dir) / "batch_summary.md"
    path.write_text(text)
    (Path(out_dir) / "batch_summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    return path
