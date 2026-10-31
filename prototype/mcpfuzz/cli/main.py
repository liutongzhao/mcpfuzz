"""mcpfuzz 命令行入口：子命令解析、配置合并、呈现与日志落盘的装配。

子命令：
  scan      完整检测（单目标 / 批量），有副作用（发载荷）
  recon     dry-run：只连接+推 sink+出计划，不发任何载荷
  report    把已有 findings.json 重渲染成 Markdown
  selftest  判定器/载荷合成自检（收编现有脚手架脚本）
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, fields
from pathlib import Path

from mcpfuzz.config import Settings, build_settings
from mcpfuzz.report import render_markdown
from mcpfuzz.run import make_run_dir, read_batch_file, scan_target, write_batch_summary
from mcpfuzz.targetcfg import resolve_target

from .console import build_console
from .events import JsonlSink, LogFileSink, Reporter

PROTOTYPE_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------

def _add_common_scan_args(p: argparse.ArgumentParser) -> None:
    g_scope = p.add_argument_group("检测范围")
    g_scope.add_argument("--tool", dest="only_tools", action="append", metavar="NAME",
                        help="只测这个工具（可重复）")
    g_scope.add_argument("--exclude-tool", dest="exclude_tools", action="append", metavar="NAME",
                        help="排除这个工具（可重复）")
    g_scope.add_argument("--sink", dest="only_sinks", action="append", metavar="TYPE",
                        help="只测这个 sink 类型（可重复，如 command_injection）")
    g_scope.add_argument("--max-payloads", type=int, default=None, metavar="N",
                        help="每个参数最多发 N 条载荷")

    g_llm = p.add_argument_group("大模型")
    g_llm.add_argument("--no-llm-sink", dest="llm_sink", action="store_false", default=None,
                       help="sink 推断只用规则（关大模型）")
    g_llm.add_argument("--no-agent", dest="sequence_agent", action="store_false", default=None,
                       help="关闭序列构建智能体，回退一次性规划")
    g_llm.add_argument("--agent-rounds", dest="agent_rounds", type=int, default=None, metavar="N",
                       help="序列构建智能体最大修复轮次（默认 4）")
    g_llm.add_argument("--no-llm-plan", dest="llm_plan", action="store_false", default=None,
                       help="编排只用兜底计划（长度 1，schema 填值，关大模型）")
    g_llm.add_argument("--llm-workers", type=int, default=None, metavar="N",
                       help="sink 推断并发数（默认 6）")
    g_llm.add_argument("--no-cache", dest="use_cache", action="store_false", default=None,
                       help="不读写 sink/plan 缓存（消融/重测用）")

    g_net = p.add_argument_group("判定 / 网络")
    g_net.add_argument("--oob-callback", default=None, metavar="URL", help="OOB 回连基址")
    g_net.add_argument("--oob-query", default=None, metavar="URL", help="OOB 命中查询地址")
    g_net.add_argument("--poll-rounds", type=int, default=None, metavar="N", help="OOB 回收轮数")
    g_net.add_argument("--poll-interval", type=float, default=None, metavar="SEC", help="OOB 回收间隔")
    g_net.add_argument("--timeout", type=float, default=None, metavar="SEC", help="单次调用超时")
    g_net.add_argument("--retries", type=int, default=None, metavar="N", help="连接/调用重试次数")
    g_net.add_argument("--delay", type=float, default=None, metavar="SEC", help="每条载荷之间的间隔（限速）")

    g_out = p.add_argument_group("输出 / 日志")
    g_out.add_argument("-o", "--out-dir", default=None, metavar="DIR", help="产物根目录（默认 runs/）")
    g_out.add_argument("--run-name", default=None, metavar="NAME", help="本次运行名（默认 时间戳__server）")
    g_out.add_argument("--format", choices=["auto", "rich", "plain", "json"], default=None,
                       help="控制台呈现方式（默认 auto：TTY 用 rich，否则 plain）")
    g_out.add_argument("-v", "--verbose", action="count", default=None,
                       help="更详细（-vv 打印每条载荷）")
    g_out.add_argument("-q", "--quiet", action="store_true", default=None, help="只出关键结论")
    g_out.add_argument("--config", default=None, metavar="FILE", help="TOML 配置文件")

    g_safe = p.add_argument_group("安全 / 伦理")
    g_safe.add_argument("--yes", dest="assume_yes", action="store_true", default=None,
                       help="跳过发起副作用检测前的确认（批量/CI 必备）")

    g_gw = p.add_argument_group("网关（经 mcphub 检测，可选）")
    g_gw.add_argument("--gateway", dest="gateway_base", default=None, metavar="URL",
                      help="mcphub 基址，如 http://host:3000；给了才启用网关集成")
    g_gw.add_argument("--gateway-token", dest="gateway_token", default=None, metavar="TOKEN",
                      help="网关管理 token（x-auth-token），与 --gateway-password 二选一")
    g_gw.add_argument("--gateway-user", dest="gateway_user", default=None, metavar="USER",
                      help="网关管理员用户名（默认 admin）")
    g_gw.add_argument("--gateway-password", dest="gateway_password", default=None, metavar="PWD",
                      help="网关管理员密码（登录换 token）")
    g_gw.add_argument("--gateway-server", dest="gateway_server", default=None, metavar="NAME",
                      help="该目标在网关里的后端名（默认从 /mcp/{server} URL 解析）")
    g_gw.add_argument("--gateway-reset", dest="gateway_reset",
                      choices=["off", "before", "after", "both"], default=None,
                      help="扫描前/后用 reload 重置后端到干净态（默认 off）")
    g_gw.add_argument("--gateway-idle-ms", dest="gateway_idle_ms", type=int, default=None, metavar="MS",
                      help="网关空闲关闭超时（按需启动），用作首连冷启动预算（默认 300000）")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcpfuzz", description="MCP 服务器黑盒注入漏洞检测")
    sub = p.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="完整检测（连接→推 sink→攻击编排→判定→报告）")
    p_scan.add_argument("targets", nargs="*", help="目标 URL 或 mcpServers 配置文件（可多个）")
    p_scan.add_argument("--name", default=None, help="配置文件里选用的 server 名（默认取第一个）")
    p_scan.add_argument("--all", action="store_true", help="配置文件里的所有 server 全测")
    p_scan.add_argument("--batch", default=None, metavar="FILE", help="批量清单文件（每行一个目标）")
    p_scan.add_argument("--header", action="append", default=[], metavar="'K: V'",
                        help="追加 HTTP 头，如鉴权（可重复）")
    p_scan.add_argument("--fail-fast", action="store_true", help="批量时遇到失败立即中断（默认跳过继续）")
    p_scan.add_argument("--dry-run", action="store_true", default=None,
                        help="等价于 recon：只预览攻击面，不发载荷")
    _add_common_scan_args(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_recon = sub.add_parser("recon", help="侦察：连接+列工具+推 sink+出计划，不发任何载荷")
    p_recon.add_argument("targets", nargs="*", help="目标 URL 或 mcpServers 配置文件（可多个）")
    p_recon.add_argument("--name", default=None, help="配置文件里选用的 server 名（默认取第一个）")
    p_recon.add_argument("--all", action="store_true", help="配置文件里的所有 server 全测")
    p_recon.add_argument("--batch", default=None, metavar="FILE", help="批量清单文件（每行一个目标）")
    p_recon.add_argument("--header", action="append", default=[], metavar="'K: V'")
    p_recon.add_argument("--fail-fast", action="store_true")
    _add_common_scan_args(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_report = sub.add_parser("report", help="把已有 findings.json 重渲染成 Markdown")
    p_report.add_argument("findings_path", help="findings.json 路径（通常是 runs/<run>/findings.json）")
    p_report.add_argument("catalog_path", help="同一次运行的 catalog.json 路径")
    p_report.add_argument("-o", "--out", default=None, metavar="FILE", help="输出路径（默认打印到终端）")
    p_report.set_defaults(func=cmd_report)

    p_self = sub.add_parser("selftest", help="判定器 / 载荷合成自检")
    p_self.add_argument("which", nargs="?", choices=["oracle", "payload"], default=None,
                        help="只跑这一个（默认两个都跑）")
    p_self.set_defaults(func=cmd_selftest)

    return p


def _parse_headers(raw: list[str]) -> dict:
    out = {}
    for item in raw:
        if ":" not in item:
            sys.exit(f"--header 格式应为 'K: V'，收到：{item!r}")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _resolve_targets(args) -> list[tuple[str, str | None]]:
    """合并位置参数 + --batch + --all，返回 [(target_arg, name_or_None), ...]。"""
    raw = list(args.targets or [])
    if args.batch:
        raw += read_batch_file(args.batch)
    if not raw:
        sys.exit("至少指定一个目标，或用 --batch 提供清单文件")

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
# 子命令实现
# ---------------------------------------------------------------------------

def _confirm_or_exit(settings: Settings, n_targets: int) -> None:
    if settings.dry_run or settings.assume_yes:
        return
    msg = (f"即将对 {n_targets} 个目标发起带副作用的检测（命令/路径/SSRF 载荷，含带外回连与文件写入）。"
          f" 继续吗？[y/N] ")
    if not sys.stdin.isatty():
        sys.exit("非交互环境需显式传 --yes 才能发起检测（或用 --dry-run 仅预览）。")
    if input(msg).strip().lower() not in ("y", "yes"):
        sys.exit("已取消。")


def _run_one(target_arg, name, settings, console, extra_headers, dry_run_override=None):
    """建运行目录、挂日志 sink、跑一个目标；返回 (run_dir, findings)，异常原样抛出。"""
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


def cmd_scan(args) -> int:
    settings = build_settings(args)
    targets = _resolve_targets(args)
    extra_headers = _parse_headers(args.header)
    _confirm_or_exit(settings, len(targets))

    console = build_console(settings.format, settings.verbose or 0, bool(settings.quiet))
    results = []
    for target_arg, name in targets:
        label = name or target_arg
        console.start(label)
        try:
            run_dir, findings = _run_one(target_arg, name, settings, console, extra_headers)
            from mcpfuzz.orchestrator import (CONFIRMED, LIKELY_CLEAN, SKIPPED, SUSPECTED,
                                              UNREACHED)
            results.append({"target": label, "run_dir": str(run_dir),
                           "confirmed": sum(f.status == CONFIRMED for f in findings),
                           "suspected": sum(f.status == SUSPECTED for f in findings),
                           "clean": sum(f.status == LIKELY_CLEAN for f in findings),
                           "unreached": sum(f.status == UNREACHED for f in findings),
                           "skipped": sum(f.status == SKIPPED for f in findings)})
        except Exception as e:
            results.append({"target": label, "error": str(e)[:300]})
            if args.fail_fast:
                console.stop()
                raise
        finally:
            console.stop()

    if len(targets) > 1:
        summary_path = write_batch_summary(Path(settings.out_dir), results)
        print(f"\n批量汇总已保存：{summary_path}")
    return 0


def cmd_recon(args) -> int:
    args.dry_run = True
    args.assume_yes = True
    return cmd_scan(args)


def cmd_report(args) -> int:
    from mcpfuzz.catalog import Target, Tool, Param
    from mcpfuzz.orchestrator.types import Finding

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
        print(f"已保存：{args.out}")
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
        print("\n已中断。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
