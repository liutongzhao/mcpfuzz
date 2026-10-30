"""执行器：在一个持久会话上，按计划建立"发射台"，再对每个 sink 参数循环发载荷并三态判定。"""
from __future__ import annotations

import asyncio

from mcpfuzz.driver import call_on

from .extract import extract_value
from .types import CONFIRMED, LIKELY_CLEAN, SKIPPED, UNREACHED, Finding


class _NullReporter:
    def emit(self, *a, **k):
        pass


async def _resolve_args(arg_specs: dict, step_responses: dict) -> tuple[dict, list]:
    """把 {param: ArgSpec} 解析成具体实参。返回 (args, 未解析的参数名列表)。"""
    args, missing = {}, []
    for param, spec in arg_specs.items():
        if not isinstance(spec, dict):
            continue
        if spec.get("src") == "from_step":
            resp = step_responses.get(spec.get("step"))
            val = extract_value(resp or "", spec.get("extract", "")) if resp is not None else None
            if val is None:
                missing.append(param)
            else:
                args[param] = val
        else:
            args[param] = spec.get("value")
    return args, missing


async def run_tool(session, plan, sink_params, synthesizer, oracle, poll_window=(3, 2.0),
                   reporter=None, settings=None) -> list:
    """plan.steps[-1] 为目标工具。sink_params: 该工具待测的 ParamSink 列表。返回 Finding 列表。

    reporter: cli.events.Reporter，不传则静默。settings: config.Settings（max_payloads/delay）。
    """
    reporter = reporter or _NullReporter()
    target = plan.steps[-1].tool
    seq_trace = []   # 可复现：前置调用记录

    if not plan.reachable:
        return _skipped_all(target, sink_params, plan.note or "计划判定目标不可达", reporter)

    # 1) 建立发射台：尽力执行前置步骤。某一步取值失败或调用报错时，不再整体放弃——
    #    前置步骤多是"保证仓库/资源存在"这类铺垫，一步失败不代表目标工具不可注入。
    #    （实测：planner 选 git_set_working_dir 作前置、该步报错，曾把一个本已确认的
    #     参数注入误判为"未触达"。）只有当目标工具的实参确实依赖失败步骤的产出、
    #    无法取值时，才在下一步判为 SKIPPED。
    step_responses = {}
    launchpad_errors = []
    for st in plan.steps[:-1]:
        args, missing = await _resolve_args(st.args, step_responses)
        if missing:
            launchpad_errors.append(f"步骤{st.step}({st.tool})参数{missing}未能取值")
            reporter.emit("launchpad.step", level="debug", tool=st.tool, step=st.step,
                          skipped=True, missing=missing,
                          reason="依赖的前置产出缺席，跳过此步")
            continue   # 跳过此步，其产出缺席；若目标依赖它，会在取值阶段暴露
        res = await _safe_call(session, st.tool, args)
        step_responses[st.step] = res["text"]
        seq_trace.append({"tool": st.tool, "args": args, "is_error": res["is_error"]})
        # 前置步骤逐步落盘：真正发出的嵌套实参 + 是否报错 + 响应/错误正文。
        # debug 级：默认不进终端，仅 -vv 显示；run.log / events.jsonl 始终全量记录。
        reporter.emit("launchpad.step", level="debug", tool=st.tool, step=st.step,
                      args=res.get("args_sent", args), is_error=res["is_error"],
                      response=res.get("text", ""), error=res.get("exc"))
        if res["is_error"]:
            launchpad_errors.append(f"步骤{st.step}({st.tool})调用报错")
    if launchpad_errors:
        reporter.emit("launchpad.warn", tool=target, reason="；".join(launchpad_errors))

    # 2) 目标工具的"发射台"实参（最后一步）：只有真的取不到值才判 SKIPPED
    base_args, missing = await _resolve_args(plan.steps[-1].args, step_responses)
    if missing:
        extra = f"（前置: {'；'.join(launchpad_errors)}）" if launchpad_errors else ""
        note = f"目标工具参数 {missing} 未能取值{extra}"
        reporter.emit("launchpad.fail", tool=target, reason=note)
        return _skipped_all(target, sink_params, note, reporter)
    reporter.emit("launchpad.ready", level="debug", tool=target, base_args=base_args)

    # 3) 对每个 sink 参数：循环发载荷 + 三态判定 + 早停
    findings = []
    for i, ps in enumerate(sink_params):
        try:
            f = await _attack_param(session, target, base_args, ps, synthesizer, oracle,
                                    seq_trace, poll_window, reporter, settings)
        except (Exception, asyncio.CancelledError) as e:
            # 远程网络抖动时，MCP SDK 内部任务组偶发用 CancelledError 打断正在进行的调用
            # （不是 KeyboardInterrupt/真实取消）。这条会话大概率已不可信：把这个参数和该工具
            # 剩余未测参数都标 unreached 并记录原因，不再用它发更多请求；之前已测完的参数的
            # 真实结论保留，不因这一次连接异常被整体清零（这是修之前版本的一个静默吞错 bug）。
            note = f"连接异常中止（可能是网络抖动打断了正在进行的调用）：{str(e)[:150]}"
            reporter.emit("attack.tool.error", tool=target, error=note)
            for ps2 in sink_params[i:]:
                f2 = Finding(target, ps2.param_path, _sink_of(ps2), SKIPPED, note=note)
                findings.append(f2)
                _emit_finding(reporter, f2)
            break
        findings.append(f)
        _emit_finding(reporter, f)
    return findings


def _skipped_all(target, sink_params, note, reporter) -> list:
    out = [Finding(target, ps.param_path, _sink_of(ps), SKIPPED, note=note) for ps in sink_params]
    for f in out:
        reporter.emit("finding.skipped", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    return out


def _emit_finding(reporter, f) -> None:
    if f.status == CONFIRMED:
        reporter.emit("finding.confirmed", tool=f.tool, param=f.param, sink=f.sink, channel=f.channel,
                      payload=f.payload, evidence=f.evidence)
    elif f.status == LIKELY_CLEAN:
        reporter.emit("finding.clean", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    elif f.status == UNREACHED:
        reporter.emit("finding.unreached", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    else:
        reporter.emit("finding.skipped", tool=f.tool, param=f.param, sink=f.sink, note=f.note)


async def _attack_param(session, target, base_args, param_sink, synthesizer, oracle, seq_trace,
                        poll_window, reporter, settings):
    payloads = synthesizer.synthesize(param_sink)
    sink = _sink_of(param_sink)
    param = param_sink.param_path
    max_payloads = getattr(settings, "max_payloads", None) if settings else None
    if max_payloads:
        payloads = payloads[:max_payloads]
    if not payloads:
        return Finding(target, param, sink, LIKELY_CLEAN, note="无该 sink 的载荷")

    reporter.emit("attack.param.start", tool=target, param=param, sink=sink, payload_count=len(payloads))
    delay = getattr(settings, "delay", 0.0) if settings else 0.0

    oob_pending = []    # [(payload, probe)]
    saw_ok = saw_err = False
    last_err = ""       # 代表性错误正文：供"未触达"结论附带原因，不再是一句笼统的话
    for p in payloads:
        args = {**base_args, param: p.value}
        res = await _safe_call(session, target, args)
        # 每条载荷全量落盘：真正发出的嵌套实参 + 是否报错 + 响应/错误正文 + sink 族类。
        # debug 级：终端默认不显示（-vv 才显示且只显示精简行），文件 sink 始终记全。
        reporter.emit("payload.sent", level="debug", tool=target, param=param, channel=p.channel,
                      payload=p.value, sink=p.sink, is_error=res["is_error"],
                      args=res.get("args_sent", args),
                      response=res.get("text", ""), error=res.get("exc"))
        if res["is_error"]:
            saw_err = True
            err_text = res.get("exc") or res.get("text") or ""
            if err_text:
                last_err = err_text
        else:
            saw_ok = True
        if p.channel == "reflection":
            hit = oracle.observe_response(p.probe, res["text"])
            if hit:
                # 确认时用命中载荷“自身”的 sink 族类，而非该参数的首要 sink 标签——
                # 否则一条命令注入载荷打中、却被报成参数首标的 path_traversal（类型标错）。
                return _confirmed(target, param, p.sink, p, hit, seq_trace, args)
        else:  # oob：先全部发出，稍后一次性 poll
            oob_pending.append(p)
        if delay:
            await asyncio.sleep(delay)

    if oob_pending:
        hits = oracle.poll([p.probe for p in oob_pending], rounds=poll_window[0], interval=poll_window[1])
        for p in oob_pending:                 # 按 rank 顺序取最早命中
            hit = hits.get(p.probe.token)
            if hit:
                args = {**base_args, param: p.value}
                return _confirmed(target, param, p.sink, p, hit, seq_trace, args)

    status = LIKELY_CLEAN if saw_ok else UNREACHED
    if saw_ok:
        note = ""
    else:
        note = "所有载荷调用均报错，可能未触达 sink"
        if last_err:
            # 摘要只带精简错误（终端/报告够用即可）；完整响应/错误正文已随
            # payload.sent 全量落到 run.log / events.jsonl，排查看文件。
            note += f"；样例错误：{str(last_err)[:120]}"
    return Finding(target, param, sink, status, note=note)


def _confirmed(target, param, sink, payload, hit, seq_trace, final_args):
    return Finding(target, param, sink, CONFIRMED, payload=payload.value, channel=payload.channel,
                   evidence=hit.evidence,
                   sequence=seq_trace + [{"tool": target, "args": final_args, "payload_param": param}])


def _sink_of(param_sink):
    return param_sink.sinks[0].type if param_sink.sinks else "unknown"


async def _safe_call(session, tool, args) -> dict:
    try:
        return await call_on(session, tool, args)
    except Exception as e:
        # 调用抛异常（网络/协议/序列化等），此时未能发到线上：args_sent 回落为原始实参。
        return {"text": "", "is_error": True, "raw": None, "exc": repr(e), "args_sent": args}
