"""执行器：在一个持久会话上，按计划建立"发射台"，再对每个 sink 参数循环发载荷并三态判定。"""
from __future__ import annotations

import asyncio

from mcpfuzz.driver import call_on

from .extract import extract_value
from .types import CONFIRMED, LIKELY_CLEAN, UNREACHED, Finding


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
        return _unreached_all(target, sink_params, plan.note, reporter)

    # 1) 建立发射台：执行前置步骤（除最后一步），逐跳取值+验证
    step_responses = {}
    for st in plan.steps[:-1]:
        args, missing = await _resolve_args(st.args, step_responses)
        if missing:
            note = f"前置步骤 {st.step}({st.tool}) 参数 {missing} 未能取值"
            reporter.emit("launchpad.fail", tool=target, reason=note)
            return _unreached_all(target, sink_params, note, reporter)
        res = await _safe_call(session, st.tool, args)
        step_responses[st.step] = res["text"]
        seq_trace.append({"tool": st.tool, "args": args, "is_error": res["is_error"]})
        if res["is_error"]:
            note = f"前置步骤 {st.step}({st.tool}) 调用报错"
            reporter.emit("launchpad.fail", tool=target, reason=note)
            return _unreached_all(target, sink_params, note, reporter)

    # 2) 目标工具的"发射台"实参（最后一步）
    base_args, missing = await _resolve_args(plan.steps[-1].args, step_responses)
    if missing:
        note = f"目标工具参数 {missing} 未能取值"
        reporter.emit("launchpad.fail", tool=target, reason=note)
        return _unreached_all(target, sink_params, note, reporter)

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
                f2 = Finding(target, ps2.param_path, _sink_of(ps2), UNREACHED, note=note)
                findings.append(f2)
                _emit_finding(reporter, f2)
            break
        findings.append(f)
        _emit_finding(reporter, f)
    return findings


def _unreached_all(target, sink_params, note, reporter) -> list:
    out = [Finding(target, ps.param_path, _sink_of(ps), UNREACHED, note=note) for ps in sink_params]
    for f in out:
        reporter.emit("finding.unreached", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    return out


def _emit_finding(reporter, f) -> None:
    if f.status == CONFIRMED:
        reporter.emit("finding.confirmed", tool=f.tool, param=f.param, sink=f.sink, channel=f.channel,
                      payload=f.payload, evidence=f.evidence)
    elif f.status == LIKELY_CLEAN:
        reporter.emit("finding.clean", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    else:
        reporter.emit("finding.unreached", tool=f.tool, param=f.param, sink=f.sink, note=f.note)


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
    for p in payloads:
        args = {**base_args, param: p.value}
        res = await _safe_call(session, target, args)
        reporter.emit("payload.sent", level="debug", tool=target, param=param, channel=p.channel,
                      payload=p.value, is_error=res["is_error"])
        if res["is_error"]:
            saw_err = True
        else:
            saw_ok = True
        if p.channel == "reflection":
            hit = oracle.observe_response(p.probe, res["text"])
            if hit:
                return _confirmed(target, param, sink, p, hit, seq_trace, args)
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
                return _confirmed(target, param, sink, p, hit, seq_trace, args)

    status = LIKELY_CLEAN if saw_ok else UNREACHED
    return Finding(target, param, sink, status,
                   note="" if saw_ok else "所有载荷调用均报错，可能未触达 sink")


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
        return {"text": "", "is_error": True, "raw": None, "exc": str(e)[:150]}
