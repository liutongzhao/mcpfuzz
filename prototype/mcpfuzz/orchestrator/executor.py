"""判定引擎：在一个持久会话上建"发射台"，取基线，再对每个参数发全套探针并五态判定。

见 docs/判定引擎模块设计.md、docs/判定方法论.md。
- 探针调度器：按 rank 发全套探针，CONFIRMED 后对该参数早停。
- 多通道观测：inband（回显/签名，直接取证）/ oob（带外回连，批量 poll）/ timing（时延差，复测）/
  differential（与基线响应差分）/ 错误指纹（被动弱证据）。
- 触达判定：基线调用 + 任一非报错调用 → reached，用于区分"疑似无"与"未触达"。
- 证据分级 → 五态：铁证/可证→确认有；仅弱证→疑似有；触达无命中→疑似无；未触达；未测成。
"""
from __future__ import annotations

import asyncio
import re
import time

from mcpfuzz.driver import call_on
from mcpfuzz.sink.types import AI, SSRF

from .extract import extract_value
from .types import CONFIRMED, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED, Finding

# 参数注入 --version/--help 差分的特征标记（版本号 / usage / getopt 风格的选项报错）。
# 不含 "invalid option"：应用层枚举校验也用这句（"Invalid option: expected one of ..."），会误报。
_AI_MARKERS = re.compile(r"(?i)(usage:|\bv?\d+\.\d+(?:\.\d+)?\b|unknown option|unrecognized option)")

# 程序/工具自身执行后产生的报错（载荷已抵达 sink，只是被程序当非法参数拒了）→ 视为"已触达"。
_PROGRAM_ERR = re.compile(r"(?i)(fatal:|exit code|stderr:|bad revision|invalid object|"
                          r"not something we can merge|does not have any commits|not a git repository|"
                          r"traversal detected|working directory does not exist|already exists)")
# 发到后端程序之前就被输入/schema 校验挡下 → 未触达 sink。
_VALIDATION_ERR = re.compile(r"(?i)(input validation error|invalid arguments for tool|"
                             r"expected (?:number|array|object|string|boolean|one of)|"
                             r"no session working directory|invalid input|invalid enum)")


def _is_program_error(text: str) -> bool:
    """报错是否出自"程序已执行"（已触达 sink）而非"输入/schema 校验"（未触达）。"""
    if not text:
        return False
    if _VALIDATION_ERR.search(text):
        return False   # schema/输入校验优先：还没到后端程序
    return bool(_PROGRAM_ERR.search(text))


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
                   reporter=None, settings=None, liveness=None, read_back=None) -> list:
    """plan.steps[-1] 为目标工具。sink_params: 该工具待测的 ParamSinkPrior 列表。返回 Finding 列表。

    liveness: 可选 async 存活探测（无参返回 bool），用于崩溃/DoS 观测。
    read_back: 可选 async(path)->text 读回器（配套读文件工具），用于 cross_tool canary 判定。
    """
    reporter = reporter or _NullReporter()
    target = plan.steps[-1].tool
    seq_trace = []   # 可复现：前置调用记录

    if not plan.reachable:
        return _skipped_all(target, sink_params, plan.note or "计划判定目标不可达", reporter)

    # 1) 建立发射台：尽力执行前置步骤。一步失败不整体放弃——前置多是"保证资源存在"这类铺垫。
    step_responses = {}
    launchpad_errors = []
    for st in plan.steps[:-1]:
        args, missing = await _resolve_args(st.args, step_responses)
        if missing:
            launchpad_errors.append(f"步骤{st.step}({st.tool})参数{missing}未能取值")
            reporter.emit("launchpad.step", level="debug", tool=st.tool, step=st.step,
                          skipped=True, missing=missing, reason="依赖的前置产出缺席，跳过此步")
            continue
        res = await _safe_call(session, st.tool, args)
        step_responses[st.step] = res["text"]
        seq_trace.append({"tool": st.tool, "args": args, "is_error": res["is_error"]})
        reporter.emit("launchpad.step", level="debug", tool=st.tool, step=st.step,
                      args=res.get("args_sent", args), is_error=res["is_error"],
                      response=res.get("text", ""), error=res.get("exc"))
        if res["is_error"]:
            launchpad_errors.append(f"步骤{st.step}({st.tool})调用报错")
    if launchpad_errors:
        reporter.emit("launchpad.warn", tool=target, reason="；".join(launchpad_errors))

    # 2) 目标工具的发射台实参（最后一步）：只有真的取不到值才判 SKIPPED
    base_args, missing = await _resolve_args(plan.steps[-1].args, step_responses)
    if missing:
        extra = f"（前置: {'；'.join(launchpad_errors)}）" if launchpad_errors else ""
        note = f"目标工具参数 {missing} 未能取值{extra}"
        reporter.emit("launchpad.fail", tool=target, reason=note)
        return _skipped_all(target, sink_params, note, reporter)

    # 3) 基线：用全良性实参调一次目标工具，取响应/时延/是否可达（供差分、时延、触达判定复用）
    base_res, base_latency = await _timed_call(session, target, base_args)
    baseline_text = base_res["text"] or ""
    baseline_ok = not base_res["is_error"]
    reporter.emit("launchpad.ready", level="debug", tool=target, base_args=base_args,
                  baseline_ok=baseline_ok, baseline_latency=round(base_latency, 3))

    # 4) 对每个参数：发全套探针 + 多通道判定 + 五态
    findings = []
    for i, ps in enumerate(sink_params):
        try:
            f = await _attack_param(session, target, base_args, ps, synthesizer, oracle,
                                    seq_trace, poll_window, reporter, settings,
                                    baseline_text, base_latency, baseline_ok, read_back)
        except (Exception, asyncio.CancelledError) as e:
            note = f"连接异常中止（可能是网络抖动打断了正在进行的调用）：{str(e)[:150]}"
            # 存活探测：区分"服务器被打挂(DoS)"与"网络抖动"
            if liveness is not None and not await _is_alive(liveness):
                note += "；事后存活探测失败，服务器可能已崩溃/无响应（疑似 DoS 信号）"
                reporter.emit("server.crash", tool=target, note=note)
            reporter.emit("attack.tool.error", tool=target, error=note)
            for ps2 in sink_params[i:]:
                f2 = Finding(target, ps2.param_path, _repr_class(ps2), SKIPPED, note=note)
                findings.append(f2)
                _emit_finding(reporter, f2)
            return findings
        findings.append(f)
        _emit_finding(reporter, f)

    # 整套打完后一次存活探测（DoS 观测）：有载荷会把服务器打到无响应，即便单次调用只表现为报错
    if liveness is not None and not await _is_alive(liveness):
        reporter.emit("server.crash", tool=target,
                      note="整套测试后存活探测失败，服务器可能已崩溃/无响应（疑似 DoS 信号）")
    return findings


async def _is_alive(liveness) -> bool:
    try:
        return bool(await liveness())
    except Exception:
        return False


def _shaped_args(base_args, prior, value):
    """按参数结构契约摆放载荷：array 型参数把标量载荷包成单元素列表，避免'expected array'被 pre-sink 拒。"""
    v = [value] if getattr(prior, "param_type", None) == "array" else value
    return {**base_args, prior.param_path: v}


def _skipped_all(target, sink_params, note, reporter) -> list:
    out = [Finding(target, ps.param_path, _repr_class(ps), SKIPPED, note=note) for ps in sink_params]
    for f in out:
        reporter.emit("finding.skipped", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    return out


def _emit_finding(reporter, f) -> None:
    if f.status == CONFIRMED:
        reporter.emit("finding.confirmed", tool=f.tool, param=f.param, sink=f.sink, channel=f.channel,
                      payload=f.payload, evidence=f.evidence)
    elif f.status == SUSPECTED:
        reporter.emit("finding.suspected", tool=f.tool, param=f.param, sink=f.sink, channel=f.channel,
                      payload=f.payload, evidence=f.evidence, note=f.note)
    elif f.status == LIKELY_CLEAN:
        reporter.emit("finding.clean", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    elif f.status == UNREACHED:
        reporter.emit("finding.unreached", tool=f.tool, param=f.param, sink=f.sink, note=f.note)
    else:
        reporter.emit("finding.skipped", tool=f.tool, param=f.param, sink=f.sink, note=f.note)


async def _attack_param(session, target, base_args, prior, synthesizer, oracle, seq_trace,
                        poll_window, reporter, settings, baseline_text, baseline_latency,
                        baseline_ok, read_back=None):
    probes = synthesizer.synthesize(prior)
    repr_cls = _repr_class(prior)
    param = prior.param_path
    max_payloads = getattr(settings, "max_payloads", None) if settings else None
    if max_payloads:
        probes = probes[:max_payloads]
    if not probes:
        return Finding(target, param, repr_cls, LIKELY_CLEAN, note="无可用载荷（参数惰性/无启用类别）")

    reporter.emit("attack.param.start", tool=target, param=param, sink=repr_cls, payload_count=len(probes))
    delay = getattr(settings, "delay", 0.0) if settings else 0.0

    oob_pending = []      # [(probe_spec, args)]
    weak = []             # [(vuln_class, probe_spec, evidence)] 弱证据 → 疑似有
    saw_ok = False
    saw_program_error = False   # 载荷抵达后端程序、被当非法参数拒（已触达，用于区分"疑似无 vs 未触达"）
    last_err = ""
    for p in probes:
        args = _shaped_args(base_args, prior, p.value)
        res, latency = await _timed_call(session, target, args)
        text = res["text"] or ""
        reporter.emit("payload.sent", level="debug", tool=target, param=param, channel=p.channel,
                      payload=p.value, sink=p.vuln_class, is_error=res["is_error"],
                      latency=round(latency, 3), args=res.get("args_sent", args),
                      response=text, error=res.get("exc"))
        if res["is_error"]:
            err_text = res.get("exc") or text or ""
            if err_text:
                last_err = err_text
            if _is_program_error(err_text):
                saw_program_error = True
        else:
            saw_ok = True

        # 被动：错误指纹（弱证据），对响应与报错正文都看
        fp = oracle.fingerprint(text, p.vuln_class)
        if fp:
            weak.append((p.vuln_class, p, {"type": "error_fingerprint", "channel": "inband",
                                           "snippet": fp}))

        if p.channel == "inband":
            hit = oracle.observe_inband(p.probe, text)
            if hit:
                # 通用反射感知：命中的签名若本就是载荷子串 → 疑似"输入被原样回显"，非执行/解析。
                # 签名不在载荷里（求值回显 token1681 / 文件特征 root:x:0:0 / 元数据 ami-id）→ 铁证确认；
                # 在载荷里（AI 未知选项、SSRF 把元数据路径词回显）→ 须有对应错误指纹佐证才确认，
                # 否则不算证据（纯回显几乎每个工具都有，计入可达、趋向"疑似无"，不再堆"疑似有"）。
                marker = (hit.evidence or {}).get("marker", "")
                reflected = bool(marker) and marker in p.value
                if not reflected:
                    return _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "inband")
                if oracle.fingerprint(text, p.vuln_class):
                    return _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "inband")
        elif p.channel == "timing":
            if baseline_latency is not None and (latency - baseline_latency) >= p.delay_target * 0.6:
                if await _confirm_timing(session, target, args, p, baseline_latency):
                    ev = {"type": "timing", "baseline": round(baseline_latency, 3),
                          "observed": round(latency, 3), "target": p.delay_target}
                    return _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "timing")
        elif p.channel == "differential":
            ev = _diff_hit(p.vuln_class, baseline_text, text)
            if ev:
                return _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "differential")
        elif p.channel == "cross_tool":
            # 写 canary 的载荷已在上面发出；若有配套读工具，读回 /tmp/{token} 并匹配
            if read_back is not None:
                canary_path = "/tmp/" + p.probe.token
                try:
                    back = await read_back(canary_path)
                except Exception:
                    back = ""
                if back and p.probe.token in back:
                    ev = {"type": "cross_tool", "reader_path": canary_path, "snippet": back[:160]}
                    return _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "cross_tool")
            # 无配套读工具或未读到 → 不计入，继续
        elif p.channel == "oob":
            oob_pending.append((p, args))
        if delay:
            await asyncio.sleep(delay)

    # 批量 poll 带外回连
    if oob_pending:
        hits = oracle.poll([p.probe for p, _ in oob_pending], rounds=poll_window[0], interval=poll_window[1])
        for p, args in oob_pending:
            hit = hits.get(p.probe.token)
            if not hit:
                continue
            if p.vuln_class == SSRF:
                # 信任边界：抓取 URL 本就是功能，回连命中但未越信任边界 → 仅"疑似有"
                weak.append((SSRF, p, {"type": "oob_ssrf", "channel": "oob",
                                       "note": "服务端回连命中，但未证明越过信任边界（内网/元数据），疑似 SSRF",
                                       **(hit.evidence or {})}))
            else:
                return _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "oob")

    # 仅弱证据 → 疑似有
    if weak:
        cls, p, ev = weak[0]
        args = _shaped_args(base_args, prior, p.value)
        return Finding(target, param, cls, SUSPECTED, payload=p.value, channel=ev.get("channel", p.channel),
                       evidence=ev,
                       sequence=seq_trace + [{"tool": target, "args": args, "payload_param": param}],
                       note="仅弱证据（错误指纹 / 回连未越边界），需人工复核")

    # 无任何命中：区分"疑似无"（已触达 sink）与"未触达"。
    # 已触达 = 有正常返回 / 基线可达 / 或载荷已抵达后端程序被其当非法参数拒（程序级报错）。
    if saw_ok or baseline_ok or saw_program_error:
        return Finding(target, param, repr_cls, LIKELY_CLEAN, note="")
    note = "所有载荷均被输入/schema 校验挡下且基线不可达，可能未触达 sink"
    if last_err:
        note += f"；样例错误：{str(last_err)[:120]}"
    return Finding(target, param, repr_cls, UNREACHED, note=note)


async def _confirm_timing(session, target, args, p, baseline, rounds=2) -> bool:
    """复测去抖：再跑 rounds 次，取中位的额外时延，仍 >= 目标*0.6 才算确认。"""
    adds = []
    for _ in range(rounds):
        res, lat = await _timed_call(session, target, args)
        adds.append(lat - baseline)
    adds.sort()
    return adds[len(adds) // 2] >= p.delay_target * 0.6


def _diff_hit(vuln_class, baseline_text, text):
    """差分：参数注入的 --version/--help 若让响应出现版本/用法/getopt 报错特征（基线没有）→ 命中。"""
    if vuln_class != AI or not text or text == baseline_text:
        return None
    if _VALIDATION_ERR.search(text):
        return None   # 应用层输入/枚举校验（非 argv 注入），不算
    m = _AI_MARKERS.search(text)
    if m and (not baseline_text or m.group(0).lower() not in baseline_text.lower()):
        i = m.start()
        return {"type": "differential", "marker": m.group(0),
                "snippet": text[max(0, i - 20): i + 60]}
    return None


def _confirmed(target, param, cls, p, evidence, seq_trace, final_args, channel):
    return Finding(target, param, cls, CONFIRMED, payload=p.value, channel=channel,
                   evidence=evidence,
                   sequence=seq_trace + [{"tool": target, "args": final_args, "payload_param": param}])


def _repr_class(prior):
    """代表类别：权重最高的启用类别（供 SKIPPED/UNREACHED 等无命中结论标注）。"""
    cls = prior.ranked_classes()
    return cls[0] if cls else "unknown"


async def _timed_call(session, tool, args):
    t0 = time.monotonic()
    res = await _safe_call(session, tool, args)
    return res, time.monotonic() - t0


async def _safe_call(session, tool, args) -> dict:
    try:
        return await call_on(session, tool, args)
    except Exception as e:
        return {"text": "", "is_error": True, "raw": None, "exc": repr(e), "args_sent": args}
