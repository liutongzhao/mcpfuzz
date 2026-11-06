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
from mcpfuzz.sink.types import AI, CODE, PT, SSRF

from .extract import extract_value
from .types import CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED, Finding

# 参数注入 --version/--help 差分的特征标记（版本号 / usage / getopt 风格的选项报错）。
# 不含 "invalid option"：应用层枚举校验也用这句（"Invalid option: expected one of ..."），会误报。
_AI_MARKERS = re.compile(r"(?i)(usage:|\bv?\d+\.\d+(?:\.\d+)?\b|unknown option|unrecognized option)")

# 发到后端程序之前就被 schema/协议级输入校验挡下 → 未触达 sink。这些是 MCP 框架 / JSON-Schema
# 通用报错（zod / JSON-RPC -32602 等），与具体服务器无关——不枚举任何某个程序的报错原文。
_VALIDATION_ERR = re.compile(r"(?i)(input validation error|invalid arguments for tool|"
                             r"expected (?:number|array|object|string|boolean|one of)|"
                             r"invalid input|invalid enum|required property|-32602)")


def _reached_via_error(res: dict) -> bool:
    """工具**业务层**返回了错误（有响应正文、非传输异常），且不是 schema/协议级输入校验错 →
    载荷已抵达后端程序、只是被当非法参数拒了（已触达 sink）。通用判定，不含任何服务器特定词。
    """
    text = res.get("text") or ""
    if not text or res.get("exc"):      # 传输异常 / 无响应 → 没触达
        return False
    return not _VALIDATION_ERR.search(text)


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
                                    baseline_text, base_latency, read_back)
        except (Exception, asyncio.CancelledError) as e:
            note = f"连接异常中止（可能是网络抖动打断了正在进行的调用）：{str(e)[:150]}"
            # 存活探测去抖：区分"服务器被打挂(DoS)"与"网络抖动/本地会话损坏"
            crashed = False
            if liveness is not None:
                alive, detail = await _liveness_recheck(liveness)
                if not alive:
                    crashed = True
                    note += f"；事后连续存活探测失败，服务器可能已崩溃/无响应（疑似 DoS）；最后原因：{detail}"
                    reporter.emit("server.crash", tool=target, note=note)
            reporter.emit("attack.tool.error", tool=target, error=note)
            for ps2 in sink_params[i:]:
                f2 = Finding(target, ps2.param_path, _repr_class(ps2), SKIPPED, note=note)
                findings.append(f2)
                _emit_finding(reporter, f2)
            if crashed:   # 崩溃落成一条可用性发现，进 findings.json / 报告
                findings.append(Finding(target, "(存活探测)", DOS, SUSPECTED, note=note))
            return findings
        findings.append(f)
        _emit_finding(reporter, f)

    # 整套打完后存活探测（DoS 观测）：有载荷会把服务器打到无响应，即便单次调用只表现为报错。
    # K 次复测去抖，真失败才判崩溃，并落成一条可用性发现进 findings（从而进 findings.json/报告）。
    if liveness is not None:
        alive, detail = await _liveness_recheck(liveness)
        if not alive:
            note = f"整套测试后连续存活探测失败，服务器可能已崩溃/无响应（疑似 DoS）；最后原因：{detail}"
            reporter.emit("server.crash", tool=target, note=note)
            findings.append(Finding(target, "(存活探测)", DOS, SUSPECTED, note=note))
    return findings


async def _liveness_recheck(liveness, rounds: int = 3, interval: float = 1.0):
    """崩溃判定去抖（docs/判定方法论.md：崩溃需 K 次重复，抵消网络抖动）：连续 rounds 次
    心跳都失败才判崩溃；任一次成功即判存活。返回 (alive, detail)，detail 为最后一次失败原因
    （真实异常，不吞——真 DoS 与误报据此区分）。"""
    detail = ""
    for i in range(rounds):
        try:
            if await liveness():
                return True, ""
            detail = detail or "心跳返回否定"
        except Exception as e:
            detail = f"{type(e).__name__}: {str(e)[:150]}"
        if i < rounds - 1:
            await asyncio.sleep(interval)
    return False, detail


def _shaped_args(base_args, prior, value, placement="value"):
    """按参数声明的约束/结构摆放载荷，避免被后端程序之前的输入校验直接挡下。返回参数字典；
    若该参数被声明约束锁死、这条载荷无法构造成合法骨架 → 返回 **None**（上层跳过该载荷）。

    - **带格式约束的字符串**（pattern/format/minLength）：走约束感知的"合法骨架+注入"
      （valuegen.inject_value）——如 `^proj-` → `proj-<载荷>`；uuid/锚死 pattern → None（如实无法注入）。
    - array → [value]；object → {<key>: value}（载荷作值）。
    - 其余标量（**含数字**）保持原样：数字仍以原值探测，保住"宽松校验服务端"的命中（如 omni maxCount）。
    见 docs/参数值生成优化方案.md。"""
    t = getattr(prior, "param_type", None)
    param = getattr(prior, "param", None)
    if (param is not None and t in ("string", "union", "unknown")
            and (param.pattern or param.str_format or param.min_length)):
        from mcpfuzz import valuegen
        shaped = valuegen.inject_value(param, value)
        if shaped is None:
            return None
        return {**base_args, prior.param_path: shaped}
    if t == "array":
        v = [value]
        n = (getattr(param, "min_items", None) or 0) if param else 0
        while len(v) < n:                       # 补足 minItems（P3：minItems≥2 的数组）
            v.append("x")
    elif t == "object":
        # P3：object 既测 value 位 {键:载荷}，也测 key 位 {载荷:值}（env 变量名/HTTP 头名型 sink）
        v = {value: "mcpfuzz"} if placement == "key" else {"mcpfuzz": value}
    else:
        v = value
    return {**base_args, prior.param_path: v}


def _blamed_param(err: str) -> str | None:
    """从**输入校验类**报错里解析它点名的参数（如 'expected number, received string at maxResults'、
    'Invalid UUID at investigationId'、'Invalid input: - appName: ...'），用于区分"目标参数本身被拒"
    与"某兄弟参数填充值不合法把整个调用挡下"。通用解析，不针对任何服务。

    保守起见只在确为输入校验错误时解析，且 'at <参数>' 只认**位于消息末尾**的那个（zod/MCP 校验
    把出错字段路径放在末尾）——避免把 'at least'/'at runtime' 这类普通英文误当参数名。"""
    if not re.search(
        r"Invalid (?:arguments|input|option|UUID|string|email|enum)|expected .+? received"
        r"|Too (?:small|big)|-32602", err, re.I):
        return None
    s = err.strip()
    # zod/MCP 风格：出错字段路径在末尾 "... at <path>"（可能后跟 error=None 之类噪音）
    m = re.search(r"\bat\s+([A-Za-z_][\w.]*(?:\[\d+\])?[\w.]*)\s*(?:error=\S+\s*)?$", s)
    if m:
        return m.group(1).split("[")[0].split(".")[0]
    # nest/zod 列表风格："- <field>: <message>"（已在上面确认是校验错误的前提下）
    m = re.search(r"[-•]\s*([A-Za-z_]\w*)\s*:\s*\S", s)
    if m:
        return m.group(1)
    return None


def _is_type_enforced(err: str, param_path) -> bool:
    """报错是否表明【目标参数本身】被服务端强制为数值/布尔类型（收到字符串被拒）。
    用于 P5：数字参数先探 1 条，若类型被强制 → 字符串注入进不去，提前停、省掉剩余探针；
    若服务端反而收下了字符串（宽松校验，如 omni git_log.maxCount）→ 不触发，继续打全套（保召回）。"""
    if not err:
        return False
    if not re.search(r"expected (number|integer|bigint|boolean)", err, re.I):
        return False
    blamed = _blamed_param(err)
    return blamed is not None and blamed == str(param_path).split(".")[0]


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
                        read_back=None):
    probes = synthesizer.synthesize(prior)
    if getattr(prior, "param_type", None) == "object":
        # P3：object 参数对每条载荷同时测 value 位与 key 位（交错，使截断后两位置都保留）
        from dataclasses import replace
        probes = [x for p in probes for x in (p, replace(p, placement="key"))]
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
    sent_any = False      # 是否真的发出过载荷（全被"锁死约束"跳过时为 False）
    type_locked = False   # P5：数字参数被服务端强制类型校验 → 提前停
    numeric = getattr(prior, "param_type", None) in ("number", "integer")
    last_err = ""
    for p in probes:
        args = _shaped_args(base_args, prior, p.value, getattr(p, "placement", "value"))
        if args is None:
            continue   # 参数被声明约束锁死（uuid/锚死 pattern 等），这条载荷无法构造成合法骨架 → 跳过
        sent_any = True
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
            if _reached_via_error(res):
                saw_program_error = True
            if numeric and _is_type_enforced(err_text, param):
                # 服务端强制数值类型、字符串被拒 → 字符串注入进不去，省掉剩余探针（宽松校验的服务端不会命中此分支）
                type_locked = True
                break
        else:
            saw_ok = True

        # 被动：错误指纹（弱证据），对响应与报错正文都看。
        # SSRF 例外：连接/解析失败指纹（ECONNREFUSED/getaddrinfo/Name or service not known…）
        # 只在**内网/元数据目标**上才算 SSRF 证据——它证明服务端"试图越过信任边界去连内网"。
        # 打公网目标连不通不是漏洞（本职功能的正常失败），不计。
        fp = oracle.fingerprint(text, p.vuln_class)
        if fp and not (p.vuln_class == SSRF and getattr(p, "target_scope", "public") != "internal"):
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
                    # 任何求值回显（服务端算出我未发出的计算结果）即确认代码注入（CWE-94，执行确认）。
                    # 不特判"算术 vs 代码"：对 CODE 用 tier 标危害程度（L2=越域 RCE 级 / L1=算术），
                    # 但 tier 不作确认闸门（口径 ①）；declared_domain 仅作人工复核附注。
                    ev = _code_ev(prior, p, hit.evidence) if p.vuln_class == CODE else hit.evidence
                    return _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "inband")
                if oracle.fingerprint(text, p.vuln_class):
                    return _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "inband")
            # SSRF 信任边界：只认与"发起 fetch"有因果关系的证据——
            #   · 正文命中云元数据特征串（ami-id/instance-id 等）→ 走上面 observe_inband 的 confirmed；
            #   · 对内网目标出现连接失败指纹（ECONNREFUSED/超时/getaddrinfo 等）→ 由上面的 error_fingerprint
            #     归入 weak（疑似），证明服务端确实去连了内网。
            # 不再用"返回了非空正文"反推"够到了内网"：返回的正文是工具的正常业务输出，与有无 fetch
            # 无因果（该参数常根本不发请求、服务端照常返回结果或业务报错），此推理不成立，故移除。
        elif p.channel == "timing":
            if baseline_latency is not None and (latency - baseline_latency) >= p.delay_target * 0.6:
                if await _confirm_timing(session, target, args, p, baseline_latency):
                    ev = {"type": "timing", "baseline": round(baseline_latency, 3),
                          "observed": round(latency, 3), "target": p.delay_target}
                    return _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "timing")
        elif p.channel == "differential":
            ev = _diff_hit(p.vuln_class, baseline_text, text, p.value)
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
        elif p.channel == "path_confine":
            # fail-closed 写型路径穿越：用该 MCP 自己的读回器做"目标路径 vs 未写入对照路径"自对照差分。
            # 读两条同形路径——我们刚写入的越界落地路径 landing，与一条从未写过的对照路径 control。
            #   · 真写进去了：读 landing 得文件正文、读 control 得"不存在"（或读失败）→ 两者不同 → 确认。
            #   · 什么都没写（读型工具/被围栏拦）：两者都是"不存在"模板 → 去掉回显的路径串后一致 → 不确认。
            # 只认"两条路径读回结果不同"这一正向差分，不检非空、不解析任何拒绝措辞（避免把"文件不存在"
            # 提示误当成写入成功）。
            tok = getattr(p.probe, "token", None) if p.probe else None
            if read_back is not None and tok:
                ext = ".txt" if p.value.endswith(".txt") else ""
                landing = "/tmp/" + tok + ext
                control = "/tmp/" + tok + "_ctl" + ext   # 同形但从未写入的对照路径
                try:
                    back = await read_back(landing)
                except Exception:
                    back = ""
                try:
                    back_ctl = await read_back(control)
                except Exception:
                    back_ctl = ""
                if back and _strip_paths(back, (landing, control)) != _strip_paths(back_ctl, (landing, control)):
                    ev = {"type": "path_traversal_write", "channel": "cross_tool",
                          "landing": landing, "control": control, "snippet": back[:160],
                          "note": "越界写入路径读回内容与未写入对照路径不同，canary 真实落地，确认不受路径限制"}
                    return _confirmed(target, param, PT, p, ev, seq_trace, args, "cross_tool")
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
                # 信任边界：SSRF 的带外回连打的是我们的**公网** collector（target_scope=public）。
                # 服务端能对外发请求=可达性（本职功能），**不**构成 SSRF 漏洞结论——SSRF 要求越过
                # 信任边界（内网/元数据），那条由上面的 internal 目标探针负责。这里仅记可达性，
                # 使结论落到"疑似无/已触达"而非"未触达"，不再堆"疑似有"。
                saw_ok = True
            else:
                return _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "oob")

    # 仅弱证据 → 疑似有
    if weak:
        cls, p, ev = weak[0]
        args = _shaped_args(base_args, prior, p.value, getattr(p, "placement", "value")) or base_args
        return Finding(target, param, cls, SUSPECTED, payload=p.value, channel=ev.get("channel", p.channel),
                       evidence=ev,
                       sequence=seq_trace + [{"tool": target, "args": args, "payload_param": param}],
                       note="仅弱证据（错误指纹 / 回连未越边界），需人工复核")

    # 无任何命中：区分"疑似无"（本参数确有探针触达 sink）与"未触达"。
    # 触达只看本参数自己的探针——有正常返回(saw_ok)，或载荷抵达后端程序被其当非法参数拒
    # （程序级报错 saw_program_error）。不拿工具级 baseline 顶替：否则强类型/枚举/pattern
    # 参数的探针被 schema 全弹回时，会被 baseline 误翻成"疑似无漏洞"，掩盖"其实没测到"。
    if saw_ok or saw_program_error:
        return Finding(target, param, repr_cls, LIKELY_CLEAN, note="")
    if type_locked:
        return Finding(target, param, repr_cls, UNREACHED,
                       note="未触达 sink：服务端对该数值参数强制类型校验，字符串注入无法进入（探 1 条即停，省余下探针）")
    if not sent_any:
        # 所有载荷都因参数被声明约束锁死（uuid/锚死 pattern/刚性 format）而无法构造合法骨架 → 未发送
        return Finding(target, param, repr_cls, UNREACHED,
                       note="未触达 sink：参数被声明约束（格式/枚举/类型）锁死，无法构造满足约束的注入载荷（未发送）")
    note = "未触达 sink：本参数所有探针在到达后端程序前被输入校验/参数约束拒绝"
    if last_err:
        err = str(last_err)
        blamed = _blamed_param(err)
        if blamed and blamed != str(param).split(".")[0]:
            # 报错指向的是另一个参数 → 不是本参数打不进，而是某兄弟必填参数的填充值不合法
            note += f"（实际被兄弟参数 '{blamed}' 的约束挡下，非本参数本身）"
        note += f"；完整错误：{err[:400]}"
    return Finding(target, param, repr_cls, UNREACHED, note=note)


async def _confirm_timing(session, target, args, p, baseline, rounds=2) -> bool:
    """复测去抖：再跑 rounds 次，取中位的额外时延，仍 >= 目标*0.6 才算确认。"""
    adds = []
    for _ in range(rounds):
        res, lat = await _timed_call(session, target, args)
        adds.append(lat - baseline)
    adds.sort()
    return adds[len(adds) // 2] >= p.delay_target * 0.6


def _strip_paths(s, paths):
    """去掉文本里回显的路径串后 strip，用于路径穿越自对照差分的"路径回显无关"比较。"""
    s = s or ""
    for pth in paths:
        s = s.replace(pth, "")
    return s.strip()


def _diff_hit(vuln_class, baseline_text, text, payload=None):
    """差分：参数注入的 --version/--help 若让响应出现版本/用法/getopt 报错特征（基线没有）→ 命中。"""
    if vuln_class != AI or not text or text == baseline_text:
        return None
    if _VALIDATION_ERR.search(text):
        return None   # 应用层输入/枚举校验（非 argv 注入），不算
    m = _AI_MARKERS.search(text)
    if m and (not baseline_text or m.group(0).lower() not in baseline_text.lower()):
        marker = m.group(0)
        # 回显感知（与 inband 同一原则）：匹配到的 marker 若本就是所发载荷的子串，说明它是载荷被
        # 原样回显（如载荷 "--usage" 让报错里出现 "usage:"），非参数解析器的真实输出 → 不算证据。
        core = marker.lower().strip(":").lstrip("-")
        if payload and core and core in str(payload).lower():
            return None
        i = m.start()
        return {"type": "differential", "marker": marker,
                "snippet": text[max(0, i - 20): i + 60]}
    return None


def _code_ev(prior, p, hit_evidence):
    """代码注入确认的证据包（口径 ①，不特判"算术 vs 代码"）：
    服务端把参数求值并回显了我未发出的计算结果 → 即确认代码注入（CWE-94，执行确认）。
    tier 只作**危害标注**、不作确认闸门：L2=越过算术的通用代码/模板求值（RCE 级）；L1=算术求值。
    declared_domain 仅作人工复核附注（LLM 复述的参数声明用途 + 引文），不参与裁决。"""
    ev = dict(hit_evidence or {})
    tier = getattr(p, "tier", "") or "L1"
    ev["tier"] = tier
    ev["impact"] = "rce" if tier == "L2" else "arithmetic_eval"
    ev["declared_domain"] = getattr(prior, "declared_domain", "")
    ev["domain_evidence"] = getattr(prior, "domain_evidence", "")
    ev["note"] = ("服务端对参数求值并回显了未发出的计算结果 → 确认代码注入（CWE-94，执行确认）。"
                  + ("命中为越过算术的通用代码/模板求值，危害达 RCE 级。" if tier == "L2"
                     else "命中为算术求值；更高危害以同参数 L2 探针结果为准。")
                  + " declared_domain 供人工复核。")
    return ev


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
