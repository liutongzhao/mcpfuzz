"""Verdict engine: build the "launch pad" on a persistent session, take a baseline, then send the full probe
battery per parameter and reach a five-state verdict.

See the verdict-engine design doc and the verdict-methodology doc.
- Probe scheduler: send the full battery by rank, with early-stop for a parameter once CONFIRMED.
- Multi-channel observation: inband (reflection/signature, direct evidence) / oob (out-of-band callback,
  batch poll) / timing (delay difference, retested) / differential (diff against the baseline response) /
  error fingerprint (passive weak evidence).
- Reachability: baseline call + any non-error call -> reached, used to distinguish "likely clean" from "unreached".
- Evidence grading -> five states: hard/provable evidence -> confirmed; weak only -> suspected; reached with
  no hit -> likely clean; unreached; not tested.
"""
from __future__ import annotations

import asyncio
import re
import time

from calchas.__about__ import MARKER
from calchas.driver import call_on
from calchas.sink.types import AI, CODE, PT, SSRF

from .extract import extract_value
from .types import CONFIRMED, DOS, LIKELY_CLEAN, SKIPPED, SUSPECTED, UNREACHED, Finding

# Signature markers for the argument-injection --version/--help differential: only accept strong signals that
# "the option was genuinely parsed by getopt/CLI" — usage text, getopt option errors, and a **contextualized
# version banner** (GNU/Copyright/"version X.Y.Z"/"vX.Y.Z").
# [KEY] No longer matches a bare decimal `\d+\.\d+`: it would mistake ratios/sizes/numbers in normal output
# (e.g. "ratio": 1.444) for a version number, causing widespread false positives (observed on token-optimizer).
# A version number must be **three segments** (explicit "version X.Y.Z" context, or vX.Y.Z with a `v` prefix) —
# a two-segment "Version 1.2" is mostly prose/data in the body (e.g. a dataset description "...Version 1.2
# structure..."), which would fire the --version probe on a normal response containing that string (observed on
# neg_ckan); a real CLI version banner is basically three segments (git 2.39.1).
# Still excludes "invalid option": application-level enum validation also uses it ("Invalid option: expected one of ..."), which would misfire.
_AI_MARKERS = re.compile(
    r"(?i)("
    r"usage:|unknown option|unrecognized option|option requires an argument|illegal option|"
    r"copyright\s*\(c\)|\(gnu[^)]*\)|\bgnu\s+coreutils\b|"
    r"\bversion\s+v?\d+\.\d+\.\d+|\bv\d+\.\d+\.\d+\b"
    r")")

# Blocked by schema/protocol-level input validation before reaching the backend program -> the sink was not
# reached. These are generic MCP-framework / JSON-Schema errors (zod / JSON-RPC -32602 etc.), independent of the
# specific server — does not enumerate any single program's error wording.
_VALIDATION_ERR = re.compile(r"(?i)(input validation error|invalid arguments for tool|"
                             r"expected (?:number|array|object|string|boolean|one of)|"
                             r"invalid input|invalid enum|required property|-32602)")


def _reached_via_error(res: dict) -> bool:
    """The tool returned an error at the **business layer** (has a response body, not a transport exception) and
    it is not a schema/protocol-level input-validation error -> the payload reached the backend program and was
    merely rejected as an illegal argument (the sink was reached). Generic judgement, no server-specific words.
    """
    text = res.get("text") or ""
    if not text or res.get("exc"):      # transport exception / no response -> not reached
        return False
    return not _VALIDATION_ERR.search(text)


class _NullReporter:
    def emit(self, *a, **k):
        pass


async def _resolve_args(arg_specs: dict, step_responses: dict) -> tuple[dict, list]:
    """Resolve {param: ArgSpec} into concrete arguments. Returns (args, list of unresolved parameter names)."""
    args, missing = {}, []
    for param, spec in arg_specs.items():
        if not isinstance(spec, dict):
            continue
        if spec.get("src") == "from_step":
            resp = step_responses.get(spec.get("step"))
            if resp is not None:
                # recorded path (deterministic) -> scored field match -> recorded value (agent path, no LLM) -> LLM
                val = extract_value(resp, spec.get("extract", ""), spec.get("path"), spec.get("value"))
            else:
                val = spec.get("value")   # producer step never ran -> fall back to the value discovery used
            if val is None:
                missing.append(param)
            else:
                args[param] = val
        else:
            args[param] = spec.get("value")
    return args, missing


async def run_tool(session, plan, sink_params, synthesizer, oracle, poll_window=(3, 2.0),
                   reporter=None, settings=None, liveness=None, read_back=None, live=False) -> list:
    """plan.steps[-1] is the target tool. sink_params: the list of ParamSinkPrior to test for this tool. Returns a list of Findings.

    liveness: optional async liveness probe (no args, returns bool), for crash/DoS observation.
    read_back: optional async(path)->text read-back (paired read-file tool), for cross_tool canary verdicts.
    live: True when the plan's prerequisites were already executed on THIS session during agent exploration
          (live-session attack) — the server-side state is already present, so do NOT replay the prerequisite
          steps (replaying would double-create resources). The target's from_step args then resolve via their
          recorded values (extract_value's value fallback), which are exactly the values the agent used to reach
          the target on this same session.
    """
    reporter = reporter or _NullReporter()
    target = plan.steps[-1].tool
    seq_trace = []   # reproducibility: record of prerequisite calls

    if not plan.reachable:
        return _skipped_all(target, sink_params, plan.note or "plan judged the target unreachable", reporter)

    # 1) Build the launch pad.
    step_responses = {}
    launchpad_errors = []
    if live:
        # State was built on this session by the agent's exploration; record the recipe for reproducibility but
        # do not re-run the prerequisites. Target from_step args fall back to their recorded values below.
        seq_trace = [{"tool": st.tool, "args": {k: v.get("value") for k, v in (st.args or {}).items()
                                                if isinstance(v, dict)}, "is_error": False}
                     for st in plan.steps[:-1]]
    else:
        # Replay prerequisite steps best-effort. One step failing does not abandon the whole thing — prerequisites are mostly "ensure a resource exists" groundwork.
        for st in plan.steps[:-1]:
            args, missing = await _resolve_args(st.args, step_responses)
            if missing:
                launchpad_errors.append(f"step {st.step} ({st.tool}) parameters {missing} could not be resolved")
                reporter.emit("launchpad.step", level="debug", tool=st.tool, step=st.step,
                              skipped=True, missing=missing, reason="a depended-on prerequisite output is absent, skipping this step")
                continue
            res = await _safe_call(session, st.tool, args)
            step_responses[st.step] = res["text"]
            seq_trace.append({"tool": st.tool, "args": args, "is_error": res["is_error"]})
            reporter.emit("launchpad.step", level="debug", tool=st.tool, step=st.step,
                          args=res.get("args_sent", args), is_error=res["is_error"],
                          response=res.get("text", ""), error=res.get("exc"))
            if res["is_error"]:
                launchpad_errors.append(f"step {st.step} ({st.tool}) call errored")
        if launchpad_errors:
            reporter.emit("launchpad.warn", tool=target, reason="; ".join(launchpad_errors))

    # 2) The target tool's launch-pad arguments (the last step): only judge SKIPPED if a value truly cannot be resolved
    base_args, missing = await _resolve_args(plan.steps[-1].args, step_responses)
    if missing:
        extra = f" (prerequisites: {'; '.join(launchpad_errors)})" if launchpad_errors else ""
        note = f"target tool parameters {missing} could not be resolved{extra}"
        reporter.emit("launchpad.fail", tool=target, reason=note)
        return _skipped_all(target, sink_params, note, reporter)

    # 3) Baseline: call the target tool once with all-benign arguments, capturing response/latency/reachability (reused for differential, timing, reachability)
    base_res, base_latency = await _timed_call(session, target, base_args)
    baseline_text = base_res["text"] or ""
    baseline_ok = not base_res["is_error"]
    reporter.emit("launchpad.ready", level="debug", tool=target, base_args=base_args,
                  baseline_ok=baseline_ok, baseline_latency=round(base_latency, 3))

    # 4) For each parameter: send the full battery + multi-channel verdict + five states
    findings = []
    for i, ps in enumerate(sink_params):
        try:
            f = await _attack_param(session, target, base_args, ps, synthesizer, oracle,
                                    seq_trace, poll_window, reporter, settings,
                                    baseline_text, base_latency, read_back)
        except (Exception, asyncio.CancelledError) as e:
            note = f"connection aborted mid-flight (a network blip may have interrupted an in-progress call): {str(e)[:150]}"
            # Liveness-probe debounce: distinguish "the server was beaten down (DoS)" from "a network blip / broken local session"
            crashed = False
            if liveness is not None:
                alive, detail = await _liveness_recheck(liveness)
                if not alive:
                    crashed = True
                    note += f"; subsequent consecutive liveness probes failed, the server may have crashed/become unresponsive (suspected DoS); last reason: {detail}"
                    reporter.emit("server.crash", tool=target, note=note)
            reporter.emit("attack.tool.error", tool=target, error=note)
            for ps2 in sink_params[i:]:
                f2 = Finding(target, ps2.param_path, _repr_class(ps2), SKIPPED, note=note)
                findings.append(f2)
                _emit_finding(reporter, f2)
            if crashed:   # the crash becomes one availability finding, entering findings.json / the report
                findings.append(Finding(target, "(liveness probe)", DOS, SUSPECTED, note=note))
            return findings
        for one in f:   # _attack_param now returns a list of "one per class" (class-level early-stop, one parameter can confirm several classes)
            findings.append(one)
            _emit_finding(reporter, one)

    # Liveness probe after the full battery (DoS observation): payloads can beat the server to unresponsiveness,
    # even if a single call only manifested as an error. Debounced over K retests; only a real failure is judged
    # a crash, landing as one availability finding in findings (and thus findings.json / the report).
    if liveness is not None:
        alive, detail = await _liveness_recheck(liveness)
        if not alive:
            note = f"consecutive liveness probes failed after the full battery, the server may have crashed/become unresponsive (suspected DoS); last reason: {detail}"
            reporter.emit("server.crash", tool=target, note=note)
            findings.append(Finding(target, "(liveness probe)", DOS, SUSPECTED, note=note))
    return findings


async def _liveness_recheck(liveness, rounds: int = 3, interval: float = 1.0):
    """Crash-judgement debounce (verdict-methodology doc: a crash needs K repeats, to offset network blips):
    only judge a crash if `rounds` consecutive heartbeats all fail; any single success judges it alive. Returns
    (alive, detail), where detail is the last failure reason (the real exception, not swallowed — this is how a
    real DoS is distinguished from a false positive)."""
    detail = ""
    for i in range(rounds):
        try:
            if await liveness():
                return True, ""
            detail = detail or "heartbeat returned negative"
        except Exception as e:
            detail = f"{type(e).__name__}: {str(e)[:150]}"
        if i < rounds - 1:
            await asyncio.sleep(interval)
    return False, detail


def _shaped_args(base_args, prior, value, placement="value"):
    """Place the payload according to the parameter's declared constraints/structure, to avoid being blocked by
    input validation before the backend program. Returns the argument dict; if the parameter is locked down by a
    declared constraint and this payload cannot be built into a valid skeleton -> returns **None** (the caller
    skips this payload).

    - **A format-constrained string** (pattern/format/minLength): use constraint-aware "valid skeleton +
      injection" (valuegen.inject_value) — e.g. `^proj-` -> `proj-<payload>`; uuid / anchored pattern -> None (honestly cannot inject).
    - array -> [value]; object -> {<key>: value} (payload as the value).
    - Other scalars (**including numbers**) kept as-is: a number is still probed with its own value, preserving a hit on a "loosely validating server" (e.g. omni maxCount).
    See the value-generation design doc."""
    t = getattr(prior, "param_type", None)
    param = getattr(prior, "param", None)
    if (param is not None and t in ("string", "union", "unknown")
            and (param.pattern or param.str_format or param.min_length)):
        from calchas import valuegen
        shaped = valuegen.inject_value(param, value)
        if shaped is None:
            return None
        return {**base_args, prior.param_path: shaped}
    if t == "array":
        v = [value]
        n = (getattr(param, "min_items", None) or 0) if param else 0
        while len(v) < n:                       # pad to minItems (P3: arrays with minItems>=2)
            v.append("x")
    elif t == "object":
        # P3: for an object, test both the value position {key: payload} and the key position {payload: value} (env-var-name / HTTP-header-name sinks)
        v = {value: MARKER} if placement == "key" else {MARKER: value}
    else:
        v = value
    return {**base_args, prior.param_path: v}


def _blamed_param(err: str) -> str | None:
    """Parse the parameter an **input-validation** error names (e.g. 'expected number, received string at
    maxResults', 'Invalid UUID at investigationId', 'Invalid input: - appName: ...'), to distinguish "the target
    parameter itself was rejected" from "a sibling parameter's fill value was invalid and blocked the whole
    call". Generic parsing, not targeted at any server.

    To be safe, only parse when it is genuinely an input-validation error, and 'at <param>' only accepts the one
    **at the end of the message** (zod/MCP validation puts the erroring field path at the end) — to avoid
    mistaking 'at least'/'at runtime' and other plain English for a parameter name."""
    if not re.search(
        r"Invalid (?:arguments|input|option|UUID|string|email|enum)|expected .+? received"
        r"|Too (?:small|big)|-32602", err, re.I):
        return None
    s = err.strip()
    # zod/MCP style: the erroring field path is at the end "... at <path>" (possibly followed by noise like error=None)
    m = re.search(r"\bat\s+([A-Za-z_][\w.]*(?:\[\d+\])?[\w.]*)\s*(?:error=\S+\s*)?$", s)
    if m:
        return m.group(1).split("[")[0].split(".")[0]
    # nest/zod list style: "- <field>: <message>" (given it was already confirmed above to be a validation error)
    m = re.search(r"[-•]\s*([A-Za-z_]\w*)\s*:\s*\S", s)
    if m:
        return m.group(1)
    return None


def _is_type_enforced(err: str, param_path) -> bool:
    """Whether the error indicates that [the target parameter itself] is enforced by the server to be a
    numeric/boolean type (a string was rejected). Used for P5: probe a numeric parameter with 1 payload first,
    and if the type is enforced -> string injection cannot get in, stop early and save the remaining probes; if
    the server instead accepted the string (loose validation, e.g. omni git_log.maxCount) -> do not trigger,
    continue with the full battery (to preserve recall)."""
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
        # P3: for an object parameter, test both the value position and key position for each payload (interleaved, so both positions survive truncation)
        from dataclasses import replace
        probes = [x for p in probes for x in (p, replace(p, placement="key"))]
    if not getattr(oracle, "oob_enabled", True):
        # no OOB collector configured -> drop out-of-band probes entirely (don't waste requests on an unreachable callback)
        probes = [p for p in probes if p.channel != "oob"]
    repr_cls = _repr_class(prior)
    param = prior.param_path
    max_payloads = getattr(settings, "max_payloads", None) if settings else None
    if max_payloads:
        probes = probes[:max_payloads]
    if not probes:
        return [Finding(target, param, repr_cls, LIKELY_CLEAN, note="no usable payload (parameter inert / no enabled class)")]

    reporter.emit("attack.param.start", tool=target, param=param, sink=repr_cls, payload_count=len(probes))
    delay = getattr(settings, "delay", 0.0) if settings else 0.0

    oob_pending = []      # [(probe_spec, args)]
    weak = []             # [(vuln_class, probe_spec, evidence)] weak evidence -> suspected
    ssrf_blind = []       # blind-SSRF candidates: an internal target fetched successfully (is_error=False) but
                          # the body has no metadata signature; promoted to suspected blind SSRF once an OOB
                          # callback confirms this parameter is truly a fetch sink (see oob poll)
    saw_ok = False
    saw_program_error = False   # a payload reached the backend program and was rejected as an illegal argument (reached, used to distinguish "likely clean vs unreached")
    sent_any = False      # whether any payload was actually sent (False when all are skipped by a "locked-down constraint")
    type_locked = False   # P5: the server enforces the type of a numeric parameter -> stop early
    numeric = getattr(prior, "param_type", None) in ("number", "integer")
    last_err = ""
    confirmed_classes: set = set()   # already-confirmed vuln classes -> intra-class early-stop (stop sending that class's remaining payloads), other classes continue
    confirmed_findings: list = []    # one record per confirmed class (a parameter can hit several classes at once)

    def _mark(cls, finding):
        confirmed_findings.append(finding)
        confirmed_classes.add(cls)

    for p in probes:
        if p.vuln_class in confirmed_classes:
            continue   # this class is already confirmed -> intra-class early-stop: skip its remaining payloads; other classes continue
        args = _shaped_args(base_args, prior, p.value, getattr(p, "placement", "value"))
        if args is None:
            continue   # the parameter is locked down by a declared constraint (uuid / anchored pattern etc.), this payload cannot be built into a valid skeleton -> skip
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
                # The server enforces the numeric type and the string was rejected -> string injection cannot get in, save the remaining probes (a loosely-validating server does not hit this branch)
                type_locked = True
                break
        else:
            saw_ok = True

        # Passive: error fingerprint (weak evidence), inspected on both the response and the error body.
        # SSRF exception: a connection/resolution-failure fingerprint (ECONNREFUSED/getaddrinfo/Name or service
        # not known...) only counts as SSRF evidence on an **internal/metadata target** — it proves the server
        # "tried to cross the trust boundary to reach the intranet". Failing to connect to a public target is not
        # a vulnerability (a normal failure of the intended function), not counted.
        fp = oracle.fingerprint(text, p.vuln_class)
        if not fp and res["is_error"] and p.vuln_class == SSRF:
            # A connection failure/timeout often lands in exc as a transport exception (not the body text) -> for
            # SSRF, scan the error channel once more as a fallback, so positive evidence of "the server did cross
            # the boundary to reach the intranet but could not connect" is not missed by scanning only text. Only
            # SSRF, only internal targets count this (see the target_scope gate below), not affecting other classes.
            fp = oracle.fingerprint(res.get("exc") or "", p.vuln_class)
        if fp and not (p.vuln_class == SSRF and getattr(p, "target_scope", "public") != "internal"):
            weak.append((p.vuln_class, p, {"type": "error_fingerprint", "channel": "inband",
                                           "snippet": fp}))

        if p.channel == "inband":
            hit = oracle.observe_inband(p.probe, text)
            if hit:
                # Generic reflection awareness: if the matched signature is itself a substring of the payload ->
                # suspected "input echoed verbatim", not execution/parsing. A signature not in the payload
                # (eval-echo token1681 / file signature root:x:0:0 / metadata ami-id) -> hard confirmation; one
                # in the payload (AI unknown option, SSRF echoing a metadata path word) -> requires a
                # corresponding error fingerprint to corroborate before confirming, otherwise it is not evidence
                # (pure echo exists on almost every tool, counts toward reachability, trends to "likely clean",
                # not piling up "suspected").
                marker = (hit.evidence or {}).get("marker", "")
                reflected = bool(marker) and marker in p.value
                if not reflected:
                    # Any eval-echo (the server computed a result I never sent) confirms code injection (CWE-94,
                    # execution-confirmed). No special-casing of "arithmetic vs code": for CODE, label the impact
                    # with tier (L2=out-of-domain RCE-level / L1=arithmetic), but tier is not a confirmation gate
                    # (policy ①); declared_domain is a manual-review annotation only.
                    ev = _code_ev(prior, p, hit.evidence) if p.vuln_class == CODE else hit.evidence
                    _mark(p.vuln_class, _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "inband"))
                    continue
                if oracle.fingerprint(text, p.vuln_class):
                    _mark(p.vuln_class, _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "inband"))
                    continue
            # SSRF trust boundary: only accept evidence causally linked to "initiating a fetch" —
            #   - a cloud-metadata signature in the body (ami-id/instance-id etc.) -> confirmed via observe_inband above;
            #   - a connection-failure fingerprint on an internal target (ECONNREFUSED/timeout/getaddrinfo etc.)
            #     -> classified into weak (suspected) by the error_fingerprint above, proving the server did try to reach the intranet.
            # No longer infers "reached the intranet" from "returned a non-empty body": the returned body is the
            # tool's normal business output, with no causal link to whether a fetch happened (this parameter
            # often does not make a request at all, and the server returns a result or a business error as usual),
            # so that inference does not hold and is removed.
            # Blind-SSRF candidate: an internal/metadata target fetched successfully (is_error==False), no
            # metadata signature in the body, and no connection-failure fingerprint. On its own this cannot
            # distinguish "truly reached the intranet" from "this parameter makes no request and returns the
            # business result as usual" -> record as a candidate for now; promote to suspected blind SSRF once the
            # OOB callback below confirms this parameter does make an outbound request (a fetch sink) (an OOB hit
            # rules out the "makes no request at all" false positive).
            if (p.vuln_class == SSRF and getattr(p, "target_scope", "public") == "internal"
                    and not res["is_error"] and not fp):
                ssrf_blind.append((p, args, text))
        elif p.channel == "timing":
            if baseline_latency is not None and (latency - baseline_latency) >= p.delay_target * 0.6:
                if await _confirm_timing(session, target, args, p, baseline_latency):
                    ev = {"type": "timing", "baseline": round(baseline_latency, 3),
                          "observed": round(latency, 3), "target": p.delay_target}
                    _mark(p.vuln_class, _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "timing"))
                    continue
        elif p.channel == "differential":
            ev = _diff_hit(p.vuln_class, baseline_text, text, p.value)
            if ev:
                _mark(p.vuln_class, _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "differential"))
                continue
        elif p.channel == "cross_tool":
            # The canary-writing payload was already sent above; if there is a paired read tool, read back /tmp/{token} and match
            if read_back is not None:
                canary_path = "/tmp/" + p.probe.token
                try:
                    back = await read_back(canary_path)
                except Exception:
                    back = ""
                # Must read back the "eval canary" (the product {TOKEN}1681 of echo {TOKEN}$((41*41))), proving
                # both: (1) the file truly landed (the read-back contains what we wrote); (2) $((41*41)) was
                # evaluated by the shell = the command truly executed. A token-only match does not count — a
                # reader often echoes canary_path verbatim in a "file not found / already cached / error" message
                # (the marker appears only in the path string, the file was not written), which is a generic false
                # positive. Consistent with the inband {TOKEN}1681 criterion (generic, not targeted at any server).
                expect = p.probe.expect or []
                if back and expect and any(e in back for e in expect):
                    ev = {"type": "cross_tool", "reader_path": canary_path, "snippet": back[:160]}
                    _mark(p.vuln_class, _confirmed(target, param, p.vuln_class, p, ev, seq_trace, args, "cross_tool"))
                    continue
            # No paired read tool or the eval canary was not read back -> not counted, continue
        elif p.channel == "path_confine":
            # fail-closed write-type path traversal: use this MCP's own read-back tool for a "target path vs
            # never-written control path" self-differential. Read two isomorphic paths — the out-of-bounds landing
            # path we just wrote, and a control path that was never written.
            #   - truly written: reading landing yields the file body, reading control yields "not found" (or a read failure) -> the two differ -> confirmed.
            #   - nothing written (a read-type tool / blocked by a fence): both are a "not found" template -> identical after stripping the echoed path strings -> not confirmed.
            # Only accept the positive differential "the two paths read back differently"; do not check non-empty,
            # do not parse any rejection wording (to avoid mistaking a "file not found" message for a successful write).
            tok = getattr(p.probe, "token", None) if p.probe else None
            if read_back is not None and tok:
                ext = ".txt" if p.value.endswith(".txt") else ""
                landing = "/tmp/" + tok + ext
                control = "/tmp/" + tok + "_ctl" + ext     # isomorphic but never-written control path
                control2 = "/tmp/" + tok + "_ctl2" + ext   # a second never-written control path, for the reader-fidelity self-check

                async def _rb(path):
                    try:
                        return await read_back(path) or ""
                    except Exception:
                        return ""
                back, back_ctl, back_ctl2 = await _rb(landing), await _rb(control), await _rb(control2)
                allp = (landing, control, control2)
                s_land = _norm_pt_readback(back, allp)
                s_ctl = _norm_pt_readback(back_ctl, allp)
                s_ctl2 = _norm_pt_readback(back_ctl2, allp)
                # Reader-fidelity self-check: the two [never-written] control paths must read back identically. If
                # they differ, the reader's output depends on the path itself / is non-deterministic (a mock or a
                # "comparison-type" tool), so its "landing != control" differential does not mean the file truly
                # landed -> untrustworthy, abandon this channel (generic, not targeted at any server). A true-write
                # scenario (e.g. git clone/init creating a directory) has a faithful reader that reads "not found"
                # identically for never-written paths, confirming as usual, unaffected.
                reader_faithful = (s_ctl == s_ctl2)
                if back and reader_faithful and s_land != s_ctl:
                    ev = {"type": "path_traversal_write", "channel": "cross_tool",
                          "landing": landing, "control": control, "snippet": back[:160],
                          "note": "the out-of-bounds write path reads back different content than the never-written control path, and the reader reads never-written paths identically (faithful), so the canary truly landed"}
                    _mark(PT, _confirmed(target, param, PT, p, ev, seq_trace, args, "cross_tool"))
                    continue
        elif p.channel == "oob":
            oob_pending.append((p, args))
        if delay:
            await asyncio.sleep(delay)

    # Batch-poll out-of-band callbacks
    if oob_pending:
        hits = oracle.poll([p.probe for p, _ in oob_pending], rounds=poll_window[0], interval=poll_window[1])
        for p, args in oob_pending:
            hit = hits.get(p.probe.token)
            if not hit:
                continue
            if p.vuln_class in confirmed_classes:
                continue   # this class was already confirmed in the loop -> intra-class early-stop, do not re-record
            if p.vuln_class == SSRF:
                # Trust boundary: SSRF's out-of-band callback hits our **public** collector (target_scope=public).
                # The server being able to make outbound requests = reachability (the intended function), which
                # alone does **not** constitute an SSRF vulnerability. But it confirms one key thing: this
                # parameter does make the server **send an outbound request** (a real fetch sink, not an inert parameter).
                saw_ok = True
                # Blind-SSRF promotion: now that this parameter is confirmed to be a fetch sink (removing the
                # "makes no request at all" false-positive concern), and it also fetched an internal/metadata
                # target successfully (is_error=False, no connection-failure fingerprint) -> a suspected blind SSRF crossing the trust boundary.
                if ssrf_blind and SSRF not in confirmed_classes and not any(
                        w[0] == SSRF and (w[2] or {}).get("type") == "blind_ssrf" for w in weak):
                    bp, bargs, btext = ssrf_blind[0]
                    weak.append((SSRF, bp, {"type": "blind_ssrf", "channel": "oob+internal",
                        "internal_target": bp.value, "snippet": (btext or "")[:160],
                        "note": "the out-of-band callback confirms this parameter makes an outbound request (fetch sink), and it fetched an internal/metadata target successfully "
                                "(is_error=False, no connection-failure fingerprint) -> suspected blind SSRF crossing the trust boundary, needs manual review"}))
            else:
                _mark(p.vuln_class, _confirmed(target, param, p.vuln_class, p, hit.evidence, seq_trace, args, "oob"))

    # NOTE: the PT "path-acceptance self-calibrating differential" (path_accept_nofence) weak-evidence channel was
    # removed. It fired when a PT-classified parameter responded differently to an existing out-of-bounds target
    # (/dev/null, /tmp) vs a nonexistent one, intended to catch write/operation-type PT with no content echo and no
    # read-back tool. Measurement on the frozen ground-truth showed it has ~no discriminative power: it fired on
    # fixed (patched) versions as often as on vulnerable ones (same params), because most fixes only block `../`
    # traversal while the tool still reads absolute in-bounds-looking paths and reacts to their existence —
    # "reacting to out-of-bounds-target existence" proves the tool does file I/O, not that it crosses a security
    # boundary. PT now relies solely on positive proof (inband read-back of an out-of-bounds file's content
    # signature, or a landed write canary via path_confine), consistent with the fail-closed stance of the other
    # classes. No-echo / no-read-back write-type PT is an acknowledged black-box limitation.

    # Any class confirmed -> return all confirmed results (one per class); not overridden by weak/clean
    if confirmed_findings:
        return confirmed_findings

    # Weak evidence only -> suspected
    if weak:
        cls, p, ev = weak[0]
        args = _shaped_args(base_args, prior, p.value, getattr(p, "placement", "value")) or base_args
        return [Finding(target, param, cls, SUSPECTED, payload=p.value, channel=ev.get("channel", p.channel),
                        evidence=ev,
                        sequence=seq_trace + [{"tool": target, "args": args, "payload_param": param}],
                        note="weak evidence only (error fingerprint / callback not crossing the boundary), needs manual review")]

    # No hit at all: distinguish "likely clean" (this parameter did have a probe reach the sink) from "unreached".
    # Reachability only looks at this parameter's own probes — a normal return (saw_ok), or a payload reaching the
    # backend program and being rejected as an illegal argument (program-level error saw_program_error). Do not
    # substitute the tool-level baseline: otherwise, when a strongly-typed/enum/pattern parameter's probes are all
    # bounced by the schema, the baseline would mistranslate it into "likely no vulnerability", masking "actually not tested".
    if saw_ok or saw_program_error:
        return [Finding(target, param, repr_cls, LIKELY_CLEAN, note="")]
    if type_locked:
        return [Finding(target, param, repr_cls, UNREACHED,
                        note="sink not reached: the server enforces the type of this numeric parameter, so string injection cannot get in (probe 1 then stop, saving the remaining probes)")]
    if not sent_any:
        # All payloads could not be built into a valid skeleton because the parameter is locked down by a declared constraint (uuid / anchored pattern / rigid format) -> not sent
        return [Finding(target, param, repr_cls, UNREACHED,
                        note="sink not reached: the parameter is locked down by a declared constraint (format/enum/type), no constraint-satisfying injection payload could be built (not sent)")]
    note = "sink not reached: all of this parameter's probes were rejected by input validation / parameter constraints before reaching the backend program"
    if last_err:
        err = str(last_err)
        blamed = _blamed_param(err)
        if blamed and blamed != str(param).split(".")[0]:
            # The error points at another parameter -> it is not this parameter being unable to get in, but a sibling required parameter's fill value being invalid
            note += f" (actually blocked by the constraint of sibling parameter '{blamed}', not this parameter itself)"
        note += f"; full error: {err[:400]}"
    return [Finding(target, param, repr_cls, UNREACHED, note=note)]


async def _confirm_timing(session, target, args, p, baseline, rounds=2) -> bool:
    """Retest debounce: run `rounds` more times and require EVERY retest's extra delay to still be >= target*0.6
    (take the min), so a single jitter spike cannot confirm — together with the initial hit this means all probes
    were slow (fail-closed, fewest timing false positives)."""
    adds = []
    for _ in range(rounds):
        res, lat = await _timed_call(session, target, args)
        adds.append(lat - baseline)
    return bool(adds) and min(adds) >= p.delay_target * 0.6


def _strip_paths(s, paths):
    """Strip the echoed path strings from the text then strip(), for the "path-echo-independent" comparison in the path-traversal self-differential."""
    s = s or ""
    for pth in paths:
        s = s.replace(pth, "")
    return s.strip()


def _norm_pt_readback(s, paths):
    """Normalization before the path-traversal self-differential comparison: first strip the echoed path strings,
    then collapse digit runs into the placeholder `#`. Collapsing digits removes the **volatile numeric noise** in
    the reader's output (e.g. duration ms, counts, timestamps) — otherwise the reader's own runtime jitter
    (landing duration:5 vs control:6) would be mistaken for a "landing-content difference" and misfire. A real
    landing produces a structural/textual difference (file body vs not found), not a mere number change, so
    collapsing digits does not harm true cases."""
    return re.sub(r"\d+", "#", _strip_paths(s, paths))


def _diff_hit(vuln_class, baseline_text, text, payload=None):
    """Differential: for argument injection, if --version/--help makes the response show a version/usage/getopt-error signature (absent in the baseline) -> hit."""
    if vuln_class != AI or not text or text == baseline_text:
        return None
    if _VALIDATION_ERR.search(text):
        return None   # application-level input/enum validation (not an argv injection), does not count
    m = _AI_MARKERS.search(text)
    if m and (not baseline_text or m.group(0).lower() not in baseline_text.lower()):
        marker = m.group(0)
        # Reflection awareness (same principle as inband): if the matched marker is itself a substring of the
        # sent payload, it is the payload echoed verbatim (e.g. payload "--usage" causing "usage:" in the error),
        # not the real output of an argument parser -> does not count as evidence.
        core = marker.lower().strip(":").lstrip("-")
        if payload and core and core in str(payload).lower():
            return None
        i = m.start()
        return {"type": "differential", "marker": marker,
                "snippet": text[max(0, i - 20): i + 60]}
    return None


def _code_ev(prior, p, hit_evidence):
    """Evidence package for a code-injection confirmation (policy ①, no special-casing of "arithmetic vs code"):
    the server evaluated the parameter and echoed a computed result I never sent -> confirm code injection
    (CWE-94, execution-confirmed). tier is only an **impact label**, not a confirmation gate: L2=general
    code/template eval beyond arithmetic (RCE-level); L1=arithmetic eval. declared_domain is a manual-review
    annotation only (the LLM's paraphrase of the parameter's declared purpose + a quote), not part of the adjudication."""
    ev = dict(hit_evidence or {})
    tier = getattr(p, "tier", "") or "L1"
    ev["tier"] = tier
    ev["impact"] = "rce" if tier == "L2" else "arithmetic_eval"
    ev["declared_domain"] = getattr(prior, "declared_domain", "")
    ev["domain_evidence"] = getattr(prior, "domain_evidence", "")
    ev["note"] = ("the server evaluated the parameter and echoed a computed result that was not sent -> confirmed code injection (CWE-94, execution-confirmed). "
                  + ("the hit is general code/template eval beyond arithmetic, impact reaches RCE-level. " if tier == "L2"
                     else "the hit is arithmetic eval; for higher impact rely on the same parameter's L2 probe results. ")
                  + "declared_domain is for manual review.")
    return ev


def _confirmed(target, param, cls, p, evidence, seq_trace, final_args, channel):
    return Finding(target, param, cls, CONFIRMED, payload=p.value, channel=channel,
                   evidence=evidence,
                   sequence=seq_trace + [{"tool": target, "args": final_args, "payload_param": param}])


def _repr_class(prior):
    """Representative class: the highest-weight enabled class (to annotate no-hit conclusions like SKIPPED/UNREACHED)."""
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
