"""用大模型给 MCP 相关漏洞逐条打标签，判断哪些属于服务端、能否黑盒检测。

输入：data/candidates.jsonl（collect.py 的输出，自动排除恶意包 MAL- 记录）
输出（均在 data/ 下）：
  labels.jsonl       每条漏洞的标签（追加写入，支持断点续跑）
  labels_raw.jsonl   每次请求的原始回复，便于事后核查
  labels_errors.log  最终失败的条目
  classified.jsonl / classified.csv  候选数据与标签合并后的结果
  label_summary.txt  各标签分布统计

用法：
  python3 scripts/classify.py                  # 标注全部（已标注的会跳过）
  python3 scripts/classify.py --limit 20       # 先试跑 20 条
  python3 scripts/classify.py --review         # 用 REVIEW_MODEL 复核 confidence=low 的条目
  python3 scripts/classify.py --export-only    # 不调用模型，只重新导出合并结果与统计
"""
import argparse
import csv
import json
import random
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llm_config import API_KEY, BASE_URL, MODEL, REVIEW_MODEL  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CANDIDATES = DATA / "candidates.jsonl"
LABELS = DATA / "labels.jsonl"
RAW_LOG = DATA / "labels_raw.jsonl"
ERR_LOG = DATA / "labels_errors.log"

# 每个标签的合法取值；模型返回值不在其中则视为无效
SCHEMA = {
    "component": ["mcp_server", "mcp_gateway", "sdk", "client_host", "dev_tool", "ai_platform", "not_mcp"],
    "attack_target": ["server_side", "agent_side", "client_side", "mixed"],
    "attacker_position": ["tool_caller", "network", "malicious_content", "malicious_server", "local", "other"],
    "vuln_class": [
        "command_injection", "argument_injection", "code_injection", "sql_nosql_injection", "other_injection",
        "path_traversal", "ssrf", "missing_authentication", "authorization_bypass", "sandbox_or_allowlist_bypass",
        "dos_resource_exhaustion", "info_disclosure", "dns_rebinding_origin_cors", "session_token_issue",
        "xss_ui", "deserialization", "prompt_injection_tool_poisoning", "supply_chain", "other",
    ],
    "trigger_interface": ["tools_call", "resources_read", "prompts_get", "transport_http", "non_mcp_interface", "client_side", "unknown"],
    "blackbox_detectable": ["yes", "partial", "no"],
    "needs_multi_step": ["yes", "no", "unknown"],
    "needs_multi_identity": ["yes", "no", "unknown"],
    "oracle": [
        "oob_callback", "time_delay", "file_canary", "response_content", "differential_identity",
        "crash_or_timeout", "http_response_check", "none_or_unclear",
    ],
    "confidence": ["high", "medium", "low"],
}
FREE_TEXT = ["reason_zh"]

SYSTEM_PROMPT = """You are a security researcher labeling vulnerability records related to the Model Context Protocol (MCP).
Our research: BLACK-BOX vulnerability detection of MCP SERVERS (like REST API black-box fuzzing). The tester only connects to a running server, reads tools/list, resources/list, prompts/list, and sends crafted JSON-RPC requests. No source code. We care about harm to the SERVER and its backend (host OS, files, databases, downstream APIs), NOT about manipulating the LLM/agent.

Label each record with these fields (use EXACTLY one allowed value each):

component — what software has the bug:
  mcp_server: a standalone MCP server exposing tools/resources (e.g. xxx-mcp-server, github-mcp)
  mcp_gateway: MCP proxy/aggregator/registry/hub hosting or routing multiple servers
  sdk: MCP SDK or protocol library (python-sdk, typescript-sdk, mcp-go, FastMCP framework itself)
  client_host: MCP client/host app (IDE, desktop app, Cursor, Claude Desktop, mcp-remote)
  dev_tool: developer tooling such as MCP Inspector
  ai_platform: larger AI/agent/LLM platform with an MCP feature (Langflow, LiteLLM, MaxKB, Dify...)
  not_mcp: unrelated to MCP (false positive)
attack_target — who is harmed:
  server_side: the server process/host/backend/data is compromised
  agent_side: the LLM/agent is manipulated (tool poisoning, prompt injection, rug pull)
  client_side: the user's client machine is harmed by a malicious server/response
  mixed: clearly several
attacker_position — what the attacker controls:
  tool_caller: arguments of tool/resource/prompt requests (directly or by steering the agent)
  network: unauthenticated network access to the server transport/HTTP endpoint
  malicious_content: data the tool later processes (web page, file, issue text)
  malicious_server: attacker operates the MCP server
  local: local user/process on the same machine
  other
vuln_class — main weakness: command_injection, argument_injection (injecting CLI flags into an invoked program), code_injection (eval/exec/template code), sql_nosql_injection, other_injection (KQL, LDAP, GraphQL, XPath...), path_traversal, ssrf, missing_authentication, authorization_bypass (BOLA/IDOR, scope/permission/read-only bypass, cross-tenant), sandbox_or_allowlist_bypass (escape allowed dirs/commands/hosts lists), dos_resource_exhaustion (incl. ReDoS, crash), info_disclosure (secrets/tokens/stack traces leaked), dns_rebinding_origin_cors, session_token_issue, xss_ui, deserialization, prompt_injection_tool_poisoning, supply_chain, other
trigger_interface — where the malicious input enters: tools_call, resources_read, prompts_get, transport_http (auth, headers, session, CORS at the MCP endpoint), non_mcp_interface (separate web UI/REST API of a platform), client_side, unknown
blackbox_detectable — could a black-box tester trigger AND confirm it only via MCP requests to a self-deployed server (observing responses, out-of-band callbacks, files/processes on the test host, but no source code)?
  yes / partial (needs special setup, specific config, or hard to confirm) / no
needs_multi_step — does triggering require a sequence of calls that build state (e.g. create resource then use its id, init repo then operate)? yes / no / unknown
needs_multi_identity — does confirming it require two or more users/tokens/sessions (e.g. access another user's data)? yes / no / unknown
oracle — best black-box signal of success: oob_callback (DNS/HTTP callback), time_delay, file_canary (read/write a marker file outside allowed area), response_content (secret/data appears in reply), differential_identity (compare users), crash_or_timeout, http_response_check (status/headers e.g. CORS, missing auth), none_or_unclear
confidence — high / medium / low (low if the record is too vague)
reason_zh — ONE short sentence in Chinese explaining the key judgment.

Return ONLY a JSON array, one object per record, each with "id" plus all fields above. No markdown, no commentary."""

csv_lock = threading.Lock()


# ---------- 模型调用 ----------

def call_llm(model, user_content, timeout=180):
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_content}],
        "max_tokens": 4000,
        # 不要传 temperature：该中转收到 temperature 参数会返回 502 Upstream request failed
    })
    # 用 curl 而非 urllib：部分网络环境下 Python 的 SSL 握手会失败
    proc = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), BASE_URL,
         "-H", f"Authorization: Bearer {API_KEY}", "-H", "Content-Type: application/json",
         "-d", "@-", "-w", "\n%{http_code}"],
        input=payload, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"curl 失败({proc.returncode}): {proc.stderr.strip()[:200]}")
    body, _, status = proc.stdout.rpartition("\n")
    if status != "200":
        raise RuntimeError(f"HTTP {status}: {body[:200]}")
    return json.loads(body)["choices"][0]["message"]["content"]


def parse_array(text):
    """兼容 ```json 代码块、前后多余文字、单个对象等情况。"""
    text = re.sub(r"```(?:json)?", "", text).strip()
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        return json.loads(text[start:end + 1])
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return [json.loads(text[start:end + 1])]
    raise ValueError("回复中没有 JSON")


def validate(obj):
    """返回清洗后的标签，或在有非法值时返回 None。"""
    out = {}
    for field, allowed in SCHEMA.items():
        value = str(obj.get(field, "")).strip().lower()
        if value not in allowed:
            return None
        out[field] = value
    for field in FREE_TEXT:
        out[field] = str(obj.get(field, "")).strip()
    return out


# ---------- 构造输入 ----------

def describe(i, rec):
    desc = rec["description"] or ""
    if len(desc) > 1500:
        desc = desc[:1500] + " ...[truncated]"
    lines = [
        f"### id: {i}",
        f"ids: {', '.join(rec['cve'] + rec['ghsa'])}",
        f"title: {rec['summary']}",
        f"packages: {', '.join(rec['packages'][:8])}",
        f"ecosystems: {', '.join(rec['ecosystems'])}",
        f"cwes: {', '.join(rec['cwes'])}",
        f"severity: {rec['severity']} {rec['cvss']}",
        f"references: {' '.join(rec['urls'][:4])}",
        f"description: {desc}",
    ]
    return "\n".join(lines)


def label_batch(batch, model, max_attempts=6):
    """batch: [(key, rec)]；返回 {key: labels}。漏掉或非法的条目不在返回值里。"""
    content = "Label these records:\n\n" + "\n\n".join(describe(n, rec) for n, (_, rec) in enumerate(batch, 1))
    for attempt in range(1, max_attempts + 1):
        try:
            reply = call_llm(model, content)
            log_raw(model, [k for k, _ in batch], reply)
            results = {}
            for obj in parse_array(reply):
                try:
                    idx = int(obj.get("id")) - 1
                except (TypeError, ValueError):
                    continue
                if 0 <= idx < len(batch) and (labels := validate(obj)):
                    results[batch[idx][0]] = labels
            if results or attempt == max_attempts:
                return results
        except Exception as e:  # 网络、HTTP、解析错误都重试
            if attempt == max_attempts:
                log_error(f"[{model}] {[k for k, _ in batch]} 最终失败: {e}")
                return {}
        time.sleep(min(60, 2 ** attempt + random.random() * 2))
    return {}


def label_with_fallback(batch, model):
    """先整批请求；漏掉的条目再逐条单独请求。"""
    results = label_batch(batch, model)
    missing = [(k, r) for k, r in batch if k not in results]
    if missing and len(batch) > 1:
        for item in missing:
            results.update(label_batch([item], model))
    for k, _ in batch:
        if k not in results:
            log_error(f"[{model}] {k} 无法得到合法标签")
    return results


# ---------- 文件读写 ----------

def log_raw(model, keys, reply):
    with csv_lock, open(RAW_LOG, "a") as f:
        f.write(json.dumps({"time": time.strftime("%F %T"), "model": model, "keys": keys, "reply": reply}, ensure_ascii=False) + "\n")


def log_error(msg):
    print("  ! " + msg, flush=True)
    with csv_lock, open(ERR_LOG, "a") as f:
        f.write(time.strftime("%F %T ") + msg + "\n")


def save_labels(results, model):
    with csv_lock, open(LABELS, "a") as f:
        for key, labels in results.items():
            f.write(json.dumps({"key": key, "model": model, **labels}, ensure_ascii=False) + "\n")


def load_labels():
    """同一 key 以最后一次写入为准（复核结果会覆盖初次标注）。"""
    labels = {}
    if LABELS.exists():
        for line in open(LABELS):
            try:
                row = json.loads(line)
                labels[row["key"]] = row
            except (json.JSONDecodeError, KeyError):
                continue
    return labels


def load_candidates():
    rows = [json.loads(l) for l in open(CANDIDATES)]
    return {r["key"]: r for r in rows if not r["malicious_pkg"]}


# ---------- 主流程 ----------

def run(todo, model, batch_size, workers):
    batches = [todo[i:i + batch_size] for i in range(0, len(todo), batch_size)]
    done, t0 = 0, time.time()
    print(f"使用 {model} 标注 {len(todo)} 条，共 {len(batches)} 批，并发 {workers}")
    with ThreadPoolExecutor(workers) as ex:
        futures = [ex.submit(label_with_fallback, b, model) for b in batches]
        for fut in as_completed(futures):
            results = fut.result()
            save_labels(results, model)
            done += len(results)
            print(f"  进度 {done}/{len(todo)}  用时 {time.time() - t0:.0f}s", flush=True)


def export(cands, labels):
    rows = [{**cands[k], **{f"label_{f}": v for f, v in labels[k].items() if f != "key"}} for k in cands if k in labels]
    with open(DATA / "classified.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    if rows:
        with open(DATA / "classified.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow({k: "; ".join(map(str, v)) if isinstance(v, list) else v for k, v in r.items()})

    lines = [f"已标注 {len(rows)} / {len(cands)} 条\n"]
    for field in SCHEMA:
        lines.append(f"[{field}]")
        for value, n in Counter(r[f"label_{field}"] for r in rows).most_common():
            lines.append(f"  {value:32s} {n}")
        lines.append("")
    summary = "\n".join(lines)
    (DATA / "label_summary.txt").write_text(summary)
    print("\n" + summary)
    print(f"已导出 classified.jsonl / classified.csv / label_summary.txt 到 {DATA}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="只处理前 N 条未标注记录（试跑用）")
    ap.add_argument("--batch", type=int, default=5, help="每次请求包含的记录数")
    ap.add_argument("--workers", type=int, default=8, help="并发请求数")
    ap.add_argument("--review", action="store_true", help="用复核模型重标 confidence=low 的条目")
    ap.add_argument("--export-only", action="store_true", help="只导出，不调用模型")
    args = ap.parse_args()

    cands = load_candidates()
    labels = load_labels()

    if not args.export_only:
        if args.review:
            todo = [(k, cands[k]) for k, v in labels.items() if k in cands and v.get("confidence") == "low" and v.get("model") != REVIEW_MODEL]
            model = REVIEW_MODEL
        else:
            todo = [(k, r) for k, r in cands.items() if k not in labels]
            model = MODEL
        if args.limit:
            todo = todo[:args.limit]
        if todo:
            try:
                run(todo, model, args.batch, args.workers)
            except KeyboardInterrupt:
                print("\n已中断，已完成的结果已保存，重新运行即可继续。")
                sys.exit(1)
        else:
            print("没有需要标注的条目。")
        labels = load_labels()

    export(cands, labels)
    missing = len(cands) - sum(k in labels for k in cands)
    if missing:
        print(f"\n还有 {missing} 条未成功标注，可重新运行本脚本补齐（详见 {ERR_LOG.name}）。")


if __name__ == "__main__":
    main()
