"""多模型故障切换调度器：所有 LLM 调用的统一入口。

- PROVIDERS（见 llm_config）按优先级排列；维护一个进程内"黏性游标"指向当前在用的模型。
- chat(): 从游标起逐个尝试，当前模型失败（限流/5xx/超时/连不上/非 200）就切下一个并把游标
  移到成功的那个（之后不再反复打死的模型）。一轮全部失败 → 抛 AllModelsUnavailable。
- current_provider()/mark_current_down(): 供多步智能体的 ChatOpenAI 路径共享同一游标与切换逻辑。

设计原则：对调用方只暴露"拿到一个可用模型的回复"或"全挂了（AllModelsUnavailable）"两种结果，
把"换哪个模型"收敛在这里，与 sink 推断 / 规划兜底 / 序列智能体三处调用解耦。
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading

from mcpfuzz.llm_config import PROVIDERS


class AllModelsUnavailable(RuntimeError):
    """配置的所有大模型在一轮尝试里都失败——检测应暂停，等恢复后 --resume 续跑。"""


_lock = threading.Lock()
_cursor = 0   # 当前优先使用的 provider 下标（黏性：切到可用的那个后就停在那）


def _notify(msg: str) -> None:
    # 直接写 stderr：扫描日志会收录，便于事后看"何时切了哪个模型"。
    print(f"[llm] {msg}", file=sys.stderr, flush=True)


def current_provider() -> dict:
    """返回当前游标指向的 provider（供 ChatOpenAI 路径构建用）。"""
    with _lock:
        return PROVIDERS[_cursor % len(PROVIDERS)]


def mark_current_down(reason: str = "") -> dict | None:
    """把当前 provider 标记为不可用、游标前移一位，返回新的 provider。
    若已绕回起点（全部试过）返回 None——调用方据此判定"全挂"。"""
    global _cursor
    with _lock:
        n = len(PROVIDERS)
        old = PROVIDERS[_cursor % n]
        _cursor = (_cursor + 1) % n
        new = PROVIDERS[_cursor % n]
        _notify(f"模型 {old['name']} 不可用（{reason[:120]}）→ 切换到 {new['name']}")
        return new


class _ProviderError(RuntimeError):
    pass


def _curl_one(prov: dict, messages: list, max_tokens: int, timeout: int) -> str:
    """对单个 provider 发一次 chat 补全。成功返回正文，失败抛 _ProviderError。"""
    payload = json.dumps({"model": prov["model"], "messages": messages, "max_tokens": max_tokens})
    try:
        p = subprocess.run(
            ["curl", "-sS", "-m", str(timeout), prov["base_url"],
             "-H", f"Authorization: Bearer {prov['api_key']}", "-H", "Content-Type: application/json",
             "-d", "@-", "-w", "\n%{http_code}"],
            input=payload, capture_output=True, text=True,
        )
    except Exception as e:  # noqa: BLE001
        raise _ProviderError(f"curl 异常：{e}") from e
    if p.returncode != 0:
        raise _ProviderError(f"curl 失败({p.returncode})：{p.stderr.strip()[:160]}")
    body, _, code = p.stdout.rpartition("\n")
    if code != "200":
        raise _ProviderError(f"HTTP {code}：{body[:160]}")
    try:
        return json.loads(body)["choices"][0]["message"]["content"]
    except Exception as e:  # noqa: BLE001
        raise _ProviderError(f"响应解析失败：{str(e)[:120]} / {body[:120]}") from e


def chat(messages: list, max_tokens: int = 2000, timeout: int = 120) -> str:
    """走故障切换拿一次补全。从黏性游标起逐个 provider 尝试；成功则把游标停在它上面并返回；
    一轮全部失败 → 抛 AllModelsUnavailable。"""
    global _cursor
    n = len(PROVIDERS)
    if n == 0:
        raise AllModelsUnavailable("未配置任何大模型（PROVIDERS 为空）")
    start = _cursor
    errors = []
    for i in range(n):
        idx = (start + i) % n
        prov = PROVIDERS[idx]
        try:
            out = _curl_one(prov, messages, max_tokens, timeout)
            with _lock:
                _cursor = idx     # 黏性：记住这个可用的，下次从它开始
            return out
        except _ProviderError as e:
            errors.append(f"{prov['name']}:{e}")
            nxt = PROVIDERS[(idx + 1) % n]
            if i < n - 1:
                _notify(f"模型 {prov['name']} 失败（{str(e)[:100]}）→ 尝试 {nxt['name']}")
            continue
    raise AllModelsUnavailable("配置的所有大模型均不可用：" + " | ".join(errors))


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    """system+user 两段式补全的便捷封装（旧 llmclient.complete 的等价入口）。"""
    return chat([{"role": "system", "content": system},
                 {"role": "user", "content": user}], max_tokens=max_tokens, timeout=timeout)
