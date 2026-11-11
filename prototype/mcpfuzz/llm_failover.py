"""多模型故障切换调度器：所有 LLM 调用的统一入口。

- PROVIDERS（见 llm_config）**按优先级排列**，PROVIDERS[0] 为主模型（批次 key 注入的那个）。
- 策略＝**优先级 + 失败冷却**（不再黏性赖在备用上）：每次 chat() 都从主模型起按优先级尝试；
  某 provider 失败就给它记一段冷却期（COOLDOWN_SEC），冷却中的 provider 在后续调用里被降到
  本轮最后（仍兜底尝试、但不抢优先、也不白等它的超时）；任一 provider 成功即**清除它的冷却**。
  → 主模型临时挂掉时自动用备用；冷却一过，下次调用又先试主模型，**一旦恢复立刻切回主模型**。
- current_provider()/mark_current_down(): 供多步智能体的 ChatOpenAI 路径共享同一「当前该优先用谁」
  的判断——主模型恢复后，智能体单例也随之重建回主模型。
- 一轮（所有 provider，含冷却中的）全失败 → 抛 AllModelsUnavailable（批量层据此暂停，--resume 续跑）。

设计原则：对调用方只暴露"拿到一个可用模型的回复"或"全挂了（AllModelsUnavailable）"两种结果，
把"换哪个模型 / 何时切回主模型"收敛在这里，与 sink 推断 / 规划兜底 / 序列智能体三处调用解耦。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

from mcpfuzz.llm_config import PROVIDERS


class AllModelsUnavailable(RuntimeError):
    """配置的所有大模型在一轮尝试里都失败——检测应暂停，等恢复后 --resume 续跑。"""


# 主/备切换的冷却期（秒）：某 provider 失败后，这段时间内把它降到最低优先级，不抢先、不白等其超时；
# 冷却一过便恢复「先试它」——主模型就是靠这个在恢复后被重新优先尝试、从而自动切回。
COOLDOWN_SEC = float(os.environ.get("LLM_PRIMARY_COOLDOWN_SEC", "60"))

_lock = threading.Lock()
# 每个 provider 的「冷却截止时刻」(time.monotonic 基准)；<=now 即可用。0 表示从未失败/已恢复。
_down_until = [0.0] * len(PROVIDERS)
_last_used_idx = 0   # 上次成功用的 provider 下标（仅用于打印"切回更高优先级"的恢复日志）


def _notify(msg: str) -> None:
    # 直接写 stderr：扫描日志会收录，便于事后看"何时切了哪个模型 / 何时切回主模型"。
    print(f"[llm] {msg}", file=sys.stderr, flush=True)


def _attempt_order(now: float) -> list[int]:
    """本次调用的尝试顺序：可用的按优先级在前；冷却中的按优先级排到最后（仍兜底尝试）。
    → 主模型没冷却时永远第一个试；主模型冷却中时备用优先，但主模型仍会在末尾被兜底尝试。"""
    n = len(PROVIDERS)
    avail = [i for i in range(n) if _down_until[i] <= now]
    cooling = [i for i in range(n) if _down_until[i] > now]
    return avail + cooling


def current_provider() -> dict:
    """返回此刻『该优先使用』的 provider（chat() 本次会第一个尝试的那个）。
    供 ChatOpenAI 智能体路径构建单例用：主模型恢复后这里即返回主模型，智能体随之切回。"""
    with _lock:
        order = _attempt_order(time.monotonic())
        return PROVIDERS[order[0] if order else 0]


def mark_current_down(reason: str = "") -> dict | None:
    """把当前『该优先用』的 provider 记为冷却，返回下一个该优先用的 provider。
    （保留接口兼容；主路径的失败冷却已在 chat() 内处理。）全部冷却中则返回 None。"""
    with _lock:
        now = time.monotonic()
        order = _attempt_order(now)
        if not order:
            return None
        cur = order[0]
        _down_until[cur] = now + COOLDOWN_SEC
        nxt_order = _attempt_order(time.monotonic())
        avail = [i for i in nxt_order if _down_until[i] <= time.monotonic()]
        new_idx = avail[0] if avail else None
        _notify(f"模型 {PROVIDERS[cur]['name']} 不可用（{reason[:120]}）→ "
                f"{'切换到 ' + PROVIDERS[new_idx]['name'] if new_idx is not None else '全部冷却中'}")
        return PROVIDERS[new_idx] if new_idx is not None else None


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
    """走故障切换拿一次补全：按优先级（主模型优先，冷却中的降到末尾）逐个尝试；
    成功 → 清除该 provider 冷却并返回（若切回了更高优先级模型，打恢复日志）；
    一轮全部失败 → 抛 AllModelsUnavailable。"""
    global _last_used_idx
    n = len(PROVIDERS)
    if n == 0:
        raise AllModelsUnavailable("未配置任何大模型（PROVIDERS 为空）")

    with _lock:
        order = _attempt_order(time.monotonic())
    errors = []
    for pos, idx in enumerate(order):
        prov = PROVIDERS[idx]
        try:
            out = _curl_one(prov, messages, max_tokens, timeout)
            with _lock:
                _down_until[idx] = 0.0            # 恢复：清除本 provider 冷却
                if idx < _last_used_idx:          # 切回了更高优先级（通常＝主模型恢复）
                    _notify(f"模型 {prov['name']} 已恢复，切回（更高优先级）")
                _last_used_idx = idx
            return out
        except _ProviderError as e:
            errors.append(f"{prov['name']}:{e}")
            with _lock:
                _down_until[idx] = time.monotonic() + COOLDOWN_SEC   # 失败：进入冷却
            if pos < len(order) - 1:
                nxt = PROVIDERS[order[pos + 1]]
                _notify(f"模型 {prov['name']} 失败（{str(e)[:100]}）→ 尝试 {nxt['name']}")
            continue
    raise AllModelsUnavailable("配置的所有大模型均不可用：" + " | ".join(errors))


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    """system+user 两段式补全的便捷封装（旧 llmclient.complete 的等价入口）。"""
    return chat([{"role": "system", "content": system},
                 {"role": "user", "content": user}], max_tokens=max_tokens, timeout=timeout)
