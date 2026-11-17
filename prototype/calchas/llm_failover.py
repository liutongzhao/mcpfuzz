"""Multi-model failover scheduler: the single entry point for all LLM calls.

- PROVIDERS (see llm_config) are **ordered by priority**, PROVIDERS[0] is the primary model (the one the batch key is injected for).
- Strategy = **priority + failure cooldown** (no longer stickily staying on a backup): every chat() tries from
  the primary by priority; a provider that fails is given a cooldown period (COOLDOWN_SEC), during which it is
  demoted to last in subsequent calls (still tried as a fallback, but without priority and without waiting on its
  timeout); any provider's success **clears its cooldown**.
  -> when the primary is temporarily down, a backup is used automatically; once the cooldown passes, the next
  call tries the primary first again, **switching back to the primary immediately once it recovers**.
- current_provider()/mark_current_down(): expose "who should be preferred now" to callers that need it (e.g. diagnostics/logs).
- agent_provider(): the provider (minimax) the sequence-construction agent (the ChatOpenAI path) uses **fixedly**,
  decoupled from the three-tier switching above — that path does no cascading fallback within a single run and is
  bound to the most stable model, to avoid a primary-model 429 beating sequence construction into fallback (no LLM).
  Sink inference / planning still go through chat()'s three-tier switching, unaffected.
- A whole round (all providers, incl. those in cooldown) failing -> raise AllModelsUnavailable (the batch layer pauses on it, resume with --resume).

Design principle: expose to callers only two outcomes — "got a reply from an available model" or "all down
(AllModelsUnavailable)" — converging "which model to switch to / when to switch back to the primary" here,
decoupled from the three call sites (sink inference / planning fallback / sequence agent).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

from calchas.llm_config import PROVIDERS


class AllModelsUnavailable(RuntimeError):
    """All configured models failed within one round of attempts — detection should pause, resume with --resume after recovery."""


# The primary/backup switching cooldown (seconds): after a provider fails, it is demoted to lowest priority for
# this period, not tried first and not waited on for its timeout; once the cooldown passes it is "tried first"
# again — this is how the primary gets re-prioritized after recovery and thus auto-switches back.
COOLDOWN_SEC = float(os.environ.get("LLM_PRIMARY_COOLDOWN_SEC", "60"))

_lock = threading.Lock()
# Each provider's "cooldown deadline" (time.monotonic basis); <=now means available. 0 means never failed / recovered.
_down_until = [0.0] * len(PROVIDERS)
_last_used_idx = 0   # the index of the last successfully-used provider (only for printing the "switched back to a higher priority" recovery log)


def _notify(msg: str) -> None:
    # Write straight to stderr: the scan log records it, so one can see "when which model was switched / when it switched back to the primary".
    print(f"[llm] {msg}", file=sys.stderr, flush=True)


def _attempt_order(now: float) -> list[int]:
    """The attempt order for this call: available ones first by priority; those in cooldown last by priority (still tried as fallbacks).
    -> the primary is always tried first when not in cooldown; when the primary is in cooldown, backups go first but the primary is still tried last as a fallback."""
    n = len(PROVIDERS)
    avail = [i for i in range(n) if _down_until[i] <= now]
    cooling = [i for i in range(n) if _down_until[i] > now]
    return avail + cooling


def current_provider() -> dict:
    """Return the provider that "should be preferred" right now (the one chat() will try first this time).
    Used to build the singleton for the ChatOpenAI agent path: after the primary recovers this returns the primary, and the agent switches back accordingly."""
    with _lock:
        order = _attempt_order(time.monotonic())
        return PROVIDERS[order[0] if order else 0]


def agent_provider() -> dict:
    """The provider the sequence-construction agent (the ChatOpenAI path) uses **fixedly**, decoupled from chat()'s three-tier switching.
    Returns the one named by llm_config.AGENT_PROVIDER_NAME (minimax); if not found, falls back to the last of PROVIDERS (the fallback tier).
    This path does no cascading fallback within a single agent run, so it is bound to the most stable model, to avoid a primary-model 429
    beating sequence construction into fallback (no LLM). Sink inference / planning are unaffected and still go through current_provider()/chat()'s priority+cooldown switching."""
    from calchas.llm_config import AGENT_PROVIDER_NAME
    for p in PROVIDERS:
        if p.get("name") == AGENT_PROVIDER_NAME:
            return p
    return PROVIDERS[-1] if PROVIDERS else {}


def mark_current_down(reason: str = "") -> dict | None:
    """Mark the currently "preferred" provider as in cooldown, returning the next provider to prefer.
    (Kept for interface compatibility; the main path's failure cooldown is already handled inside chat().) Returns None if all are in cooldown."""
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
        _notify(f"model {PROVIDERS[cur]['name']} unavailable ({reason[:120]}) -> "
                f"{'switching to ' + PROVIDERS[new_idx]['name'] if new_idx is not None else 'all in cooldown'}")
        return PROVIDERS[new_idx] if new_idx is not None else None


class _ProviderError(RuntimeError):
    pass


def _curl_one(prov: dict, messages: list, max_tokens: int, timeout: int) -> str:
    """Send one chat completion to a single provider. Return the body on success, raise _ProviderError on failure."""
    payload = json.dumps({"model": prov["model"], "messages": messages, "max_tokens": max_tokens})
    try:
        p = subprocess.run(
            ["curl", "-sS", "-m", str(timeout), prov["base_url"],
             "-H", f"Authorization: Bearer {prov['api_key']}", "-H", "Content-Type: application/json",
             "-d", "@-", "-w", "\n%{http_code}"],
            input=payload, capture_output=True, text=True,
        )
    except Exception as e:  # noqa: BLE001
        raise _ProviderError(f"curl exception: {e}") from e
    if p.returncode != 0:
        raise _ProviderError(f"curl failed ({p.returncode}): {p.stderr.strip()[:160]}")
    body, _, code = p.stdout.rpartition("\n")
    if code != "200":
        raise _ProviderError(f"HTTP {code}: {body[:160]}")
    try:
        return json.loads(body)["choices"][0]["message"]["content"]
    except Exception as e:  # noqa: BLE001
        raise _ProviderError(f"response parse failed: {str(e)[:120]} / {body[:120]}") from e


def chat(messages: list, max_tokens: int = 2000, timeout: int = 120) -> str:
    """Get one completion through failover: try each by priority (primary first, those in cooldown demoted to last);
    on success -> clear that provider's cooldown and return (log a recovery if it switched back to a higher-priority model);
    a whole round all failing -> raise AllModelsUnavailable."""
    global _last_used_idx
    n = len(PROVIDERS)
    if n == 0:
        raise AllModelsUnavailable("no model configured (PROVIDERS is empty)")

    with _lock:
        order = _attempt_order(time.monotonic())
    errors = []
    for pos, idx in enumerate(order):
        prov = PROVIDERS[idx]
        try:
            out = _curl_one(prov, messages, max_tokens, timeout)
            with _lock:
                _down_until[idx] = 0.0            # recovery: clear this provider's cooldown
                if idx < _last_used_idx:          # switched back to a higher priority (usually = the primary recovered)
                    _notify(f"model {prov['name']} recovered, switched back (higher priority)")
                _last_used_idx = idx
            return out
        except _ProviderError as e:
            errors.append(f"{prov['name']}:{e}")
            with _lock:
                _down_until[idx] = time.monotonic() + COOLDOWN_SEC   # failure: enter cooldown
            if pos < len(order) - 1:
                nxt = PROVIDERS[order[pos + 1]]
                _notify(f"model {prov['name']} failed ({str(e)[:100]}) -> trying {nxt['name']}")
            continue
    raise AllModelsUnavailable("all configured models are unavailable: " + " | ".join(errors))


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    """Convenience wrapper for a two-part system+user completion (equivalent entry to the old llmclient.complete)."""
    return chat([{"role": "system", "content": system},
                 {"role": "user", "content": user}], max_tokens=max_tokens, timeout=timeout)
