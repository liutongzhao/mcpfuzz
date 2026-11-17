"""Multi-model failover scheduler: the single entry point for all LLM calls.

- Providers come from llm_config.get_providers() (configured at runtime; see llm_config), ordered by priority,
  providers[0] being the primary.
- Strategy = **priority + failure cooldown** (no sticky staying on a backup): every chat() tries from the
  primary by priority; a provider that fails gets a cooldown (COOLDOWN_SEC), during which it is demoted to last
  in subsequent calls (still tried as a fallback, but without priority and without waiting on its timeout); any
  provider's success clears its cooldown.
  -> when the primary is temporarily down, a backup is used automatically; once the cooldown passes, the next
  call tries the primary first again, switching back to it immediately once it recovers.
- current_provider()/mark_current_down(): expose "who should be preferred now" to callers that need it.
- agent_provider(): the provider the sequence-construction agent (the ChatOpenAI path) uses **fixedly**,
  decoupled from the three-tier switching above.
- No provider configured, or a whole round (all providers) failing -> raise AllModelsUnavailable (the batch
  layer pauses on it, resume with --resume).

Design principle: expose to callers only "got a reply from an available model" or "all down
(AllModelsUnavailable)", converging "which model to switch to / when to switch back" here.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

from calchas import llm_config


class AllModelsUnavailable(RuntimeError):
    """No provider configured, or all failed within one round — detection should pause, resume with --resume after recovery."""


# The primary/backup switching cooldown (seconds): after a provider fails, it is demoted to lowest priority for
# this period; once the cooldown passes it is tried first again — this is how the primary is re-prioritized after recovery.
COOLDOWN_SEC = float(os.environ.get("LLM_PRIMARY_COOLDOWN_SEC", "60"))

_lock = threading.Lock()
# Each provider's cooldown deadline (time.monotonic basis), keyed by provider name; absent/<=now means available.
_cooldown: dict[str, float] = {}
_last_used_name = ""   # the last successfully-used provider name (only for the "switched back to a higher priority" log)


def _notify(msg: str) -> None:
    # Write straight to stderr: the scan log records it, so one can see when which model was switched / switched back.
    print(f"[llm] {msg}", file=sys.stderr, flush=True)


def _attempt_order(providers: list, now: float) -> list:
    """The attempt order: available ones first (in priority order), those in cooldown last (still tried as fallbacks)."""
    avail = [p for p in providers if _cooldown.get(p["name"], 0.0) <= now]
    cooling = [p for p in providers if _cooldown.get(p["name"], 0.0) > now]
    return avail + cooling


def current_provider() -> dict:
    """Return the provider that should be preferred right now (the one chat() will try first)."""
    with _lock:
        provs = llm_config.get_providers()
        order = _attempt_order(provs, time.monotonic())
        return order[0] if order else (provs[0] if provs else {})


def agent_provider() -> dict:
    """The provider the sequence-construction agent (the ChatOpenAI path) uses fixedly.
    Returns the one named by llm_config.get_agent_provider_name(); if not found, falls back to the last provider."""
    provs = llm_config.get_providers()
    name = llm_config.get_agent_provider_name()
    for p in provs:
        if p.get("name") == name:
            return p
    return provs[-1] if provs else {}


def mark_current_down(reason: str = "") -> dict | None:
    """Mark the currently preferred provider as in cooldown, returning the next provider to prefer (or None if all are in cooldown)."""
    with _lock:
        provs = llm_config.get_providers()
        now = time.monotonic()
        order = _attempt_order(provs, now)
        if not order:
            return None
        cur = order[0]
        _cooldown[cur["name"]] = now + COOLDOWN_SEC
        avail = [p for p in _attempt_order(provs, time.monotonic())
                 if _cooldown.get(p["name"], 0.0) <= time.monotonic()]
        nxt = avail[0] if avail else None
        _notify(f"model {cur['name']} unavailable ({reason[:120]}) -> "
                f"{'switching to ' + nxt['name'] if nxt is not None else 'all in cooldown'}")
        return nxt


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
    """Get one completion through failover: try each by priority (primary first, those in cooldown last);
    on success -> clear that provider's cooldown and return; a whole round failing -> raise AllModelsUnavailable."""
    global _last_used_name
    provs = llm_config.get_providers()
    if not provs:
        raise AllModelsUnavailable(
            "no LLM provider configured; pass --llm-base-url / --llm-api-key / --llm-model "
            "(or a --llm-config file), or run LLM-free with --no-llm-sink --no-agent --no-llm-plan")

    with _lock:
        order = _attempt_order(provs, time.monotonic())
    prio = {p["name"]: i for i, p in enumerate(provs)}   # priority position, for the "switched back" log
    errors = []
    for pos, prov in enumerate(order):
        try:
            out = _curl_one(prov, messages, max_tokens, timeout)
            with _lock:
                _cooldown.pop(prov["name"], None)            # recovery: clear this provider's cooldown
                if _last_used_name and prio.get(prov["name"], 0) < prio.get(_last_used_name, 0):
                    _notify(f"model {prov['name']} recovered, switched back (higher priority)")
                _last_used_name = prov["name"]
            return out
        except _ProviderError as e:
            errors.append(f"{prov['name']}:{e}")
            with _lock:
                _cooldown[prov["name"]] = time.monotonic() + COOLDOWN_SEC   # failure: enter cooldown
            if pos < len(order) - 1:
                _notify(f"model {prov['name']} failed ({str(e)[:100]}) -> trying {order[pos + 1]['name']}")
            continue
    raise AllModelsUnavailable("all configured LLM providers are unavailable: " + " | ".join(errors))


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    """Convenience wrapper for a two-part system+user completion."""
    return chat([{"role": "system", "content": system},
                 {"role": "user", "content": user}], max_tokens=max_tokens, timeout=timeout)
