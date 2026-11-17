"""LLM provider configuration for Calchas.

No API keys are baked into the package. Providers are resolved at runtime, in priority order:
  1. configure(...) — set by the CLI from --llm-base-url / --llm-api-key / --llm-model, or a --llm-config file.
  2. an external JSON file — env LLM_PROVIDERS_FILE, else LLM_PROVIDERS_DIR/<BATCH>.json, else LLM_PROVIDERS_DIR/default.json.
  3. otherwise none — LLM-using steps raise AllModelsUnavailable; run LLM-free with --no-llm-sink --no-agent --no-llm-plan.

A provider is {"name", "base_url", "api_key", "model"}. base_url is an OpenAI-compatible endpoint; a bare
".../v1" is accepted and "/chat/completions" is appended. In a JSON file, an api_key of "env:VARNAME" reads
that environment variable; any other value is used literally.
"""
from __future__ import annotations

import json
import os
import sys

_PROVIDERS: list[dict] = []
_AGENT_NAME: str = ""
_configured = False
_autoload_tried = False


def _normalize_base_url(url: str) -> str:
    """Accept either a full chat-completions endpoint or a bare base (".../v1"); return the full endpoint."""
    url = (url or "").strip()
    if not url:
        return ""
    if url.rstrip("/").endswith("chat/completions"):
        return url
    return url.rstrip("/") + "/chat/completions"


def _resolve_api_key(raw) -> str:
    """Resolve an api_key value: "env:VARNAME" reads that env var; anything else is the literal key."""
    raw = ("" if raw is None else str(raw)).strip()
    if raw.startswith("env:"):
        return os.environ.get(raw[4:].strip(), "").strip()
    return raw


def make_provider(base_url: str, api_key: str, model: str, name: str | None = None) -> dict:
    """Build one provider dict from explicit values (api_key used literally, already resolved)."""
    base = _normalize_base_url(base_url)
    model = (model or "").strip()
    return {"name": (name or model or "user").strip(),
            "base_url": base, "api_key": (api_key or "").strip(), "model": model}


def configure(providers, agent_provider: str | None = None) -> None:
    """Set the active providers (called once by the CLI before scanning). Keeps only entries with a base_url and model."""
    global _PROVIDERS, _AGENT_NAME, _configured
    _PROVIDERS = [p for p in (providers or []) if p.get("base_url") and p.get("model")]
    names = [p["name"] for p in _PROVIDERS]
    _AGENT_NAME = agent_provider if (agent_provider in names) else (names[0] if names else "")
    _configured = True


def get_providers() -> list[dict]:
    """Return the active providers. If none were configured, try the external JSON file once (lazy)."""
    global _autoload_tried
    if not _configured and not _PROVIDERS and not _autoload_tried:
        _autoload_tried = True
        loaded = _load_from_file()
        if loaded:
            configure(loaded[0], loaded[1])
    return _PROVIDERS


def get_agent_provider_name() -> str:
    get_providers()   # ensure lazy autoload has run
    return _AGENT_NAME


# ---------------------------------------------------------------------------
# external JSON file (optional; used by the batch deploy and power users)
# ---------------------------------------------------------------------------

def _candidate_config_paths() -> list[str]:
    paths = []
    explicit = os.environ.get("LLM_PROVIDERS_FILE", "").strip()
    if explicit:
        paths.append(explicit)
    cfg_dir = os.environ.get("LLM_PROVIDERS_DIR", "").strip()
    if cfg_dir:
        batch = os.environ.get("BATCH", "").strip()
        if batch:
            paths.append(os.path.join(cfg_dir, f"{batch}.json"))
        paths.append(os.path.join(cfg_dir, "default.json"))
    return paths


def load_file(path: str) -> tuple[list, str] | None:
    """Load (providers, agent_name) from a JSON file, or None on any problem (missing/invalid/empty)."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"[llm_config] failed to read {path} ({e})", file=sys.stderr, flush=True)
        return None
    providers = []
    for p in (data.get("providers") or []):
        base = _normalize_base_url(str(p.get("base_url", "")))
        model = str(p.get("model", "")).strip()
        if not base or not model:
            continue
        prov = {"name": str(p.get("name") or model).strip(),
                "base_url": base,
                "api_key": _resolve_api_key(p.get("api_key")),
                "model": model}
        # Optional provider-specific request fields merged into every chat-completion body,
        # e.g. {"enable_thinking": false} to turn off a model's default reasoning mode.
        extra = p.get("extra_body")
        if isinstance(extra, dict) and extra:
            prov["extra_body"] = extra
        providers.append(prov)
    if not providers:
        return None
    agent = str(data.get("agent_provider") or "").strip()
    return providers, agent


def _load_from_file() -> tuple[list, str] | None:
    for path in _candidate_config_paths():
        loaded = load_file(path)
        if loaded:
            print(f"[llm_config] loaded {path}: "
                  f"{[p['name'] + '(' + p['model'] + ')' for p in loaded[0]]}", file=sys.stderr, flush=True)
            return loaded
    return None
