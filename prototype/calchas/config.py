"""Config: command-line args > environment variables > config file > built-in defaults, merged layer by layer.

The CLI only hands the argparse.Namespace to build_settings; the LLM API key / relay address still live in
llm_config.py (already gitignored), not in this generic config.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

DEFAULT_OOB_CALLBACK = os.environ.get("MCP_OOB_CALLBACK", "http://43.133.80.249:9100")
DEFAULT_OOB_QUERY = os.environ.get("MCP_OOB_QUERY", "http://43.133.80.249:9100/__hits")


@dataclass
class Settings:
    # verdict / network
    oob_callback: str = DEFAULT_OOB_CALLBACK
    oob_query: str = DEFAULT_OOB_QUERY
    poll_rounds: int = 3
    poll_interval: float = 2.0
    timeout: float = 30.0
    retries: int = 3
    delay: float = 0.0
    tool_timeout: float = 900.0   # per-tool total-time watchdog (seconds): if a tool's total time from sequence
                                   # construction to attack verdict exceeds it, abandon the tool, record its
                                   # parameters as "not tested", and move to the next, to avoid stalling the whole
                                   # batch. Default 15 minutes; <=0 disables the watchdog. Only effective on a Unix main thread (which is the case inside the container).
    # LLM
    llm_sink: bool = True
    llm_plan: bool = True
    sequence_agent: bool = True    # the sequence-construction agent (runs the loop live to produce a recipe); if off, falls back to one-shot planning
    agent_rounds: int = 6          # the agent's max repair rounds (recursion_limit = max(10, rounds*6))
    llm_workers: int = 6
    use_cache: bool = True
    # scope
    only_tools: tuple = ()
    exclude_tools: tuple = ()
    only_sinks: tuple = ()
    max_payloads: int | None = None
    # output
    out_dir: str = "runs"
    run_name: str | None = None
    format: str = "auto"       # auto|rich|plain|json (auto: rich on a TTY, else plain)
    verbose: int = 0
    quiet: bool = False
    # safety / ethics
    dry_run: bool = False
    assume_yes: bool = False
    # gateway (detect via mcphub, optional): enabled only when gateway_base is given; the detection logic is unchanged, only reset/cold-start adaptation is added
    gateway_base: str | None = None        # mcphub base, e.g. http://host:3000
    gateway_token: str | None = None       # admin token (x-auth-token), alternative to password
    gateway_user: str = "admin"
    gateway_password: str | None = None
    gateway_server: str | None = None      # this target's backend name in the gateway; default parsed from the /mcp/{server} URL
    gateway_reset: str = "off"             # off|before|after|both: reset the backend via reload before/after the scan
    gateway_lifecycle: bool = True         # enable only during detection: enable the backend before the scan, disable it after to kill the process and free resources,
                                           # avoiding a crowd of persistent stdio backends overwhelming the gateway during batch detection
    gateway_idle_ms: int = 300000          # gateway idle-shutdown timeout (on-demand start); used as the first-connect cold-start budget
    gateway_launch_map: str | None = None  # [only for large-scale whole-ecosystem batches] a JSON file of backend-name -> launch command. Only given to enter
                                           # the "add the backend before the scan -> scan -> delete after" mode; if not given (dataset scanning) it keeps
                                           # the pre-registered backend enable -> scan -> disable, and never deletes.
    after_target_cmd: str | None = None    # a local command run after each target is scanned (lifecycle already disabled);
                                           # a generic finishing hook, typically to clean the gateway container's npm/uv cache to avoid filling the disk.
                                           # Run at the safe moment when "the backend process has stopped", so it does not interrupt any cold-start install
    after_target_cmd_timeout: float = 120.0  # timeout for the above command (seconds)


def _load_toml(path: str | Path) -> dict:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    flat: dict = {}
    for v in data.values():
        if isinstance(v, dict):
            flat.update(v)
        else:
            flat[v] = v
    return flat


def build_settings(args) -> Settings:
    """args is an argparse.Namespace; only explicitly-given (non-None) attributes override the previous layer."""
    settings = Settings()

    cfg_path = getattr(args, "config", None)
    if cfg_path:
        for k, v in _load_toml(cfg_path).items():
            if hasattr(settings, k):
                setattr(settings, k, v)

    for f in fields(settings):
        if not hasattr(args, f.name):
            continue
        val = getattr(args, f.name)
        if val is None:
            continue
        if isinstance(val, list):
            val = tuple(val)
        setattr(settings, f.name, val)
    return settings
