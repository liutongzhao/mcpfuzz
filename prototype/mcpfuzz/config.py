"""配置：命令行参数 > 环境变量 > 配置文件 > 内置默认，逐层合并。

CLI 只负责把 argparse.Namespace 交给 build_settings；大模型 API key/中转地址仍留在
llm_config.py（已 gitignore），不进这份通用配置。
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
    # 判定 / 网络
    oob_callback: str = DEFAULT_OOB_CALLBACK
    oob_query: str = DEFAULT_OOB_QUERY
    poll_rounds: int = 3
    poll_interval: float = 2.0
    timeout: float = 30.0
    retries: int = 3
    delay: float = 0.0
    # 大模型
    llm_sink: bool = True
    llm_plan: bool = True
    llm_workers: int = 6
    use_cache: bool = True
    # 范围
    only_tools: tuple = ()
    exclude_tools: tuple = ()
    only_sinks: tuple = ()
    max_payloads: int | None = None
    # 输出
    out_dir: str = "runs"
    run_name: str | None = None
    format: str = "auto"       # auto|rich|plain|json（auto：TTY 用 rich，否则 plain）
    verbose: int = 0
    quiet: bool = False
    # 安全 / 伦理
    dry_run: bool = False
    assume_yes: bool = False
    # 网关（经 mcphub 检测，可选）：给了 gateway_base 才启用；检测逻辑不变，仅加重置/冷启动适配
    gateway_base: str | None = None        # mcphub 基址，如 http://host:3000
    gateway_token: str | None = None       # 管理 token（x-auth-token），与 password 二选一
    gateway_user: str = "admin"
    gateway_password: str | None = None
    gateway_server: str | None = None      # 该目标在网关里的后端名；默认从 /mcp/{server} URL 解析
    gateway_reset: str = "off"             # off|before|after|both：扫描前/后用 reload 重置后端
    gateway_idle_ms: int = 300000          # 网关空闲关闭超时（按需启动）；用作首连冷启动预算


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
    """args 为 argparse.Namespace；只有显式给出（非 None）的属性才会覆盖上一层。"""
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
