"""错误指纹：从响应/报错正文里识别"注入抵达了解释器"的弱证据（Tier-3）。

单独出现只作"疑似有"旁证，不进"确认"。各类别一组通用正则，不针对任何服务器。
"""
from __future__ import annotations

import re

from mcpfuzz.sink.types import AI, CI, CODE, PT, SSRF

_PATTERNS = {
    CI: [
        r"/bin/(?:sh|bash)\b",
        r"\bcommand not found\b",          # 不用裸 "not found"：会撞 "File not found"（文件不存在，非 shell）
        r"\bsyntax error near\b",            # bash: "syntax error near unexpected token"
        r"\bunexpected (?:EOF|end of file)\b",  # shell 专属;不含裸 "unexpected token"——JS/JSON 的
                                             # "Unexpected token '<'" 等解析错误与 shell 无关,会误判
        r"^sh:\s",
    ],
    AI: [
        r"\bunknown option\b",
        r"\bunrecognized option\b",
        r"\bunknown (?:flag|switch)\b",
        r"\bunexpected argument\b",
        # 不含 "invalid option"：应用层枚举校验也用这句（"Invalid option: expected one of ..."），会误判
    ],
    # 路径穿越**不**走错误指纹弱证据：响应里出现 ENOENT / "No such file" / permission denied
    # 只证明"服务端拿这个值去开了个文件/路径但失败了"，**不**证明越界访问真的发生（载荷常被
    # 喷进非路径参数也会产生这类报错）。PT 一律 fail-closed：仅凭正向实据确认——
    # inband 读回越界文件内容签名（passwd/key），或写后回读落地 canary（见 executor）。
    SSRF: [
        r"\b(?:ECONNREFUSED|connection refused)\b",
        r"\b(?:ETIMEDOUT|ESOCKETTIMEDOUT)\b",
        r"\btimed out\b",                       # "Request/connection/operation timed out"（含 SDK 封装超时）
        r"\bREQUEST_TIMEOUT\b",                  # 代码级超时标记（SdkError | code=REQUEST_TIMEOUT 等）
        r"\bno route to host\b",
        r"\bfetch failed\b",                    # Node undici fetch() 运行时失败：已发起外连、网络层失败
                                                # （区别于过滤器前置拒绝如 "Blocked URL"——那不触网，不匹配）
        # DNS 解析/连接发起失败：证明我们给的值确实被当作主机名/URL 交给了网络客户端
        r"\b(?:ENOTFOUND|EAI_AGAIN)\b",
        r"\bgetaddrinfo\b",
        r"\bName or service not known\b",
        r"\bnodename nor servname\b",
        r"\bfailed to (?:resolve|establish a? ?new connection)\b",
        r"\bMax retries exceeded with url\b",             # requests 库打到我们 host 的典型报错
    ],
    # 代码注入**只作弱证据**（→ 疑似，不单独定案；确认靠 L2 越域回显）。
    # 取各解释器/模板引擎抵达并报错的高信号 traceback，通用、不针对任何服务器。
    # 刻意不收 "TypeError"/"Unexpected token" 等过泛词（JSON/JS 解析也产生，会误判）。
    CODE: [
        r"Traceback \(most recent call last\)",            # Python 解释器栈
        r"\bSyntaxError\b", r"\bNameError\b",               # Python eval/exec
        r"\binvalid syntax\b",
        r"\bunexpected EOF while parsing\b",
        r"\bSympifyError\b", r"\bcould not parse\b",        # SymPy parse_expr
        r"\bParseException\b",
        r"\bjinja2\.exceptions\.", r"\bTemplateSyntaxError\b",  # Jinja2/模板引擎
        r"\bat new Script\b", r"\bevalmachine\b",           # Node vm/eval 栈帧
    ],
}

_COMPILED = {k: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in v] for k, v in _PATTERNS.items()}


def error_fingerprint(text: str, vuln_class: str) -> str | None:
    """命中则返回匹配到的片段（最多 120 字），否则 None。"""
    if not text:
        return None
    for rx in _COMPILED.get(vuln_class, []):
        m = rx.search(text)
        if m:
            i = m.start()
            return text[max(0, i - 20): i + 100]
    return None
