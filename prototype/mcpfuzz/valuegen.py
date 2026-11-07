"""约束感知的参数值生成（见 docs/参数值生成优化方案.md）。

统一服务 P2（合法填充值）与 P4（约束感知载荷）——二者都是"生成满足参数声明约束的值"，
P4 只多一步"在合法骨架里嵌载荷"。全部由参数自己在 JSON Schema 里声明的约束
（pattern/format/type/长度/数值界）驱动，**不针对任何服务/参数名特判**。

- benign_value(param)：产一个满足约束的良性值（确定性阶梯；LLM 仅作预留兜底，默认不启用）。
- inject_value(param, payload)：把攻击片段嵌进满足约束的合法骨架；参数被完全锁死（uuid/枚举/
  纯数值/无自由位）→ 返回 None（如实表示"此参数扛不住这类注入"，不强塞、不算漏报）。
"""
from __future__ import annotations

import re
import secrets

_PATH_KEYS = ("path", "file", "dir", "folder", "location", "dest", "filepath")
_URL_KEYS = ("url", "uri", "endpoint", "link", "href")
# 目录型线索：命中则填"唯一的新目录路径"（让工具自己 makedirs），否则按文件填
_DIR_KEYS = ("dir", "folder", "directory")
# 限返回量型数值线索：命中则填"大值"（仍夹进声明的 [min,max]），避免最小值 1 把可观测输出截断、
# 致判定致盲（如 fetch 类 max_length=1 把 SSRF 元数据回显截成 1 字符 → 漏报）。只认"限制返回量"
# 语义；刻意不含 index/offset/start（填大反而跳过内容）、timeout/delay/retry/port（填大有副作用）。
_LIMIT_KEYS = ("max_length", "maxlength", "max_len", "maxchars", "max_chars", "maxbytes", "max_bytes",
               "maxresults", "max_results", "num_results", "max_tokens", "maxtokens", "max_items",
               "maxitems", "page_size", "pagesize", "per_page", "perpage", "max_size", "maxsize",
               "limit", "length", "truncate", "top_k", "topk", "top_n")
_LIMIT_DESC = ("maximum number of", "max number of", "number of characters", "characters to return",
               "maximum length", "max length", "number of results", "truncat")


def _path_filler(param) -> str:
    """路径型参数的良性填充值。两条铁律：
    1) 每次唯一（带随机 token）——绝不用跨工具/跨运行共享的写死常量，否则会出现
       "A 工具把它写成文件、B 工具又当目录用" 的互踩（见 output_dir 踩到 consciousness 残留）。
    2) 按原型区分目录/文件——目录型给不存在的唯一目录(工具自己建)，文件型给唯一文件路径。
    代价：填充值不再逐参数确定(引入随机)，但这是避免残留污染的必要取舍。"""
    name = (param.path or "").lower()
    desc = (getattr(param, "description", "") or "").lower()
    is_dir = any(k in name for k in _DIR_KEYS) or "directory" in desc or "folder" in desc
    tok = secrets.token_hex(4)
    return f"/tmp/mcpfuzz_d{tok}" if is_dir else f"/tmp/mcpfuzz_f{tok}.bin"

# format 关键字 → 一个合法良性值（JSON Schema 标准词汇表，对所有服务一视同仁）
_FORMAT_VALUES = {
    "uuid": "00000000-0000-4000-8000-000000000000",
    "guid": "00000000-0000-4000-8000-000000000000",
    "date-time": "2026-01-01T00:00:00Z",
    "date": "2026-01-01",
    "time": "00:00:00",
    "duration": "PT1S",
    "email": "test@example.com",
    "idn-email": "test@example.com",
    "uri": "http://example.com/",
    "url": "http://example.com/",
    "iri": "http://example.com/",
    "uri-reference": "http://example.com/",
    "hostname": "example.com",
    "idn-hostname": "example.com",
    "ipv4": "127.0.0.1",
    "ipv6": "::1",
    "byte": "dGVzdA==",
    "binary": "dGVzdA==",
    "password": "Passw0rd!",
    "json-pointer": "/x",
}

# 这些 format 刚性锁死，字符串注入无法承载 → inject_value 返 None
_RIGID_FORMATS = {"uuid", "guid", "date", "date-time", "time", "duration",
                  "email", "idn-email", "ipv4", "ipv6", "hostname", "idn-hostname", "byte", "binary"}

_META = set("[](){}.*+?|^$\\")


def _literal_prefix(pattern: str) -> str:
    """从正则里取出"必须的字面前缀"：^ 之后到第一个正则元字符为止。
    如 ^proj-[a-z0-9]+$ → 'proj-'；^user_\\d+ → 'user_'。覆盖最常见的"must start with X"。"""
    if not pattern:
        return ""
    p = pattern[1:] if pattern.startswith("^") else pattern
    out = []
    for c in p:
        if c in _META:
            break
        out.append(c)
    return "".join(out)


def _pattern_injectable(pattern: str) -> bool:
    """pattern 是否存在"自由位"可放载荷：有字面前缀，或含宽松量词（*/+/.*/\\w 等）。
    纯定长字符类（如 ^[0-9]{6}$）视为无自由位。"""
    if _literal_prefix(pattern):
        return True
    return any(tok in pattern for tok in (".*", ".+", "\\w", "\\S", "[^", "*", "+"))


def _enforce(param, v):
    """对【生成的】值做长度/数值界收尾，保证其本身合法（不动 default/example/enum 等权威值）。"""
    if isinstance(v, str):
        if getattr(param, "min_length", None) and len(v) < param.min_length:
            v = v + "a" * (param.min_length - len(v))
        if getattr(param, "max_length", None) and len(v) > param.max_length:
            v = v[: param.max_length]
        return v
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        lo, hi = getattr(param, "minimum", None), getattr(param, "maximum", None)
        step = 1 if param.type == "integer" else 0.1
        # 把排他边界折算成"含界的合法下/上限"，再把 v 夹进 [lo_ok, hi_ok]
        lo_ok = (lo + step) if (lo is not None and getattr(param, "exclusive_min", False)) else lo
        hi_ok = (hi - step) if (hi is not None and getattr(param, "exclusive_max", False)) else hi
        if lo_ok is not None and v < lo_ok:
            v = lo_ok
        if hi_ok is not None and v > hi_ok:
            v = hi_ok
        mult = getattr(param, "multiple_of", None)
        if mult:
            k = round(v / mult) or 1
            cand = k * mult
            if lo_ok is not None and cand < lo_ok:   # 对齐倍数后别掉出下界
                cand = (int(lo_ok / mult) + 1) * mult
            v = cand
        if param.type == "integer":
            v = int(v)
    return v


_TYPE_DEFAULT = {"string": "test", "integer": 1, "number": 1, "boolean": True, "array": [], "object": {}}


def benign_value(param):
    """产一个满足参数声明约束的良性值。确定性阶梯：
    default/example/enum(权威) → format → pattern前缀 → 名字启发 → 类型兜底(并 _enforce 收尾)。"""
    name = (param.path or "").lower()
    stringy = param.type in ("string", "union", "unknown")
    pathlike = stringy and any(k in name for k in _PATH_KEYS)

    # 权威值：路径型相对默认值规避（保留原启发），否则 default/example/enum 直接用（已合法，不 _enforce）
    if pathlike and getattr(param, "default", None) in (None, ".", "", "./", "cwd"):
        return _path_filler(param)
    if getattr(param, "default", None) is not None:
        return param.default
    if getattr(param, "example", None) is not None:
        return param.example
    if param.enum:
        return param.enum[0]

    # 约束驱动的生成（过 _enforce 收尾）
    fmt = (getattr(param, "str_format", None) or "").lower()
    if fmt in _FORMAT_VALUES:
        return _enforce(param, _FORMAT_VALUES[fmt])
    pat = getattr(param, "pattern", None)
    if pat:
        pref = _literal_prefix(pat)
        if pref:
            return _enforce(param, pref + "x")

    # 名字启发（保留原 _fallback_literal 行为）
    if stringy:
        if pathlike:
            return _path_filler(param)
        if any(k in name for k in _URL_KEYS):
            return "http://example.com/"

    # 限返回量型数值参数：填大值（夹进声明界），别用最小值截断可观测输出致判定致盲
    if param.type in ("integer", "number"):
        desc = (getattr(param, "description", "") or "").lower()
        if any(k in name for k in _LIMIT_KEYS) or any(k in desc for k in _LIMIT_DESC):
            return _enforce(param, 100_000)

    if param.type == "array":
        n = getattr(param, "min_items", None) or 0
        return [_benign_item(param)] * n if n > 0 else []
    return _enforce(param, _TYPE_DEFAULT.get(param.type, "test"))


def _benign_item(param):
    """数组元素的良性值（按声明的 item_type 粗略取）。"""
    it = getattr(param, "item_type", None)
    if it in ("integer", "number"):
        return 1
    if it == "boolean":
        return True
    return "test"


def inject_value(param, payload: str):
    """把 payload 嵌进满足约束的合法骨架（P4）。锁死无自由位 → None。
    array/object 返回"带载荷的结构值"，更细的形状/minItems/key位由上层（executor._shaped_args）决定。"""
    t = param.type
    if t in ("integer", "number", "boolean"):
        return None   # 字符串注入进不去；宽松校验服务端由 P5 类型探测另处理
    if param.enum:
        return None
    fmt = (getattr(param, "str_format", None) or "").lower()
    if fmt in _RIGID_FORMATS:
        return None   # uuid/date/email/ipv4… 刚性，注入不可能
    if t in ("string", "union", "unknown"):
        pat = getattr(param, "pattern", None)
        if pat:
            if not _pattern_injectable(pat):
                return None   # 锚死定长、无自由位
            pref = _literal_prefix(pat)
            return _enforce(param, pref + payload)
        return _enforce(param, payload)   # 无 pattern/format → 载荷本身（补足 min_length）
    if t == "array":
        arr = [payload]
        n = getattr(param, "min_items", None) or 0
        while len(arr) < n:                    # 补足 minItems，避免被 "Too small" 拒
            arr.append(_benign_item(param))
        return arr
    if t == "object":
        return {"mcpfuzz": payload}            # key 位注入由上层(executor._shaped_args)按 placement 另发
    return payload
