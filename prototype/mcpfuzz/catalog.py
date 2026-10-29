"""目录解析：把原始 tools/list 规范化为统一的工具/参数结构。

设计目标：把每个工具参数（含嵌套 object、array）摊平成可注入的叶子参数，
用点号/方括号路径表达层级（如 config.timeout、files[].path），供后续 sink 推断与载荷生成使用。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Param:
    path: str                 # 参数路径，如 "path" / "config.timeout" / "files[].name"
    type: str                 # string/number/integer/boolean/object/array/union/unknown
    required: bool
    description: str | None = None
    enum: list | None = None
    default: object = None
    example: object = None
    item_type: str | None = None   # 当 type==array 时，元素类型


@dataclass
class Tool:
    name: str
    description: str | None
    raw_input_schema: dict
    params: list[Param] = field(default_factory=list)


@dataclass
class Target:
    url: str
    server_name: str | None
    server_version: str | None
    protocol_version: str | None
    tools: list[Tool] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _norm_type(schema: dict) -> str:
    """从 JSON Schema 片段推断类型，兼容 type 为列表、anyOf/oneOf 的情况。"""
    t = schema.get("type")
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        non_null = [x for x in t if x != "null"]
        return non_null[0] if len(non_null) == 1 else "union"
    for key in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(key, []):
            if isinstance(sub, dict) and sub.get("type") and sub["type"] != "null":
                return _norm_type(sub)
    if schema.get("properties"):
        return "object"
    if schema.get("enum"):
        return "string"
    return "unknown"


def _example(schema: dict):
    if "example" in schema:
        return schema["example"]
    ex = schema.get("examples")
    if isinstance(ex, list) and ex:
        return ex[0]
    return None


def flatten_schema(schema: dict, prefix: str = "", parent_required: bool = True) -> list[Param]:
    """递归摊平 JSON Schema 的 properties，返回叶子参数列表。"""
    out: list[Param] = []
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    for name, sub in props.items():
        if not isinstance(sub, dict):
            continue
        path = f"{prefix}.{name}" if prefix else name
        is_req = parent_required and (name in required)
        typ = _norm_type(sub)
        if typ == "object" and sub.get("properties"):
            out += flatten_schema(sub, path, is_req)
        elif typ == "array":
            items = sub.get("items") or {}
            item_type = _norm_type(items) if isinstance(items, dict) else "unknown"
            out.append(Param(path, "array", is_req, sub.get("description"),
                             sub.get("enum"), sub.get("default"), _example(sub), item_type))
            if item_type == "object" and isinstance(items, dict) and items.get("properties"):
                out += flatten_schema(items, path + "[]", False)
        else:
            out.append(Param(path, typ, is_req, sub.get("description"),
                             sub.get("enum"), sub.get("default"), _example(sub)))
    return out


def normalize_tool(name: str, description: str | None, input_schema: dict | None) -> Tool:
    schema = input_schema or {}
    return Tool(name=name, description=description, raw_input_schema=schema,
                params=flatten_schema(schema))
