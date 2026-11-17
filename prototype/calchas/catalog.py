"""Catalog parsing: normalize the raw tools/list into a uniform tool/parameter structure.

Design goal: flatten each tool parameter (including nested object, array) into injectable leaf parameters,
expressing the hierarchy with a dotted / bracketed path (e.g. config.timeout, files[].path), for downstream
sink inference and payload generation.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Param:
    path: str                 # parameter path, e.g. "path" / "config.timeout" / "files[].name"
    type: str                 # string/number/integer/boolean/object/array/union/unknown
    required: bool
    description: str | None = None
    enum: list | None = None
    default: object = None
    example: object = None
    item_type: str | None = None   # element type when type==array
    # -- constraints declared in JSON Schema (for constraint-aware value/payload generation; see the value-generation design doc) --
    pattern: str | None = None          # pattern (regex)
    str_format: str | None = None       # format: uuid/date-time/email/uri/ipv4/hostname...
    min_length: int | None = None       # minLength
    max_length: int | None = None       # maxLength
    minimum: float | None = None        # minimum / exclusiveMinimum (numeric form)
    maximum: float | None = None        # maximum / exclusiveMaximum (numeric form)
    exclusive_min: bool = False
    exclusive_max: bool = False
    multiple_of: float | None = None    # multipleOf
    min_items: int | None = None        # minItems
    max_items: int | None = None        # maxItems


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
    """Infer the type from a JSON Schema fragment, handling type being a list, or anyOf/oneOf."""
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


def _constraints(sub: dict) -> dict:
    """Read the declared constraints from a property sub-schema, for constraint-aware value/payload generation. Read-only, does not change behavior."""
    mn, emn = sub.get("minimum"), sub.get("exclusiveMinimum")
    mx, emx = sub.get("maximum"), sub.get("exclusiveMaximum")
    # draft-07: exclusiveMinimum/Maximum are numeric; draft-04: boolean (paired with minimum/maximum)
    minimum = mn if mn is not None else (emn if isinstance(emn, (int, float)) and not isinstance(emn, bool) else None)
    maximum = mx if mx is not None else (emx if isinstance(emx, (int, float)) and not isinstance(emx, bool) else None)
    excl_min = (emn is True) or (mn is None and isinstance(emn, (int, float)) and not isinstance(emn, bool))
    excl_max = (emx is True) or (mx is None and isinstance(emx, (int, float)) and not isinstance(emx, bool))
    return dict(
        pattern=sub.get("pattern"),
        str_format=sub.get("format"),
        min_length=sub.get("minLength"),
        max_length=sub.get("maxLength"),
        minimum=minimum,
        maximum=maximum,
        exclusive_min=bool(excl_min),
        exclusive_max=bool(excl_max),
        multiple_of=sub.get("multipleOf"),
        min_items=sub.get("minItems"),
        max_items=sub.get("maxItems"),
    )


def flatten_schema(schema: dict, prefix: str = "", parent_required: bool = True) -> list[Param]:
    """Recursively flatten a JSON Schema's properties, returning a list of leaf parameters."""
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
                             sub.get("enum"), sub.get("default"), _example(sub), item_type,
                             **_constraints(sub)))
            if item_type == "object" and isinstance(items, dict) and items.get("properties"):
                out += flatten_schema(items, path + "[]", False)
        else:
            out.append(Param(path, typ, is_req, sub.get("description"),
                             sub.get("enum"), sub.get("default"), _example(sub),
                             **_constraints(sub)))
    return out


def normalize_tool(name: str, description: str | None, input_schema: dict | None) -> Tool:
    schema = input_schema or {}
    return Tool(name=name, description=description, raw_input_schema=schema,
                params=flatten_schema(schema))


def _path_tokens(key: str) -> list[tuple[str, bool]]:
    """Split a flat parameter path into [(name, is_array_level), ...].
    Symmetric with flatten_schema's convention: `.` means a nested object, `xxx[]` means that level is an array.
    E.g. `author.name` -> [(author,False),(name,False)];
         `files[].path` -> [(files,True),(path,False)]; `tags[]` -> [(tags,True)].
    """
    toks: list[tuple[str, bool]] = []
    for part in key.split("."):
        is_arr = part.endswith("[]")
        toks.append((part[:-2] if is_arr else part, is_arr))
    return toks


def nest_arguments(flat: dict) -> dict:
    """Rebuild the flat dotted/bracketed-key arguments produced by flatten_schema into the nested structure the MCP tool expects.

    This is the inverse of flatten_schema: internally the detection stages uniformly use leaf paths like
    `author.name`, `files[].path` as keys, but just before sending to tools/call they must be reassembled into
    {author:{name:..}}, {files:[{path:..}]}, otherwise tools with object/array parameters error out due to the
    wrong argument structure (manifesting as lots of "unreached" and cascading prerequisite-step failures).
    Generic across any MCP, with no tool special-casing.

    - Plain keys without `.`/`[]` pass through verbatim.
    - If the value is already a dict/list (the caller gave a structured value directly), place it verbatim under the plain key, without splitting.
    - On a structural conflict (the same name used as both a scalar and a container), conservatively skip that key, never raising to interrupt the call.
    """
    if not isinstance(flat, dict):
        return flat
    root: dict = {}
    for key, value in flat.items():
        if not isinstance(key, str) or ("." not in key and "[]" not in key):
            root[key] = value
            continue
        _assign(root, _path_tokens(key), value)
    return root


def _assign(root: dict, toks: list[tuple[str, bool]], value) -> None:
    cur = root
    n = len(toks)
    for i, (name, is_arr) in enumerate(toks):
        last = i == n - 1
        if not is_arr:
            if last:
                if isinstance(cur, dict):
                    cur[name] = value
                return
            nxt = cur.get(name) if isinstance(cur, dict) else None
            if not isinstance(nxt, dict):
                if not isinstance(cur, dict):
                    return
                nxt = {}
                cur[name] = nxt
            cur = nxt
        else:
            if not isinstance(cur, dict):
                return
            lst = cur.get(name)
            if not isinstance(lst, list):
                lst = []
                cur[name] = lst
            if last:
                lst.append(value)
                return
            if not lst or not isinstance(lst[-1], dict):
                lst.append({})
            cur = lst[-1]
