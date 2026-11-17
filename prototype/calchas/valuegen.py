"""Constraint-aware parameter value generation (see the value-generation design doc).

Unifies P2 (valid fill values) and P4 (constraint-aware payloads) — both "generate a value satisfying the
parameter's declared constraints", P4 just adds one step "embed the payload into a valid skeleton". All driven
by the constraints the parameter declares in its own JSON Schema (pattern/format/type/length/numeric-bounds),
with **no special-casing of any service/parameter name**.

- benign_value(param): produce a benign value satisfying the constraints (deterministic ladder; the LLM is a reserved fallback, off by default).
- inject_value(param, payload): embed the attack fragment into a constraint-satisfying valid skeleton; a fully
  locked-down parameter (uuid/enum/pure-numeric/no free slot) -> returns None (honestly "this parameter cannot
  carry this injection", not force-fed, not counted as a miss).
"""
from __future__ import annotations

from calchas.__about__ import MARKER

import re
import secrets

_PATH_KEYS = ("path", "file", "dir", "folder", "location", "dest", "filepath")
_URL_KEYS = ("url", "uri", "endpoint", "link", "href")
# Directory-type hints: on a hit, fill a "unique new directory path" (let the tool makedirs itself); otherwise fill as a file
_DIR_KEYS = ("dir", "folder", "directory")
# Return-limit numeric hints: on a hit, fill a "large value" (still clamped into the declared [min,max]), to
# avoid a minimum of 1 truncating the observable output and blinding the verdict (e.g. a fetch-type max_length=1
# truncating the SSRF metadata echo to 1 char -> a miss). Only accepts "limit the return amount" semantics;
# deliberately excludes index/offset/start (a large value would skip content), timeout/delay/retry/port (a large value has side effects).
_LIMIT_KEYS = ("max_length", "maxlength", "max_len", "maxchars", "max_chars", "maxbytes", "max_bytes",
               "maxresults", "max_results", "num_results", "max_tokens", "maxtokens", "max_items",
               "maxitems", "page_size", "pagesize", "per_page", "perpage", "max_size", "maxsize",
               "limit", "length", "truncate", "top_k", "topk", "top_n")
_LIMIT_DESC = ("maximum number of", "max number of", "number of characters", "characters to return",
               "maximum length", "max length", "number of results", "truncat")


def _path_filler(param) -> str:
    """Benign fill value for a path-type parameter. Two iron rules:
    1) Unique each time (with a random token) — never a hardcoded constant shared across tools/runs, otherwise
       "tool A writes it as a file, tool B uses it as a directory" clashes arise (see output_dir hitting a consciousness leftover).
    2) Distinguish directory/file by shape — a directory-type gets a nonexistent unique directory (the tool creates it), a file-type gets a unique file path.
    Cost: the fill value is no longer per-parameter deterministic (introduces randomness), but this is a necessary trade-off to avoid residual pollution."""
    name = (param.path or "").lower()
    desc = (getattr(param, "description", "") or "").lower()
    is_dir = any(k in name for k in _DIR_KEYS) or "directory" in desc or "folder" in desc
    tok = secrets.token_hex(4)
    return f"/tmp/{MARKER}_d{tok}" if is_dir else f"/tmp/{MARKER}_f{tok}.bin"

# format keyword -> a valid benign value (the JSON Schema standard vocabulary, treated the same for all services)
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

# These formats are rigidly locked down, a string injection cannot be carried -> inject_value returns None
_RIGID_FORMATS = {"uuid", "guid", "date", "date-time", "time", "duration",
                  "email", "idn-email", "ipv4", "ipv6", "hostname", "idn-hostname", "byte", "binary"}

_META = set("[](){}.*+?|^$\\")


def _literal_prefix(pattern: str) -> str:
    """Take the "required literal prefix" from a regex: from after ^ up to the first regex metacharacter.
    E.g. ^proj-[a-z0-9]+$ -> 'proj-'; ^user_\\d+ -> 'user_'. Covers the most common "must start with X"."""
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
    """Whether the pattern has a "free slot" for a payload: a literal prefix, or a loose quantifier (*/+/.*/\\w etc.).
    A purely fixed-length character class (e.g. ^[0-9]{6}$) is treated as having no free slot."""
    if _literal_prefix(pattern):
        return True
    return any(tok in pattern for tok in (".*", ".+", "\\w", "\\S", "[^", "*", "+"))


def _enforce(param, v):
    """Apply length/numeric-bound finishing to the [generated] value, ensuring it is itself valid (does not touch authoritative values like default/example/enum)."""
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
        # Convert exclusive bounds into "inclusive valid lower/upper limits", then clamp v into [lo_ok, hi_ok]
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
            if lo_ok is not None and cand < lo_ok:   # after aligning to the multiple, don't fall below the lower bound
                cand = (int(lo_ok / mult) + 1) * mult
            v = cand
        if param.type == "integer":
            v = int(v)
    return v


_TYPE_DEFAULT = {"string": "test", "integer": 1, "number": 1, "boolean": True, "array": [], "object": {}}


def benign_value(param):
    """Produce a benign value satisfying the parameter's declared constraints. Deterministic ladder:
    default/example/enum (authoritative) -> format -> pattern prefix -> name heuristic -> type fallback (with _enforce finishing)."""
    name = (param.path or "").lower()
    stringy = param.type in ("string", "union", "unknown")
    pathlike = stringy and any(k in name for k in _PATH_KEYS)

    # Authoritative values: for path-type, avoid a relative default (keep the original heuristic); otherwise use default/example/enum directly (already valid, no _enforce)
    if pathlike and getattr(param, "default", None) in (None, ".", "", "./", "cwd"):
        return _path_filler(param)
    if getattr(param, "default", None) is not None:
        return param.default
    if getattr(param, "example", None) is not None:
        return param.example
    if param.enum:
        return param.enum[0]

    # Constraint-driven generation (through _enforce finishing)
    fmt = (getattr(param, "str_format", None) or "").lower()
    if fmt in _FORMAT_VALUES:
        return _enforce(param, _FORMAT_VALUES[fmt])
    pat = getattr(param, "pattern", None)
    if pat:
        pref = _literal_prefix(pat)
        if pref:
            return _enforce(param, pref + "x")

    # Name heuristic (keeps the original _fallback_literal behavior)
    if stringy:
        if pathlike:
            return _path_filler(param)
        if any(k in name for k in _URL_KEYS):
            return "http://example.com/"

    # Return-limit numeric parameter: fill a large value (clamped into the declared bounds), do not use the minimum which truncates observable output and blinds the verdict
    if param.type in ("integer", "number"):
        desc = (getattr(param, "description", "") or "").lower()
        if any(k in name for k in _LIMIT_KEYS) or any(k in desc for k in _LIMIT_DESC):
            return _enforce(param, 100_000)

    if param.type == "array":
        n = getattr(param, "min_items", None) or 0
        return [_benign_item(param)] * n if n > 0 else []
    return _enforce(param, _TYPE_DEFAULT.get(param.type, "test"))


def _benign_item(param):
    """Benign value for an array element (roughly by the declared item_type)."""
    it = getattr(param, "item_type", None)
    if it in ("integer", "number"):
        return 1
    if it == "boolean":
        return True
    return "test"


def inject_value(param, payload: str):
    """Embed the payload into a constraint-satisfying valid skeleton (P4). Locked down with no free slot -> None.
    array/object return a "structured value with the payload"; the finer shape/minItems/key-position is decided by the upper layer (executor._shaped_args)."""
    t = param.type
    if t in ("integer", "number", "boolean"):
        return None   # a string injection cannot get in; a loosely-validating server is handled separately by P5 type probing
    if param.enum:
        return None
    fmt = (getattr(param, "str_format", None) or "").lower()
    if fmt in _RIGID_FORMATS:
        return None   # uuid/date/email/ipv4... are rigid, injection is impossible
    if t in ("string", "union", "unknown"):
        pat = getattr(param, "pattern", None)
        if pat:
            if not _pattern_injectable(pat):
                return None   # anchored fixed-length, no free slot
            pref = _literal_prefix(pat)
            return _enforce(param, pref + payload)
        return _enforce(param, payload)   # no pattern/format -> the payload itself (padded to min_length)
    if t == "array":
        arr = [payload]
        n = getattr(param, "min_items", None) or 0
        while len(arr) < n:                    # pad to minItems, to avoid a "Too small" rejection
            arr.append(_benign_item(param))
        return arr
    if t == "object":
        return {MARKER: payload}            # key-position injection is sent separately by the upper layer (executor._shaped_args) per placement
    return payload
