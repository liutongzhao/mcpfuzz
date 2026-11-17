"""Error fingerprints: recognize, from the response/error body, the weak evidence (Tier-3) that "the
injection reached an interpreter".

On its own this only serves as corroboration for "suspected", never for "confirmed". One group of generic
regexes per class, not targeted at any specific server.
"""
from __future__ import annotations

import re

from calchas.sink.types import AI, CI, CODE, PT, SSRF

_PATTERNS = {
    CI: [
        r"/bin/(?:sh|bash)\b",
        r"\bcommand not found\b",          # not a bare "not found": it would collide with "File not found" (a missing file, not a shell)
        r"\bsyntax error near\b",            # bash: "syntax error near unexpected token"
        r"\bunexpected (?:EOF|end of file)\b",  # shell-specific; excludes a bare "unexpected token" — JS/JSON parse
                                             # errors like "Unexpected token '<'" are unrelated to a shell and would misfire
        r"^sh:\s",
    ],
    AI: [
        r"\bunknown option\b",
        r"\bunrecognized option\b",
        r"\bunknown (?:flag|switch)\b",
        r"\bunexpected argument\b",
        # excludes "invalid option": application-level enum validation also uses it ("Invalid option: expected one of ..."), which would misfire
    ],
    # Path traversal does NOT use error-fingerprint weak evidence: ENOENT / "No such file" / permission denied
    # in the response only proves "the server tried to open a file/path with this value and failed", it does
    # NOT prove that out-of-bounds access actually happened (a payload sprayed into a non-path parameter also
    # produces such errors). PT is always fail-closed: confirmed only by positive concrete evidence —
    # in-band read-back of an out-of-bounds file's content signature (passwd/key), or reading back a landed
    # canary after a write (see executor).
    SSRF: [
        r"\b(?:ECONNREFUSED|connection refused)\b",
        r"\b(?:ETIMEDOUT|ESOCKETTIMEDOUT)\b",
        r"\btimed out\b",                       # "Request/connection/operation timed out" (incl. SDK-wrapped timeouts)
        r"\bREQUEST_TIMEOUT\b",                  # code-level timeout marker (SdkError | code=REQUEST_TIMEOUT etc.)
        r"\bno route to host\b",
        r"\bfetch failed\b",                    # Node undici fetch() runtime failure: an outbound connection was started and failed at the
                                                # network layer (distinct from a pre-emptive filter rejection like "Blocked URL" — that never touches the network, no match)
        # DNS resolution / connection-initiation failure: proves our value was actually handed to the network client as a hostname/URL
        r"\b(?:ENOTFOUND|EAI_AGAIN)\b",
        r"\bgetaddrinfo\b",
        r"\bName or service not known\b",
        r"\bnodename nor servname\b",
        r"\bfailed to (?:resolve|establish a? ?new connection)\b",
        r"\bMax retries exceeded with url\b",             # typical requests-library error when hitting our host
    ],
    # Code injection is WEAK evidence ONLY (-> suspected, never decided alone; confirmation relies on L2
    # out-of-domain echo). Takes high-signal tracebacks from interpreters/template engines that were reached
    # and errored, generic and not targeted at any specific server. Deliberately excludes over-broad terms
    # like "TypeError"/"Unexpected token" (JSON/JS parsing also produces them, which would misfire).
    CODE: [
        r"Traceback \(most recent call last\)",            # Python interpreter stack
        r"\bSyntaxError\b", r"\bNameError\b",               # Python eval/exec
        r"\binvalid syntax\b",
        r"\bunexpected EOF while parsing\b",
        r"\bSympifyError\b", r"\bcould not parse\b",        # SymPy parse_expr
        r"\bParseException\b",
        r"\bjinja2\.exceptions\.", r"\bTemplateSyntaxError\b",  # Jinja2 / template engines
        r"\bat new Script\b", r"\bevalmachine\b",           # Node vm/eval stack frames
    ],
}

_COMPILED = {k: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in v] for k, v in _PATTERNS.items()}


def error_fingerprint(text: str, vuln_class: str) -> str | None:
    """Return the matched snippet (up to 120 chars) on a hit, else None."""
    if not text:
        return None
    for rx in _COMPILED.get(vuln_class, []):
        m = rx.search(text)
        if m:
            i = m.start()
            return text[max(0, i - 20): i + 100]
    return None
