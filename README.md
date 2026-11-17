# Calchas

**Black-box injection vulnerability detection for MCP (Model Context Protocol) servers.**

Calchas connects to an MCP server over Streamable HTTP, reads its `tools/list`, and tests every tool
parameter for server-side injection flaws — without source code, instrumentation, or knowledge of the
server's implementation language. A finding is only *confirmed* when the server's response (or an
out-of-band callback) shows that the injected payload was actually executed.

Supported vulnerability classes:

| Class | Example sink |
|---|---|
| Command injection | `subprocess(..., shell=True)` |
| Argument injection | user value reaching an argv option (`git --upload-pack=...`) |
| Path traversal | file read/write outside the intended root |
| SSRF | server-side fetch of an attacker-chosen URL |
| Code injection | `eval` / template / expression evaluation |

> **Authorized use only.** `calchas scan` sends real attack payloads (command, path, SSRF and code
> payloads, file writes, out-of-band callbacks). Run it only against servers you own or are explicitly
> permitted to test.

## How it works

1. **Semantic parameter classification** — each parameter's name, description and JSON Schema are
   classified (rules + LLM) into the injection classes it may reach.
2. **Execution-guided sequence construction** — tools that cannot be called standalone are brought into a
   callable state by an agent that builds the prerequisite call sequence from benign values.
3. **Execution-confirmation oracle** — payloads are paired with benign controls and judged through
   in-band reflection, timing, cross-tool read-back and (optionally) out-of-band callbacks; only the
   *difference* between attack and control counts as evidence.

## Install

Requires Python ≥ 3.11. `curl` must be on `PATH` when LLM features are used.

```bash
pipx install mcp-calchas      # recommended for a CLI tool (isolated environment)
# or
pip install mcp-calchas
```

The distribution is called `mcp-calchas`; the command and the Python package are `calchas`.

## Quick start

```bash
# 1. Preview the attack surface only (no payloads sent)
calchas recon http://localhost:8080/mcp --no-llm-sink --no-agent --no-llm-plan

# 2. Full scan with an OpenAI-compatible LLM
export CALCHAS_LLM_API_KEY=sk-...
calchas scan http://localhost:8080/mcp \
    --llm-base-url https://api.openai.com/v1 --llm-model gpt-4o
```

Results are written to `./runs/<timestamp>__<server>/` in the current directory (`runs/latest` points to
the most recent run). Change the location with `-o DIR`.

| File | Content |
|---|---|
| `report.md` | human-readable report |
| `findings.json` | machine-readable findings |
| `catalog.json` | tools and parameters returned by `tools/list` |
| `sinks.json` | per-parameter injection-class classification |
| `events.jsonl` | full event log of the run |

Re-render a report later with `calchas report runs/latest/findings.json runs/latest/catalog.json`.

## Configuring the LLM

No model is bundled. LLM features (parameter classification, sequence agent, planning) need an
OpenAI-compatible chat-completions endpoint, configured in one of three ways:

```bash
# command line (the key may also come from $CALCHAS_LLM_API_KEY)
calchas scan <url> --llm-base-url https://api.example.com/v1 --llm-api-key sk-... --llm-model my-model

# provider file, with automatic failover in listed order
calchas scan <url> --llm-config providers.json

# no LLM at all (rule-based classification, single-call plans)
calchas scan <url> --no-llm-sink --no-agent --no-llm-plan
```

`--llm-base-url` accepts either `.../v1` or the full `.../v1/chat/completions` URL.

`providers.json`:

```json
{
  "providers": [
    {"name": "primary", "base_url": "https://api.example.com/v1", "api_key": "env:MY_KEY", "model": "model-a"},
    {"name": "backup",  "base_url": "https://api.other.com/v1",   "api_key": "sk-...",     "model": "model-b"}
  ],
  "agent_provider": "primary"
}
```

`"api_key": "env:VAR"` reads the key from environment variable `VAR`.

## Out-of-band (OOB) channel

Blind SSRF and blind command execution are confirmed by an out-of-band callback. The OOB channel is
**off by default**; enable it by pointing Calchas at a collector the target can reach:

```bash
calchas scan <url> --oob-callback http://<collector-ip>:9100
```

The collector must record any request to `/<token>` and report hits as JSON at `/__hits`
(override with `--oob-query`). A standard-library reference implementation is in the repository at
`deploy/infra/oob/collector.py`. Without OOB, Calchas still detects and confirms through in-band
reflection, timing and read-back channels.

## Common options

| Option | Purpose |
|---|---|
| `--header 'Authorization: Bearer ...'` | add HTTP headers (repeatable) |
| `--tool NAME` / `--exclude-tool NAME` | limit which tools are tested |
| `--sink command_injection` | limit which vulnerability classes are tested |
| `--batch FILE --batch-name NAME` | scan many targets; writes `batch_summary.md` |
| `--yes` | skip the interactive confirmation (needed for batch/CI) |
| `--format json` | machine-readable console output |

Run `calchas scan --help` for the full list.

## Repository layout

| Path | Content |
|---|---|
| `calchas/` | the tool (the only code shipped in the PyPI package) |
| `dev/` | developer debugging scripts |
| `deploy/` | experiment infrastructure: batch-scan docker-compose cells, OOB collector, frozen batch records |
| `dataset/` | vulnerability-dataset pipeline (CVE/GHSA/OSV collection and labeling) |
| `docs/`, `research_notes/` | design notes and related-work surveys |

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/calchas selftest
```

## License

Apache-2.0
