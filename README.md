# SessionTrail

[![CI](https://github.com/Conalh/SessionTrail/actions/workflows/ci.yml/badge.svg)](https://github.com/Conalh/SessionTrail/actions/workflows/ci.yml)
[![SessionTrail](https://github.com/Conalh/SessionTrail/actions/workflows/sessiontrail.yml/badge.svg)](https://github.com/Conalh/SessionTrail/actions/workflows/sessiontrail.yml)
[![Release](https://img.shields.io/github/v/release/Conalh/SessionTrail)](https://github.com/Conalh/SessionTrail/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Runtime behavior review for AI agent sessions.

SessionTrail is a free OSS CLI and GitHub Action that parses Cursor, Claude Code, and Codex transcripts and flags risky **runtime behavior intent** during a session.

- Tool invocations parsed from Cursor, Claude Code, and Codex JSONL transcripts
- Reads and writes outside the declared repository root
- Home-directory and cross-session transcript access
- Shell commands, MCP tool calls, and external network intent
- Path heat map and behavior summary in Markdown/JSON output
- Terminal, Markdown, JSON, and GitHub annotation output
- Runtime summary across multiple agent families in one PR review

It is intentionally not a hosted scanner. SessionTrail reads local transcript files, uploads nothing by default, and starts advisory with `fail-on: none`.

> ScopeTrail for config. SessionTrail for behavior.

SessionTrail v0 reviews **tool intent** recorded in transcripts. It does not yet see denied actions or tool results unless those appear in future transcript formats.

## Part of an AI-agent governance suite

Five tools mapping orthogonal failure modes of AI-agent deployment:

- **[ScopeTrail](https://github.com/Conalh/ScopeTrail)** — config drift over time (PR-level).
- **[PolicyMesh](https://github.com/Conalh/PolicyMesh)** — policy contradictions across agent surfaces.
- **[CapabilityEcho](https://github.com/Conalh/CapabilityEcho)** — capability drift via code, not config.
- **[TaskBound](https://github.com/Conalh/TaskBound)** — scope creep after the agent runs.
- **SessionTrail** *(this repo)* — runtime behavior review across agent session transcripts.

ScopeTrail, PolicyMesh, and CapabilityEcho are preventive (static analysis of config and code). SessionTrail is runtime (in-session transcript review). TaskBound is detective (stated task vs. actual diff).

## Demo

Live demo PR: [Demo: rogue agent session behavior](https://github.com/Conalh/SessionTrail/pull/1)

The demo uses `test/fixtures/rogue-session.jsonl`, which states a CSS task but records:

- Home-directory and cross-session transcript reads
- A broad home-directory scan
- A pipe-to-shell `curl` command
- MCP and WebFetch calls
- A write outside the repository root

Local fixture:

```powershell
node dist/index.js audit --transcript test/fixtures/rogue-session.jsonl --repo C:/Dev/Demo --format markdown
```

## Local Use

After `npm install -g sessiontrail` (or `npx sessiontrail` for one-off runs):

```powershell
sessiontrail audit --transcript test/fixtures/rogue-session.jsonl --repo C:/Dev/Demo --format markdown
```

From a local checkout:

```powershell
npm install
npm run bundle
node bundle/index.js audit --transcript test/fixtures/rogue-session.jsonl --repo C:/Dev/Demo --format markdown
```

Audit every JSONL file in a transcript directory:

```powershell
sessiontrail audit --transcript-dir C:/Users/conno/.cursor/projects/c-Dev-Demo/agent-transcripts --repo C:/Dev/Demo --format json
```

CLI options:

- `--format text|markdown|json|github|sarif` — output written to stdout (default: `text`).
- `--json-out <path>` — also write the JSON report to a file. Combine with `--format github` so the action streams annotations to stdout while side-outputting JSON.
- `--markdown-out <path>` — also write the Markdown report to a file.
- `--sarif-out <path>` — also write a SARIF 2.1.0 report to a file. Uploadable to GitHub Code Scanning via `github/codeql-action/upload-sarif`.
- `--config <path>` — override the default `<repo>/.sessiontrail.json` allowlist lookup. Useful in monorepos where the audit repo root isn't where the config lives.
- `--fail-on none|low|medium|high|critical` — exit 1 when the session rating meets or exceeds the threshold (default: `none`). Uses the same severity ladder as the GitHub Action.

### Allowlist (`.sessiontrail.json`)

Drop a `.sessiontrail.json` at the audit `--repo` root to declare project-specific expected behaviors. Matched findings drop to `low` severity — visible in the report, but not enough to trip `--fail-on medium` or higher. The risky-pattern detection (e.g. `npm publish`, `curl | sh`, `rm -rf`) still wins, so the allowlist cannot whitelist known exfiltration shapes.

```json
{
  "allowedMcpServers": ["github-pr-helper"],
  "benignShellPatterns": ["^cargo\\s+test", "^deno\\s+task\\s+\\w+$"],
  "allowedNetworkHosts": ["internal.example.com"]
}
```

- `allowedMcpServers` — exact server name match (case-insensitive).
- `benignShellPatterns` — RegExp source strings, applied to each tokenized subcommand with the case-insensitive flag.
- `allowedNetworkHosts` — substring match (case-insensitive) against the requested URL or search term.

See [`.sessiontrail.json.example`](.sessiontrail.json.example) in this repo for a copyable starter file.

Supported transcript families:

- Cursor-style JSONL with assistant `tool_use` blocks.
- Claude Code JSONL with assistant `tool_use` blocks and `file_path` inputs. Per-message `cwd` is used to resolve relative paths.
- Codex JSONL with `response_item` function calls and JSON or freeform tool arguments.

## GitHub Action

Review a transcript artifact against a repository root:

```yaml
name: SessionTrail

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  sessiontrail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: Conalh/SessionTrail@v0.4.0
        with:
          transcript: path/to/session.jsonl
          repo: .
          fail-on: none
```

Review transcripts downloaded from a pull-request artifact:

```yaml
name: SessionTrail

on:
  pull_request:

permissions:
  contents: read
  actions: read

jobs:
  sessiontrail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: actions/download-artifact@v6
        with:
          name: ai-agent-transcripts
          path: sessiontrail-transcripts

      - uses: Conalh/SessionTrail@v0.4.0
        with:
          transcript-dir: sessiontrail-transcripts
          repo: .
          fail-on: none
```

The action uploads nothing by default. It reads the transcript from the workspace, writes a Markdown report to the GitHub Actions step summary, and emits severity-aware inline annotations for each finding — `::error` for critical and high, `::warning` for medium and low.

Action outputs:

- `rating`: `none`, `low`, `medium`, `high`, or `critical`
- `finding-count`: total findings in the session review
- `tool-invocation-count`: total tool invocations parsed
- `unique-tool-count`: number of unique tools invoked
- `runtime-count`: number of agent runtimes represented in the reviewed transcripts
- `sarif-file`: filesystem path of the SARIF 2.1.0 report written by the action

### Upload SARIF to GitHub Code Scanning

The action writes a SARIF report to `${{ runner.temp }}/sessiontrail-report.sarif` and exposes the path via the `sarif-file` output. Chain it into `github/codeql-action/upload-sarif` to surface findings in the Security tab:

```yaml
jobs:
  sessiontrail:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6

      - id: audit
        uses: Conalh/SessionTrail@v0.3.0
        with:
          transcript: path/to/session.jsonl
          repo: .
          fail-on: none

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.audit.outputs.sarif-file }}
          category: sessiontrail
```

## Current Findings

SessionTrail detects:

- Reads outside the declared repository root.
- Writes outside the declared repository root.
- Privileged path access (`.ssh`, `.aws`, `.kube`, `.gnupg`, `/etc/shadow`, `/private/var`) — emitted as a separate `critical` finding. Also caught when referenced inside shell commands (e.g. `cat /home/u/.ssh/id_rsa`).
- Home directory and agent-metadata access (`.cursor`, `.codex`, `.claude`, `.aider`, `.continue`, `.vscode-server`) — Windows, POSIX, WSL (`\\wsl$\`, `\\wsl.localhost\`), and unexpanded `~` paths.
- Cross-session transcript reads.
- Shell command invocations — chained pipelines (`;`, `|`, `&&`, `||`) are split and each branch is scored independently; trivial quote-obfuscation (`c""url`, `c''url`, `c\\url`) is neutralized before matching. Neutral setup verbs (`cd`, `export`, `source`) don't contribute to severity; built-in benign verbs (`git status`, `npm test`, `pwd`) and allowlisted patterns drop to `low`.
- MCP tool invocations.
- External network intent via `WebFetch` or `WebSearch`.
- Subagent spawns via `Task`.
- Broad scans of user roots, filesystem root, and top-level data trees (`Documents`, `Downloads`, etc.) via `Glob` or `Grep`.
- Parser skips — a `low`-severity finding fires when the transcript contained lines that couldn't be parsed, so `--fail-on low` catches truncated transcripts.

## Complements the Suite

Use SessionTrail with the other agent governance tools:

- **[ScopeTrail](https://github.com/Conalh/ScopeTrail)** — did agent permissions **change** in this PR?
- **[PolicyMesh](https://github.com/Conalh/PolicyMesh)** — do agent surfaces **agree** in this repo right now?
- **[CapabilityEcho](https://github.com/Conalh/CapabilityEcho)** — did the **code or workflow diff** introduce new capability signals?
- **[TaskBound](https://github.com/Conalh/TaskBound)** — did the edits stay within the **stated task**?
- **SessionTrail** — what did the agent **actually try to do** during the session?

## Feedback Wanted

SessionTrail is intentionally small right now. If a warning is noisy, open a
[false-positive report](https://github.com/Conalh/SessionTrail/issues/new?template=false-positive.yml).
If your team uses another transcript or runtime signal, open a
[missing-signal request](https://github.com/Conalh/SessionTrail/issues/new?template=missing-signal.yml).

## Development

```powershell
npm install
npm run build
npm test
```

Shared parsing, locators, and the Finding schema live in [agent-gov-core](https://github.com/Conalh/agent-gov-core) — see its [CONTRIBUTING.md](https://github.com/Conalh/agent-gov-core/blob/main/CONTRIBUTING.md) before touching that library.
