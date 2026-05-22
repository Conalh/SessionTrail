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

```powershell
npm install
npm run build
node dist/index.js audit --transcript test/fixtures/rogue-session.jsonl --repo C:/Dev/Demo --format markdown
```

Audit every JSONL file in a transcript directory:

```powershell
node dist/index.js audit --transcript-dir C:/Users/conno/.cursor/projects/c-Dev-Demo/agent-transcripts --repo C:/Dev/Demo --format json
```

Supported transcript families:

- Cursor-style JSONL with assistant `tool_use` blocks.
- Claude Code JSONL with assistant `tool_use` blocks and `file_path` inputs.
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

      - uses: Conalh/SessionTrail@v0.1.1
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

      - uses: Conalh/SessionTrail@v0.1.1
        with:
          transcript-dir: sessiontrail-transcripts
          repo: .
          fail-on: none
```

The action uploads nothing by default. It reads the transcript from the workspace, writes a Markdown report to the GitHub Actions step summary, and emits warning annotations for each finding.

Action outputs:

- `rating`: `none`, `low`, `medium`, `high`, or `critical`
- `finding-count`: total findings in the session review
- `tool-invocation-count`: total tool invocations parsed
- `unique-tool-count`: number of unique tools invoked
- `runtime-count`: number of agent runtimes represented in the reviewed transcripts

## Current Findings

SessionTrail v0 detects:

- Reads outside the declared repository root.
- Writes outside the declared repository root.
- Privileged path access (`.ssh`, `.aws`, `.kube`, `.gnupg`, `/etc/shadow`, `/private/var`) — emitted as a separate `critical` finding.
- Home directory and agent-metadata access (`.cursor`, `.codex`, `.claude`, `.aider`, `.continue`, `.vscode-server`) — Windows, POSIX, WSL (`\\wsl$\`, `\\wsl.localhost\`), and unexpanded `~` paths.
- Cross-session transcript reads.
- Shell command invocations — chained pipelines (`;`, `|`, `&&`, `||`) are split and each branch is scored independently; trivial quote-obfuscation (`c""url`, `c''url`, `c\\url`) is neutralized before matching.
- MCP tool invocations.
- External network intent via `WebFetch` or `WebSearch`.
- Subagent spawns via `Task`.
- Broad scans of user roots, filesystem root, and top-level data trees (`Documents`, `Downloads`, etc.) via `Glob` or `Grep`.

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
