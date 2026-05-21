# SessionTrail

[![CI](https://github.com/Conalh/SessionTrail/actions/workflows/ci.yml/badge.svg)](https://github.com/Conalh/SessionTrail/actions/workflows/ci.yml)
[![SessionTrail](https://github.com/Conalh/SessionTrail/actions/workflows/sessiontrail.yml/badge.svg)](https://github.com/Conalh/SessionTrail/actions/workflows/sessiontrail.yml)
[![Release](https://img.shields.io/github/v/release/Conalh/SessionTrail)](https://github.com/Conalh/SessionTrail/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Runtime behavior review for AI agent sessions.

SessionTrail is a free OSS CLI and GitHub Action that parses local Cursor agent transcripts and flags risky **runtime behavior intent** during a session.

- Tool invocations parsed from Cursor JSONL transcripts
- Reads and writes outside the declared repository root
- Home-directory and cross-session transcript access
- Shell commands, MCP tool calls, and external network intent
- Path heat map and behavior summary in Markdown/JSON output
- Terminal, Markdown, JSON, and GitHub annotation output

It is intentionally not a hosted scanner. SessionTrail reads local transcript files, uploads nothing by default, and starts advisory with `fail-on: none`.

> ScopeTrail for config. SessionTrail for behavior.

SessionTrail v0 reviews **tool intent** recorded in transcripts. It does not yet see denied actions or tool results unless those appear in future transcript formats.

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

      - uses: Conalh/SessionTrail@v0.1.0
        with:
          transcript: path/to/session.jsonl
          repo: .
          fail-on: none
```

The action uploads nothing by default. It reads the transcript from the workspace, writes a Markdown report to the GitHub Actions step summary, and emits warning annotations for each finding.

Action outputs:

- `rating`: `none`, `low`, `medium`, `high`, or `critical`
- `finding-count`: total findings in the session review
- `tool-invocation-count`: total tool invocations parsed
- `unique-tool-count`: number of unique tools invoked

## Current Findings

SessionTrail v0 detects:

- Reads outside the declared repository root.
- Writes outside the declared repository root.
- Home-directory or Cursor metadata access.
- Cross-session transcript reads.
- Shell command invocations.
- MCP tool invocations.
- External network intent via `WebFetch` or `WebSearch`.
- Subagent spawns via `Task`.
- Broad home-directory scans via `Glob` or `Grep`.

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
