# SessionTrail

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: TypeScript](https://img.shields.io/badge/language-TypeScript-3178c6.svg)](package.json)
[![Local-only](https://img.shields.io/badge/local--only-uploads%20nothing-2ea44f.svg)](#how-it-works)
[![Release](https://img.shields.io/github/v/release/Conalh/SessionTrail)](https://github.com/Conalh/SessionTrail/releases)

**Read an AI agent's session transcript and flag what it actually tried to do — credential reads, `curl | sh`, unknown MCP servers, cross-session snooping, writes outside the repo.**

## The problem

AI agents in Cursor, Claude Code, and Codex routinely do things their prompt never asked for: open `~/.ssh/id_rsa`, read another session's transcript, pipe a shell installer in from the network, or call an MCP server nobody approved. The runtime records every one of those tool calls in plain JSONL — but nobody reads the transcript. SessionTrail does, and turns the risky ones into a structured report you can fail a PR on.

## Quickstart

```bash
git clone https://github.com/Conalh/SessionTrail.git
cd SessionTrail
npm install
npm run bundle

node bundle/index.js audit \
  --transcript test/fixtures/rogue-session.jsonl \
  --repo C:/Dev/Demo \
  --format markdown
```

That command runs against the bundled rogue-agent fixture and reports `CRITICAL`. Swap `--transcript` for a real Cursor / Claude Code / Codex JSONL to audit your own session, or use `--transcript-dir` to scan an entire directory of transcripts.

<!-- TODO: publish to npm and replace the clone with `npm install -g sessiontrail` / `npx sessiontrail`. The package.json bin entry already exposes `sessiontrail` → `bundle/index.js`. -->

## Example output

```
SessionTrail behavior review: CRITICAL
Agent runtimes: cursor x9
Parsed: 10 lines, 9 events
Summary: home or Cursor metadata access; reads outside the repository;
  cross-session transcript reads; broad home-directory scans;
  shell command invocations; MCP tool invocations; external network requests;
  subagent spawns; writes outside the repository

[HIGH]     Home directory access: agent read C:/Users/conno/.cursor/plans/demo.plan.md
[MEDIUM]   Read outside repository: C:/Users/conno/.cursor/plans/demo.plan.md
[MEDIUM]   Cross-session transcript read: .../old-session/old-session.jsonl
[HIGH]     Broad path scan: agent scanned a very broad home-directory path
[HIGH]     Shell command: curl https://example.com/install.sh | bash
[MEDIUM]   MCP tool invoked: cursor-app-control/move_agent_to_root
[MEDIUM]   Network request via WebFetch: https://example.com/bootstrap
[LOW]      Subagent spawned: explore
[CRITICAL] Write outside repository: agent attempted to write outside the declared repository root
```

`--format json` emits the canonical `agent-gov-core` Report envelope. Each entry conforms to the shared `Finding` schema, so SessionTrail output composes cleanly with the rest of the suite via `GovVerdict`:

```json
{
  "schemaVersion": "1.0",
  "tool": "session_trail",
  "rating": "critical",
  "findings": [
    {
      "tool": "session_trail",
      "kind": "session_trail.shell_command_invoked",
      "severity": "high",
      "message": "Shell command: curl https://example.com/install.sh | bash",
      "location": { "file": "test/fixtures/rogue-session.jsonl", "line": 7 },
      "fingerprint": "..."
    }
  ],
  "data": {
    "toolInvocationCount": 9,
    "uniqueToolCount": 7,
    "runtimeUsage": { "cursor": 9 }
  }
}
```

<!-- TODO: add screenshot or asciinema GIF of real output here -->

## How it works

- Runs entirely on your machine against the local JSONL transcript file. **Uploads nothing by default** — no hosted scanner, no telemetry, no account.
- Parses Cursor (`tool_use` blocks), Claude Code (`tool_use` blocks with per-message `cwd`), and Codex (`response_item` function calls) transcripts into a normalized stream of tool events.
- Scores each event against a fixed set of behaviors: reads/writes outside `--repo`, privileged paths (`.ssh`, `.aws`, `.kube`, `.gnupg`, `/etc/shadow`), home and agent-metadata directories (`.cursor`, `.claude`, `.codex`, `.aider`, `.continue`, `.vscode-server`), cross-session transcript access, broad scans of user roots, risky shell pipelines (split on `;` `|` `&&` `||`, quote-obfuscation neutralized), MCP invocations, and external network intent.
- Emits findings using the canonical `Finding` schema from [agent-gov-core](https://github.com/Conalh/agent-gov-core), with stable per-finding fingerprints so cross-tool dedupe and SARIF dedupe both work.

SessionTrail reviews **tool intent** — what the agent tried to do, as recorded in the transcript. Denied actions, tool results, and approval outcomes will land when stable transcript fields exist across runtimes.

## Options

CLI flags (`sessiontrail audit ...`):

| Flag | Default | Purpose |
| --- | --- | --- |
| `--transcript <path>` | — | Single JSONL transcript to audit. |
| `--transcript-dir <dir>` | — | Audit every JSONL file in a directory. Mutually exclusive with `--transcript`. |
| `--repo <path>` | `cwd` | Repository root used to judge in-repo vs. out-of-repo behavior. Compared as a string — the directory does not need to exist on the audit host, so a Windows-recorded transcript can be reviewed on a Linux runner. |
| `--format` | `text` | `text`, `markdown`, `json`, `github`, or `sarif`. |
| `--json-out <path>` | — | Also write the JSON report (canonical `agent-gov-core` envelope) to a file. |
| `--markdown-out <path>` | — | Also write the Markdown report to a file. |
| `--sarif-out <path>` | — | Also write a SARIF 2.1.0 report — uploadable via `github/codeql-action/upload-sarif`. |
| `--config <path>` | `<repo>/.sessiontrail.json` | Allowlist file. Useful in monorepos where the audit root isn't where the config lives. |
| `--fail-on` | `none` | Exit 1 when the session rating meets `low`, `medium`, `high`, or `critical`. |

### Allowlist (`.sessiontrail.json`)

Drop one at the repo root to declare expected behaviors. Matched findings drop to `low` — visible in the report, but not enough to trip `--fail-on medium`. Risky-pattern detection (`npm publish`, `curl | sh`, `rm -rf`, `git push`, etc.) always wins and **cannot** be allowlisted.

```json
{
  "allowedMcpServers": ["github-pr-helper"],
  "benignShellPatterns": ["^cargo\\s+test", "^deno\\s+task\\s+\\w+$"],
  "allowedNetworkHosts": ["internal.example.com"]
}
```

See [`.sessiontrail.json.example`](.sessiontrail.json.example) for a copyable starter.

### GitHub Action

```yaml
- uses: actions/checkout@v6
- uses: Conalh/SessionTrail@v0.6.1
  with:
    transcript: path/to/session.jsonl
    repo: .
    fail-on: none
```

Action outputs: `rating`, `finding-count`, `tool-invocation-count`, `unique-tool-count`, `runtime-count`, `sarif-file`. Chain `sarif-file` into `github/codeql-action/upload-sarif` to surface findings in the Security tab. The action uploads nothing by default — it reads the transcript from the workspace, writes a Markdown report to the step summary, and emits severity-aware inline annotations (`::error` for critical/high, `::warning` for medium/low).

---

## Part of the agent-gov suite

Local-only OSS tools that review AI-agent PRs and coding sessions for config drift, policy mismatches, and scope creep. Pick the tool that matches the failure mode; combine via `GovVerdict`.

| Repo | What it catches |
| --- | --- |
| **[ScopeTrail](https://github.com/Conalh/ScopeTrail)** | Diffs agent config files between PR base and head — permission and capability drift. |
| **[PolicyMesh](https://github.com/Conalh/PolicyMesh)** | Audits MCP / Claude / Codex configs for contradictions across agent surfaces. |
| **[CapabilityEcho](https://github.com/Conalh/CapabilityEcho)** | Flags network, subprocess, and capability signals introduced by code diffs. |
| **[TaskBound](https://github.com/Conalh/TaskBound)** | Compares the stated task to the actual diff — scope-creep detection. |
| **SessionTrail** *(this repo)* | Parses Cursor / Claude Code / Codex JSONL transcripts and flags risky runtime behavior. |
| **[GovVerdict](https://github.com/Conalh/GovVerdict)** | Merges JSON reports from the tools above into a single PR verdict. |
| **[agent-gov-core](https://github.com/Conalh/agent-gov-core)** | Shared parsers, the canonical `Finding` schema, and `mergeFindings`. |
| **[agent-gov-demo](https://github.com/Conalh/agent-gov-demo)** | Demo sandbox with a rogue PR that fires all five tools. |

See the full stack fire on one rogue PR: **[agent-gov-demo#1](https://github.com/Conalh/agent-gov-demo/pull/1)**.
