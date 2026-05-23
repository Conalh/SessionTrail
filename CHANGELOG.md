# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Under v1.0, minor versions may carry breaking changes.

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
