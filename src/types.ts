// Single source of truth for the Finding schema and Runtime union across the
// agent-gov suite lives in agent-gov-core. SessionTrail re-exports them here
// so internal imports stay stable and downstream meta-reviewers can dedupe
// findings from every suite tool against a shared shape. AgentRuntime is just
// core's Runtime under a local name — aliasing avoids a second copy that
// silently drifts when core adds a runtime (e.g. 'antigravity' in v1.2.0).
import type { Runtime } from 'agent-gov-core';

export type { Finding, Severity } from 'agent-gov-core';

export type AgentRuntime = Runtime;

export interface ToolEvent {
  tool: string;
  runtime: AgentRuntime;
  line: number;
  turn: number;
  input: Record<string, unknown>;
  source?: string;
  // The agent's recorded working directory at the time of this event.
  // Claude Code transcripts carry this per-message; older Cursor and
  // Codex transcripts may not. When present, the detector uses it as
  // the base for resolving relative paths so a relative `package.json`
  // is judged from the agent's cwd rather than the audit CLI's cwd.
  cwd?: string;
}

export interface PathAccess {
  path: string;
  reads: number;
  writes: number;
}

export interface SessionContext {
  transcriptPath: string;
  repoRoot: string;
  events: ToolEvent[];
  runtimeUsage: Record<AgentRuntime, number>;
  toolUsage: Record<string, number>;
  pathAccess: PathAccess[];
}
