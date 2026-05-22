// Single source of truth for the Finding schema across the agent-gov suite
// lives in agent-gov-core. SessionTrail re-exports it here so internal
// imports stay stable and downstream meta-reviewers can dedupe findings
// from every suite tool against a shared shape.
export type { Finding, Severity } from 'agent-gov-core';

export type AgentRuntime = 'cursor' | 'claude-code' | 'codex' | 'unknown';

export interface ToolEvent {
  tool: string;
  runtime: AgentRuntime;
  line: number;
  turn: number;
  input: Record<string, unknown>;
  source?: string;
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
