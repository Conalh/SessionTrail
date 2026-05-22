export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type AgentRuntime = 'cursor' | 'claude-code' | 'codex' | 'unknown';

export interface Finding {
  kind: string;
  severity: Severity;
  // The thing the agent touched — for path findings this is the accessed
  // target, for behavior findings (shell/mcp/network/subagent) it's
  // literal 'session'. Surfaced in markdown/text and in the annotation
  // message body.
  file: string;
  line?: number;
  // The transcript file where the underlying event was recorded.
  // Optional for back-compat with parseTranscriptEvents callers that
  // don't pass a source. Used as the annotation anchor in GitHub output
  // so warnings attach to a real, locatable file rather than to a path
  // that isn't in the workspace (e.g. /home/u/.ssh/id_rsa).
  source?: string;
  subject: string;
  message: string;
  recommendation: string;
}

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
