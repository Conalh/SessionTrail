export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  kind: string;
  severity: Severity;
  file: string;
  line?: number;
  subject: string;
  message: string;
  recommendation: string;
}

export interface ToolEvent {
  tool: string;
  line: number;
  turn: number;
  input: Record<string, unknown>;
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
  toolUsage: Record<string, number>;
  pathAccess: PathAccess[];
}
