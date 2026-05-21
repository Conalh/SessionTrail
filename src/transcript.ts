import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { normalizePath } from './paths.js';
import type { AgentRuntime, ToolEvent } from './types.js';

interface TranscriptMessage {
  role?: string;
  type?: string;
  cwd?: string;
  sessionId?: string;
  version?: string;
  source?: string;
  message?: {
    content?: Array<{
      type?: string;
      name?: string;
      input?: Record<string, unknown>;
    }>;
  };
}

interface CodexResponseItem {
  type?: string;
  payload?: {
    type?: string;
    name?: string;
    arguments?: unknown;
  };
}

export async function loadTranscriptEvents(transcriptPath: string): Promise<ToolEvent[]> {
  const raw = await readFile(transcriptPath, 'utf8');
  return parseTranscriptEvents(raw);
}

export async function loadTranscriptDirectory(directory: string): Promise<ToolEvent[]> {
  const files = await listJsonlFiles(directory);
  const events: ToolEvent[] = [];

  for (const file of files) {
    events.push(...(await loadTranscriptEvents(file)));
  }

  return events;
}

export function parseTranscriptEvents(raw: string): ToolEvent[] {
  const events: ToolEvent[] = [];
  let turn = 0;
  let sessionRuntime: AgentRuntime = 'unknown';

  for (const [index, line] of raw.split(/\r?\n/).entries()) {
    if (!line.trim()) {
      continue;
    }

    let parsed: TranscriptMessage;
    try {
      parsed = JSON.parse(line) as TranscriptMessage;
    } catch {
      continue;
    }

    if (isCodexSessionMeta(parsed)) {
      sessionRuntime = 'codex';
      continue;
    }

    const codexEvent = parseCodexFunctionCall(parsed as CodexResponseItem, index + 1, turn);
    if (codexEvent) {
      events.push(codexEvent);
      continue;
    }

    const runtime = detectAnthropicRuntime(parsed, sessionRuntime);

    if (parsed.role === 'assistant' || parsed.type === 'assistant') {
      turn += 1;
    }

    const blocks = parsed.message?.content ?? [];
    for (const block of blocks) {
      if (block.type !== 'tool_use' || !block.name) {
        continue;
      }

      events.push({
        tool: block.name,
        runtime,
        line: index + 1,
        turn,
        input: block.input ?? {}
      });
    }
  }

  return events;
}

function countToolUsage(events: ToolEvent[]): Record<string, number> {
  const usage: Record<string, number> = {};
  for (const event of events) {
    usage[event.tool] = (usage[event.tool] ?? 0) + 1;
  }
  return usage;
}

function countRuntimeUsage(events: ToolEvent[]): Record<AgentRuntime, number> {
  const usage: Record<AgentRuntime, number> = {
    cursor: 0,
    'claude-code': 0,
    codex: 0,
    unknown: 0
  };

  for (const event of events) {
    usage[event.runtime] += 1;
  }

  return usage;
}

export function buildPathAccess(events: ToolEvent[]): Array<{ path: string; reads: number; writes: number }> {
  const access = new Map<string, { path: string; reads: number; writes: number }>();

  for (const event of events) {
    const paths = extractPathsFromEvent(event);
    for (const entry of paths) {
      const current = access.get(entry.path) ?? { path: entry.path, reads: 0, writes: 0 };
      if (entry.kind === 'read') {
        current.reads += 1;
      } else {
        current.writes += 1;
      }
      access.set(entry.path, current);
    }
  }

  return [...access.values()].sort((left, right) => left.path.localeCompare(right.path));
}

export function summarizeSession(events: ToolEvent[]) {
  return {
    runtimeUsage: countRuntimeUsage(events),
    toolUsage: countToolUsage(events),
    pathAccess: buildPathAccess(events)
  };
}

function extractPathsFromEvent(event: ToolEvent): Array<{ path: string; kind: 'read' | 'write' }> {
  const input = event.input;
  const results: Array<{ path: string; kind: 'read' | 'write' }> = [];

  const add = (value: unknown, kind: 'read' | 'write') => {
    if (typeof value === 'string' && value.trim()) {
      results.push({ path: normalizePath(value), kind });
    }
  };

  switch (event.tool) {
    case 'Read':
    case 'ReadLints':
      add(input.path, 'read');
      add(input.file_path, 'read');
      if (Array.isArray(input.paths)) {
        for (const path of input.paths) {
          add(path, 'read');
        }
      }
      break;
    case 'Write':
    case 'StrReplace':
    case 'Delete':
    case 'Edit':
    case 'MultiEdit':
      add(input.path, 'write');
      add(input.file_path, 'write');
      break;
    case 'Grep':
    case 'Glob':
      add(input.path ?? input.target_directory, 'read');
      break;
    case 'Shell':
      add(input.working_directory, 'read');
      break;
    default:
      if (isShellTool(event.tool)) {
        add(input.working_directory ?? input.workdir ?? input.cwd, 'read');
      } else if (toolKey(event.tool) === 'view_image') {
        add(input.path, 'read');
      } else if (toolKey(event.tool) === 'apply_patch') {
        for (const path of extractPatchPaths(input.patch)) {
          add(path, 'write');
        }
      }
      break;
  }

  return results;
}

function toolKey(tool: string): string {
  return (tool.split('.').pop() ?? tool).toLowerCase();
}

function isShellTool(tool: string): boolean {
  const key = toolKey(tool);
  return key === 'shell' || key === 'bash' || key === 'shell_command';
}

function extractPatchPaths(value: unknown): string[] {
  if (typeof value !== 'string') {
    return [];
  }

  const paths: string[] = [];
  const pattern = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    paths.push(match[1].trim());
  }
  return paths;
}

function isCodexSessionMeta(parsed: TranscriptMessage): boolean {
  if (parsed.type !== 'session_meta') {
    return false;
  }

  const payload = (parsed as { payload?: { originator?: unknown; source?: unknown } }).payload;
  return payload?.originator === 'codex-tui' || payload?.source === 'cli';
}

function parseCodexFunctionCall(parsed: CodexResponseItem, line: number, turn: number): ToolEvent | undefined {
  if (parsed.type !== 'response_item' || parsed.payload?.type !== 'function_call' || !parsed.payload.name) {
    return undefined;
  }

  return {
    tool: parsed.payload.name,
    runtime: 'codex',
    line,
    turn,
    input: parseCodexArguments(parsed.payload.arguments)
  };
}

function parseCodexArguments(value: unknown): Record<string, unknown> {
  if (isRecord(value)) {
    return value;
  }

  if (typeof value !== 'string') {
    return {};
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (isRecord(parsed)) {
      return parsed;
    }
  } catch {
    // Freeform tool arguments such as apply_patch are intentionally not JSON.
  }

  return { patch: value };
}

function detectAnthropicRuntime(parsed: TranscriptMessage, sessionRuntime: AgentRuntime): AgentRuntime {
  if (sessionRuntime !== 'unknown') {
    return sessionRuntime;
  }

  if (
    parsed.source === 'claude-code' ||
    typeof parsed.sessionId === 'string' ||
    typeof parsed.cwd === 'string' ||
    typeof parsed.version === 'string' ||
    parsed.type === 'assistant' ||
    parsed.type === 'user'
  ) {
    return 'claude-code';
  }

  if (parsed.role || parsed.message) {
    return 'cursor';
  }

  return 'unknown';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function listJsonlFiles(directory: string, current = ''): Promise<string[]> {
  const entries = await readdir(join(directory, current), { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const relativePath = current ? `${current}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      files.push(...(await listJsonlFiles(directory, relativePath)));
      continue;
    }

    if (entry.name.endsWith('.jsonl')) {
      files.push(join(directory, relativePath));
    }
  }

  return files;
}
