import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  isCodexLine,
  isCodexSessionMeta,
  parseAnthropicLine,
  parseCodexLine,
  type Runtime,
  type TranscriptEvent
} from 'agent-gov-core';
import { normalizePath } from './paths.js';
import { collectEventPaths, extractShellPaths, isShellTool } from './tool-paths.js';
import type { AgentRuntime, ToolEvent } from './types.js';

// Surface counts so users can see when a transcript was partially
// parsed. Audit tools that silently skip malformed lines hide signal —
// a corrupted middle-of-file event could be the one that matters.
export interface ParseStats {
  linesRead: number;
  eventsExtracted: number;
  linesSkipped: number;
}

export interface ParsedTranscript {
  events: ToolEvent[];
  stats: ParseStats;
}

export async function loadTranscriptEvents(transcriptPath: string): Promise<ToolEvent[]> {
  return (await loadTranscriptEventsWithStats(transcriptPath)).events;
}

export async function loadTranscriptEventsWithStats(transcriptPath: string): Promise<ParsedTranscript> {
  const raw = await readFile(transcriptPath, 'utf8');
  return parseTranscriptEventsWithStats(raw, transcriptPath);
}

export async function loadTranscriptDirectory(directory: string): Promise<ToolEvent[]> {
  return (await loadTranscriptDirectoryWithStats(directory)).events;
}

export async function loadTranscriptDirectoryWithStats(directory: string): Promise<ParsedTranscript> {
  const files = await listJsonlFiles(directory);
  const events: ToolEvent[] = [];
  const stats: ParseStats = { linesRead: 0, eventsExtracted: 0, linesSkipped: 0 };

  for (const file of files) {
    const parsed = await loadTranscriptEventsWithStats(file);
    events.push(...parsed.events);
    stats.linesRead += parsed.stats.linesRead;
    stats.eventsExtracted += parsed.stats.eventsExtracted;
    stats.linesSkipped += parsed.stats.linesSkipped;
  }

  return { events, stats };
}

export function parseTranscriptEvents(raw: string, source?: string): ToolEvent[] {
  return parseTranscriptEventsWithStats(raw, source).events;
}

// SessionTrail keeps its own line-by-line walk so each ToolEvent can carry the
// transcript line number and source path that every finding's location depends
// on — agent-gov-core's TranscriptEvent is keyed on timestamp and intentionally
// drops both. The per-line *parsing* (runtime detection, Codex argument
// coercion, apply_patch handling) is delegated to core so this tool no longer
// vendors a second copy that drifts from the shared parser surface.
export function parseTranscriptEventsWithStats(raw: string, source?: string): ParsedTranscript {
  const events: ToolEvent[] = [];
  const stats: ParseStats = { linesRead: 0, eventsExtracted: 0, linesSkipped: 0 };
  let turn = 0;
  let sessionRuntime: Runtime = 'unknown';

  for (const [index, line] of raw.split(/\r?\n/).entries()) {
    if (!line.trim()) {
      continue;
    }

    stats.linesRead += 1;

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Malformed JSON line — almost always a truncated transcript.
      // Counting it is the difference between an audit user noticing
      // partial data and silently trusting a half-parsed file.
      stats.linesSkipped += 1;
      continue;
    }

    if (isCodexSessionMeta(parsed)) {
      sessionRuntime = 'codex';
      continue;
    }

    // A new turn begins at each assistant line, so tool calls inside that
    // message share its turn number. Read off the raw line rather than the
    // parsed events to preserve the exact pre-core numbering.
    const lineRecord = parsed as { type?: unknown; role?: unknown };
    if (lineRecord.type === 'assistant' || lineRecord.role === 'assistant') {
      turn += 1;
    }

    const parsedEvents: TranscriptEvent[] | null = isCodexLine(parsed)
      ? parseCodexLine(parsed)
      : parseAnthropicLine(parsed, sessionRuntime === 'unknown' ? undefined : sessionRuntime);

    if (!parsedEvents) {
      continue;
    }

    const lineNumber = index + 1;
    for (const event of parsedEvents) {
      if (event.kind !== 'tool_use' || !event.toolName) {
        continue;
      }

      events.push({
        tool: event.toolName,
        runtime: event.runtime,
        line: lineNumber,
        turn,
        input: event.toolInput ?? {},
        source,
        cwd: event.cwd
      });
      stats.eventsExtracted += 1;
    }
  }

  return { events, stats };
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
    antigravity: 0,
    unknown: 0
  };

  for (const event of events) {
    usage[event.runtime] = (usage[event.runtime] ?? 0) + 1;
  }

  return usage;
}

export function buildPathAccess(events: ToolEvent[]): Array<{ path: string; reads: number; writes: number }> {
  const access = new Map<string, { path: string; reads: number; writes: number }>();
  const bump = (rawPath: string, kind: 'read' | 'write') => {
    const path = normalizePath(rawPath);
    const current = access.get(path) ?? { path, reads: 0, writes: 0 };
    if (kind === 'read') {
      current.reads += 1;
    } else {
      current.writes += 1;
    }
    access.set(path, current);
  };

  for (const event of events) {
    for (const entry of collectEventPaths(event)) {
      bump(entry.path, entry.kind);
    }
    // Shell-extracted paths previously only showed up as findings — the
    // heat map missed them, so a `cat /home/u/.ssh/id_rsa` left no
    // evidence in the heat-map section even though it produced a
    // privileged-path finding. Counted as reads (extraction can't
    // distinguish read from write in a shell command body).
    if (isShellTool(event.tool)) {
      const command = typeof event.input.command === 'string' ? event.input.command : '';
      for (const shellPath of extractShellPaths(command)) {
        bump(shellPath, 'read');
      }
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

async function listJsonlFiles(directory: string, current = ''): Promise<string[]> {
  const entries = await readdir(join(directory, current), { withFileTypes: true });
  const files: string[] = [];

  // readdir order is filesystem-dependent — sorting by name gives
  // stable finding order and stable diffs across platforms / runs.
  // Lexicographic sort is fine here; we're not aiming for natural
  // sort of numeric suffixes, just determinism.
  const sortedEntries = [...entries].sort((a, b) => a.name.localeCompare(b.name));

  for (const entry of sortedEntries) {
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
