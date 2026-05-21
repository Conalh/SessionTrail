import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { ToolEvent } from './types.js';

interface TranscriptMessage {
  role?: string;
  message?: {
    content?: Array<{
      type?: string;
      name?: string;
      input?: Record<string, unknown>;
    }>;
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

    if (parsed.role === 'assistant') {
      turn += 1;
    }

    const blocks = parsed.message?.content ?? [];
    for (const block of blocks) {
      if (block.type !== 'tool_use' || !block.name) {
        continue;
      }

      events.push({
        tool: block.name,
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
    toolUsage: countToolUsage(events),
    pathAccess: buildPathAccess(events)
  };
}

function extractPathsFromEvent(event: ToolEvent): Array<{ path: string; kind: 'read' | 'write' }> {
  const input = event.input;
  const results: Array<{ path: string; kind: 'read' | 'write' }> = [];

  const add = (value: unknown, kind: 'read' | 'write') => {
    if (typeof value === 'string' && value.trim()) {
      results.push({ path: value, kind });
    }
  };

  switch (event.tool) {
    case 'Read':
    case 'ReadLints':
      add(input.path, 'read');
      if (Array.isArray(input.paths)) {
        for (const path of input.paths) {
          add(path, 'read');
        }
      }
      break;
    case 'Write':
    case 'StrReplace':
    case 'Delete':
      add(input.path, 'write');
      break;
    case 'Grep':
    case 'Glob':
      add(input.path ?? input.target_directory, 'read');
      break;
    case 'Shell':
      if (typeof input.working_directory === 'string') {
        add(input.working_directory, 'read');
      }
      break;
    default:
      break;
  }

  return results;
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
