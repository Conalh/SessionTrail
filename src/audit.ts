import { createFinding } from 'agent-gov-core';
import { loadAllowlist } from './config.js';
import { detectSessionBehavior } from './detectors/session-behavior.js';
import {
  loadTranscriptDirectoryWithStats,
  loadTranscriptEventsWithStats,
  summarizeSession,
  type ParseStats
} from './transcript.js';
import { createReport, type SessionReport } from './report.js';
import type { Finding } from './types.js';

export type AuditInput =
  | { mode: 'transcript'; transcriptPath: string; repoRoot: string }
  | { mode: 'directory'; transcriptDir: string; repoRoot: string };

export async function runSessionAudit(options: AuditInput): Promise<SessionReport> {
  const parsed =
    options.mode === 'transcript'
      ? await loadTranscriptEventsWithStats(options.transcriptPath)
      : await loadTranscriptDirectoryWithStats(options.transcriptDir);

  const allowlist = await loadAllowlist(options.repoRoot);
  const summary = summarizeSession(parsed.events);
  const transcriptPath = options.mode === 'transcript' ? options.transcriptPath : options.transcriptDir;
  const findings: Finding[] = [
    ...parseSkipFindings(parsed.stats, transcriptPath),
    ...detectSessionBehavior(options.repoRoot, parsed.events, allowlist)
  ];

  return createReport(findings, {
    transcriptPath,
    repoRoot: options.repoRoot,
    events: parsed.events,
    runtimeUsage: summary.runtimeUsage,
    toolUsage: summary.toolUsage,
    pathAccess: summary.pathAccess,
    parseStats: parsed.stats
  });
}

// Parse skips usually mean a truncated or corrupted transcript. Surfacing
// the count in markdown is good; promoting it to a finding lets
// `--fail-on low` catch the case instead of relying on someone reading
// the report header.
function parseSkipFindings(stats: ParseStats, transcriptPath: string): Finding[] {
  if (stats.linesSkipped <= 0) {
    return [];
  }
  return [createFinding({
    tool: 'session_trail',
    name: 'parse_lines_skipped',
    severity: 'low',
    message: `Parser skipped ${stats.linesSkipped} malformed line${stats.linesSkipped === 1 ? '' : 's'} (${stats.linesRead} read total).`,
    detail: 'A truncated or corrupted transcript can hide events. Review the source file before trusting the audit result.',
    location: { file: transcriptPath },
    data: { linesRead: stats.linesRead, linesSkipped: stats.linesSkipped, eventsExtracted: stats.eventsExtracted },
    salientKey: `${transcriptPath}:${stats.linesSkipped}`
  })];
}
