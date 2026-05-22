import { loadAllowlist } from './config.js';
import { detectSessionBehavior } from './detectors/session-behavior.js';
import { loadTranscriptDirectory, loadTranscriptEvents, summarizeSession } from './transcript.js';
import { createReport, type SessionReport } from './report.js';

export type AuditInput =
  | { mode: 'transcript'; transcriptPath: string; repoRoot: string }
  | { mode: 'directory'; transcriptDir: string; repoRoot: string };

export async function runSessionAudit(options: AuditInput): Promise<SessionReport> {
  const events =
    options.mode === 'transcript'
      ? await loadTranscriptEvents(options.transcriptPath)
      : await loadTranscriptDirectory(options.transcriptDir);

  const allowlist = await loadAllowlist(options.repoRoot);
  const summary = summarizeSession(events);
  const findings = detectSessionBehavior(options.repoRoot, events, allowlist);
  const transcriptPath = options.mode === 'transcript' ? options.transcriptPath : options.transcriptDir;

  return createReport(findings, {
    transcriptPath,
    repoRoot: options.repoRoot,
    events,
    runtimeUsage: summary.runtimeUsage,
    toolUsage: summary.toolUsage,
    pathAccess: summary.pathAccess
  });
}
