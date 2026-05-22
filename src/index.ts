#!/usr/bin/env node

import { fileURLToPath } from 'node:url';
import { runSessionAudit } from './audit.js';
import { renderReport, type ReportFormat } from './report.js';

export async function main(argv = process.argv.slice(2)): Promise<number> {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }

  if (argv[0] === 'audit') {
    return runAuditCommand(argv.slice(1));
  }

  process.stderr.write(`Unknown command: ${argv[0]}\n`);
  return 2;
}

async function runAuditCommand(argv: string[]): Promise<number> {
  const parsed = parseAuditArgs(argv);
  if (!parsed.ok) {
    process.stderr.write(`${parsed.error}\n${usage()}\n`);
    return 2;
  }

  const report =
    parsed.mode === 'transcript'
      ? await runSessionAudit({ mode: 'transcript', transcriptPath: parsed.transcriptPath, repoRoot: parsed.repoRoot })
      : await runSessionAudit({ mode: 'directory', transcriptDir: parsed.transcriptDir, repoRoot: parsed.repoRoot });

  process.stdout.write(renderReport(report, parsed.format));
  return 0;
}

type ParsedAuditArgs =
  | { ok: true; mode: 'transcript'; transcriptPath: string; repoRoot: string; format: ReportFormat }
  | { ok: true; mode: 'directory'; transcriptDir: string; repoRoot: string; format: ReportFormat }
  | { ok: false; error: string };

function parseAuditArgs(argv: string[]): ParsedAuditArgs {
  let transcriptPath: string | undefined;
  let transcriptDir: string | undefined;
  let repoRoot = process.cwd();
  let format: ReportFormat = 'text';

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = argv[index + 1];

    if (arg === '--transcript') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --transcript.' };
      }
      transcriptPath = value;
      index += 1;
    } else if (arg === '--transcript-dir') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --transcript-dir.' };
      }
      transcriptDir = value;
      index += 1;
    } else if (arg === '--repo') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --repo.' };
      }
      repoRoot = value;
      index += 1;
    } else if (arg === '--format') {
      if (!isReportFormat(value)) {
        return { ok: false, error: `Invalid format: ${value ?? ''}` };
      }
      format = value;
      index += 1;
    } else {
      return { ok: false, error: `Unknown argument: ${arg}` };
    }
  }

  if (transcriptPath && transcriptDir) {
    return { ok: false, error: 'Use either --transcript or --transcript-dir, not both.' };
  }

  if (transcriptDir) {
    return { ok: true, mode: 'directory', transcriptDir, repoRoot, format };
  }

  if (!transcriptPath) {
    return { ok: false, error: 'Missing required --transcript <path> or --transcript-dir <dir> argument.' };
  }

  return { ok: true, mode: 'transcript', transcriptPath, repoRoot, format };
}

function isReportFormat(value: string | undefined): value is ReportFormat {
  return value === 'text' || value === 'markdown' || value === 'json' || value === 'github';
}

const invokedPath = process.argv[1] ? fileURLToPath(import.meta.url) === process.argv[1] : false;

if (invokedPath) {
  process.exitCode = await main();
}

function usage(): string {
  return [
    'Usage:',
    '  sessiontrail audit --transcript <path> --repo <path> [--format text|markdown|json|github]',
    '  sessiontrail audit --transcript-dir <dir> --repo <path> [--format text|markdown|json|github]'
  ].join('\n');
}
