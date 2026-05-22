#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { passesSeverityThreshold } from 'agent-gov-core';
import { runSessionAudit } from './audit.js';
import { renderReport, type ReportFormat } from './report.js';
import type { Severity } from './types.js';

type FailOn = 'none' | Severity;
const FAIL_ON_VALUES: readonly FailOn[] = ['none', 'low', 'medium', 'high', 'critical'];

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

  // Side outputs land in files; the chosen --format still goes to stdout
  // so consumers like the GitHub Action can stream annotations directly.
  if (parsed.jsonOut) {
    await writeFile(parsed.jsonOut, renderReport(report, 'json'));
  }
  if (parsed.markdownOut) {
    await writeFile(parsed.markdownOut, renderReport(report, 'markdown'));
  }
  if (parsed.sarifOut) {
    await writeFile(parsed.sarifOut, renderReport(report, 'sarif'));
  }

  process.stdout.write(renderReport(report, parsed.format));

  // --fail-on mirrors the GitHub Action's threshold logic via core's
  // passesSeverityThreshold, so local runs and CI exit-code the same.
  // rating='none' means no findings → always pass; otherwise compare.
  if (parsed.failOn !== 'none' && report.rating !== 'none') {
    if (passesSeverityThreshold(report.rating, parsed.failOn)) {
      process.stderr.write(
        `SessionTrail behavior rating ${report.rating} meets fail-on threshold ${parsed.failOn}.\n`
      );
      return 1;
    }
  }

  return 0;
}

interface AuditFlags {
  format: ReportFormat;
  jsonOut?: string;
  markdownOut?: string;
  sarifOut?: string;
  failOn: FailOn;
}

type ParsedAuditArgs =
  | ({ ok: true; mode: 'transcript'; transcriptPath: string; repoRoot: string } & AuditFlags)
  | ({ ok: true; mode: 'directory'; transcriptDir: string; repoRoot: string } & AuditFlags)
  | { ok: false; error: string };

function parseAuditArgs(argv: string[]): ParsedAuditArgs {
  let transcriptPath: string | undefined;
  let transcriptDir: string | undefined;
  let repoRoot = process.cwd();
  let format: ReportFormat = 'text';
  let jsonOut: string | undefined;
  let markdownOut: string | undefined;
  let sarifOut: string | undefined;
  let failOn: FailOn = 'none';

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
    } else if (arg === '--json-out') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --json-out.' };
      }
      jsonOut = value;
      index += 1;
    } else if (arg === '--markdown-out') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --markdown-out.' };
      }
      markdownOut = value;
      index += 1;
    } else if (arg === '--sarif-out') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --sarif-out.' };
      }
      sarifOut = value;
      index += 1;
    } else if (arg === '--fail-on') {
      if (!isFailOn(value)) {
        return { ok: false, error: `Invalid fail-on value: ${value ?? ''}. Use none, low, medium, high, or critical.` };
      }
      failOn = value;
      index += 1;
    } else {
      return { ok: false, error: `Unknown argument: ${arg}` };
    }
  }

  if (transcriptPath && transcriptDir) {
    return { ok: false, error: 'Use either --transcript or --transcript-dir, not both.' };
  }

  if (transcriptDir) {
    return { ok: true, mode: 'directory', transcriptDir, repoRoot, format, jsonOut, markdownOut, sarifOut, failOn };
  }

  if (!transcriptPath) {
    return { ok: false, error: 'Missing required --transcript <path> or --transcript-dir <dir> argument.' };
  }

  return { ok: true, mode: 'transcript', transcriptPath, repoRoot, format, jsonOut, markdownOut, sarifOut, failOn };
}

function isReportFormat(value: string | undefined): value is ReportFormat {
  return (
    value === 'text' ||
    value === 'markdown' ||
    value === 'json' ||
    value === 'github' ||
    value === 'sarif'
  );
}

function isFailOn(value: string | undefined): value is FailOn {
  return typeof value === 'string' && (FAIL_ON_VALUES as readonly string[]).includes(value);
}

const invokedPath = process.argv[1] ? fileURLToPath(import.meta.url) === process.argv[1] : false;

if (invokedPath) {
  process.exitCode = await main();
}

function usage(): string {
  return [
    'Usage:',
    '  sessiontrail audit --transcript <path> --repo <path> [options]',
    '  sessiontrail audit --transcript-dir <dir> --repo <path> [options]',
    '',
    'Options:',
    '  --format text|markdown|json|github|sarif  Format for stdout (default: text)',
    '  --json-out <path>                         Also write JSON report to <path>',
    '  --markdown-out <path>                     Also write Markdown report to <path>',
    '  --sarif-out <path>                        Also write SARIF 2.1.0 report to <path>',
    '  --fail-on none|low|medium|high|critical   Exit 1 if rating meets threshold (default: none)'
  ].join('\n');
}
