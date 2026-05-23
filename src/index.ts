#!/usr/bin/env node

import { stat, writeFile } from 'node:fs/promises';
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

  // Fast input validation. Without these checks, the failure mode was a
  // stack trace (file missing) or an empty report (repo missing) — both
  // user-hostile. Bail with exit 2 and a one-line message instead.
  const validation = await validateInputs(parsed);
  if (validation) {
    process.stderr.write(`${validation}\n`);
    return 2;
  }

  const report =
    parsed.mode === 'transcript'
      ? await runSessionAudit({ mode: 'transcript', transcriptPath: parsed.transcriptPath, repoRoot: parsed.repoRoot, configPath: parsed.configPath })
      : await runSessionAudit({ mode: 'directory', transcriptDir: parsed.transcriptDir, repoRoot: parsed.repoRoot, configPath: parsed.configPath });

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
  configPath?: string;
  failOn: FailOn;
}

async function validateInputs(
  parsed: Extract<ParsedAuditArgs, { ok: true }>
): Promise<string | undefined> {
  // --repo is intentionally NOT validated. It's a classification anchor,
  // not a directory we read: a Windows-recorded transcript can be
  // audited against a synthetic `C:/Dev/Demo` repo root on a Linux
  // runner where that path doesn't exist as a real directory. The path
  // comparison logic still works (string-level normalization), so
  // requiring the directory to exist would block a legitimate
  // cross-environment audit workflow.

  if (parsed.mode === 'transcript') {
    try {
      const stats = await stat(parsed.transcriptPath);
      if (!stats.isFile()) {
        return `--transcript path is not a file: ${parsed.transcriptPath}`;
      }
    } catch {
      return `--transcript file does not exist: ${parsed.transcriptPath}`;
    }
  } else {
    try {
      const stats = await stat(parsed.transcriptDir);
      if (!stats.isDirectory()) {
        return `--transcript-dir is not a directory: ${parsed.transcriptDir}`;
      }
    } catch {
      return `--transcript-dir does not exist: ${parsed.transcriptDir}`;
    }
  }

  if (parsed.configPath) {
    try {
      const stats = await stat(parsed.configPath);
      if (!stats.isFile()) {
        return `--config path is not a file: ${parsed.configPath}`;
      }
    } catch {
      return `--config file does not exist: ${parsed.configPath}`;
    }
  }

  return undefined;
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
  let configPath: string | undefined;
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
    } else if (arg === '--config') {
      if (typeof value !== 'string') {
        return { ok: false, error: 'Missing value for --config.' };
      }
      configPath = value;
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
    return { ok: true, mode: 'directory', transcriptDir, repoRoot, format, jsonOut, markdownOut, sarifOut, configPath, failOn };
  }

  if (!transcriptPath) {
    return { ok: false, error: 'Missing required --transcript <path> or --transcript-dir <dir> argument.' };
  }

  return { ok: true, mode: 'transcript', transcriptPath, repoRoot, format, jsonOut, markdownOut, sarifOut, configPath, failOn };
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
    '  --config <path>                           Allowlist file (default: <repo>/.sessiontrail.json)',
    '  --fail-on none|low|medium|high|critical   Exit 1 if rating meets threshold (default: none)'
  ].join('\n');
}
