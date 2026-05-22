import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, rm, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const execFileAsync = promisify(execFile);
const testDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(testDir, '..');
const REPO = 'C:/Dev/Demo';

test('CLI returns none for benign session transcript', async () => {
  const transcript = join(testDir, 'fixtures', 'benign-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'json'],
    { cwd: packageRoot }
  );
  const report = JSON.parse(stdout);

  assert.equal(report.rating, 'none');
  assert.equal(report.findingCount, 0);
  assert.ok(report.toolInvocationCount >= 3);
});

test('CLI flags rogue session behavior', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'json'],
    { cwd: packageRoot }
  );
  const report = JSON.parse(stdout);

  assert.equal(report.rating, 'critical');
  assert.ok(report.findingCount >= 6);
  assert.ok(report.behaviorSummary.length >= 4);
  assert.ok(report.findings.some((finding) => finding.kind === 'session_trail.write_outside_repo'));
  assert.ok(report.findings.some((finding) => finding.kind === 'session_trail.shell_command_invoked'));
  assert.ok(report.findings.some((finding) => finding.kind === 'session_trail.transcript_cross_read'));
  assert.ok(report.pathHeatMap.length >= 3);
});

test('Markdown heat map shows (+N more) when truncated past 12 entries', async () => {
  const { createReport, renderReport } = await import('../dist/report.js');
  // Build a report with 20 distinct paths to exercise the truncation.
  const pathAccess = Array.from({ length: 20 }, (_, i) => ({
    path: `C:/Dev/Demo/file-${String(i).padStart(2, '0')}.ts`,
    reads: 1,
    writes: 0
  }));
  // Need at least one finding so the heat map section renders.
  const findings = [{
    tool: 'session_trail',
    kind: 'session_trail.shell_command_invoked',
    severity: 'low',
    message: 'Shell command: pwd',
    location: { file: 'fixture.jsonl', line: 1 }
  }];
  const report = createReport(findings, {
    transcriptPath: 'fixture.jsonl',
    repoRoot: REPO,
    events: [],
    runtimeUsage: { cursor: 0, 'claude-code': 0, codex: 0, unknown: 0 },
    toolUsage: {},
    pathAccess
  });
  const md = renderReport(report, 'markdown');
  assert.match(md, /\(\+8 more\)/);
});

test('CLI emits Markdown behavior summary and heat map', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'markdown'],
    { cwd: packageRoot }
  );

  assert.match(stdout, /# SessionTrail behavior review: CRITICAL/);
  assert.match(stdout, /Behavior summary/);
  assert.match(stdout, /Path heat map/);
  assert.match(stdout, /shell command invocations/);
  assert.doesNotMatch(stdout, /session_trail\.shell_command_invoked/);
});

test('CLI emits Markdown runtime summary when no findings are present', async () => {
  const transcript = join(testDir, 'fixtures', 'benign-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'markdown'],
    { cwd: packageRoot }
  );

  assert.match(stdout, /# SessionTrail behavior review: NONE/);
  assert.match(stdout, /Agent runtimes: cursor x3/);
  assert.match(stdout, /No session behavior findings\./);
});

test('CLI emits stdout, JSON file, and Markdown file in a single pass', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');
  const tempDir = await mkdtemp(join(tmpdir(), 'sessiontrail-cli-'));
  const jsonPath = join(tempDir, 'report.json');
  const mdPath = join(tempDir, 'report.md');

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [
        'dist/index.js', 'audit',
        '--transcript', transcript,
        '--repo', REPO,
        '--format', 'github',
        '--json-out', jsonPath,
        '--markdown-out', mdPath
      ],
      { cwd: packageRoot }
    );

    // stdout still carries the --format output (GitHub annotations here).
    assert.match(stdout, /::warning file=/);

    const jsonReport = JSON.parse(await readFile(jsonPath, 'utf8'));
    assert.equal(jsonReport.rating, 'critical');

    const markdownReport = await readFile(mdPath, 'utf8');
    assert.match(markdownReport, /# SessionTrail behavior review: CRITICAL/);
    assert.match(markdownReport, /Behavior summary/);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('CLI rejects --repo with no value instead of crashing', async () => {
  const transcript = join(testDir, 'fixtures', 'benign-session.jsonl');

  await assert.rejects(
    execFileAsync(
      process.execPath,
      ['dist/index.js', 'audit', '--transcript', transcript, '--repo'],
      { cwd: packageRoot }
    ),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Missing value for --repo\./);
      assert.doesNotMatch(error.stderr, /ERR_INVALID_ARG_TYPE/);
      return true;
    }
  );
});

test('CLI emits GitHub annotations with severity-aware ::error vs ::warning', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'github'],
    { cwd: packageRoot }
  );

  // Annotations anchor at the transcript file/line — accessed target
  // lives in the message body. Critical/high → ::error; medium/low →
  // ::warning (handled by agent-gov-core's emitFindingAnnotation).
  assert.match(stdout, /::error [^:]*rogue-session\.jsonl,line=\d+,title=\[session_trail\.write_outside_repo\]/);
  assert.match(stdout, /::warning [^:]*rogue-session\.jsonl,line=\d+,title=\[session_trail\.read_outside_repo\]/);
  assert.match(stdout, /target: C:\/Users\/conno\/outside-repo\.txt/);
});

test('CLI --fail-on exits non-zero when rating meets threshold', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');

  // rogue session is rated critical → should fail at every threshold.
  await assert.rejects(
    execFileAsync(
      process.execPath,
      ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'json', '--fail-on', 'high'],
      { cwd: packageRoot }
    ),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /meets fail-on threshold high/);
      return true;
    }
  );
});

test('CLI --fail-on stays zero when rating is below threshold', async () => {
  const transcript = join(testDir, 'fixtures', 'benign-session.jsonl');

  // benign session has rating=none → never trips fail-on.
  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'json', '--fail-on', 'critical'],
    { cwd: packageRoot }
  );
  const report = JSON.parse(stdout);
  assert.equal(report.rating, 'none');
});
