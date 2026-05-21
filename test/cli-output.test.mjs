import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
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
  assert.ok(report.findings.some((finding) => finding.kind === 'write_outside_repo'));
  assert.ok(report.findings.some((finding) => finding.kind === 'shell_command_invoked'));
  assert.ok(report.findings.some((finding) => finding.kind === 'transcript_cross_read'));
  assert.ok(report.pathHeatMap.length >= 3);
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

test('CLI emits GitHub warning annotations', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'github'],
    { cwd: packageRoot }
  );

  assert.match(stdout, /::warning file=session,line=/);
  assert.match(stdout, /outside-repo\.txt/);
});
