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
// Synthetic classification anchor. --repo isn't required to exist on
// the audit host (cross-environment workflows audit Windows transcripts
// on Linux runners), so the path here is intentionally a Windows-style
// string the fixtures' paths can be classified against.
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
    pathAccess,
    parseStats: { linesRead: 0, eventsExtracted: 0, linesSkipped: 0 }
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
  // The Behavior summary section must use the friendly label, not the
  // raw kind. The Findings table further down legitimately includes the
  // kind in its Kind column (it's the GitHub Code Scanning grouping
  // field), so scope this check to the summary section only.
  const summarySection = stdout.split('## Behavior summary')[1]?.split('##')[0] ?? '';
  assert.doesNotMatch(summarySection, /session_trail\.shell_command_invoked/);
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

test('CLI emits valid SARIF 2.1.0 with rule, level, location, fingerprint', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');

  const { stdout } = await execFileAsync(
    process.execPath,
    ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'sarif'],
    { cwd: packageRoot }
  );

  const sarif = JSON.parse(stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'SessionTrail');

  // Rules array is derived from the kinds present in the results.
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.ok(ruleIds.includes('session_trail.write_outside_repo'));

  // Spot-check a result row.
  const writeResult = sarif.runs[0].results.find(
    (r) => r.ruleId === 'session_trail.write_outside_repo'
  );
  assert.ok(writeResult);
  assert.equal(writeResult.level, 'error'); // critical → error
  assert.ok(writeResult.locations[0].physicalLocation.artifactLocation.uri.endsWith('rogue-session.jsonl'));
  assert.ok(writeResult.partialFingerprints?.sessionTrail);
  assert.match(writeResult.partialFingerprints.sessionTrail, /^[a-f0-9]{16}$/);

  // Medium severity maps to warning.
  const readResult = sarif.runs[0].results.find(
    (r) => r.ruleId === 'session_trail.read_outside_repo'
  );
  assert.ok(readResult);
  assert.equal(readResult.level, 'warning');
});

test('CLI --sarif-out writes SARIF to file alongside other formats', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');
  const tempDir = await mkdtemp(join(tmpdir(), 'sessiontrail-sarif-'));
  const sarifPath = join(tempDir, 'report.sarif');

  try {
    await execFileAsync(
      process.execPath,
      ['dist/index.js', 'audit', '--transcript', transcript, '--repo', REPO, '--format', 'github', '--sarif-out', sarifPath],
      { cwd: packageRoot }
    );
    const sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.runs[0].results.length > 0);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('CLI bails with exit 2 when --transcript file is missing', async () => {
  await assert.rejects(
    execFileAsync(
      process.execPath,
      ['dist/index.js', 'audit', '--transcript', '/nope/does/not/exist.jsonl', '--repo', REPO, '--format', 'json'],
      { cwd: packageRoot }
    ),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--transcript file does not exist/);
      return true;
    }
  );
});

test('CLI --config flag points the allowlist away from <repo>/.sessiontrail.json', async () => {
  const transcript = join(testDir, 'fixtures', 'rogue-session.jsonl');
  const tempDir = await mkdtemp(join(tmpdir(), 'sessiontrail-config-'));
  const configPath = join(tempDir, 'custom.json');
  try {
    // Use the demo repo path but a config file that doesn't sit at that
    // repo's root. Allowlist the cursor-app-control MCP so its finding
    // drops to low; if the override worked, the rogue MCP finding will
    // be low instead of medium.
    await (await import('node:fs/promises')).writeFile(
      configPath,
      JSON.stringify({ allowedMcpServers: ['cursor-app-control'] })
    );
    const { stdout } = await execFileAsync(
      process.execPath,
      [
        'dist/index.js', 'audit',
        '--transcript', transcript,
        '--repo', REPO,
        '--config', configPath,
        '--format', 'json'
      ],
      { cwd: packageRoot }
    );
    const report = JSON.parse(stdout);
    const mcp = report.findings.find((f) => f.kind === 'session_trail.mcp_tool_invoked');
    assert.ok(mcp, 'expected an mcp_tool_invoked finding');
    assert.equal(mcp.severity, 'low', '--config allowlist should have lowered severity');
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
