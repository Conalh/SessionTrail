import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { detectSessionBehavior } from '../dist/detectors/session-behavior.js';
import { parseTranscriptEvents } from '../dist/transcript.js';

const testDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(testDir, '..');

test('parser extracts tool events from Cursor JSONL', async () => {
  const raw = await readFile(join(testDir, 'fixtures', 'benign-session.jsonl'), 'utf8');
  const events = parseTranscriptEvents(raw);

  assert.ok(events.length >= 3);
  assert.equal(events[0].tool, 'Read');
});

test('detector flags write outside repo', async () => {
  const raw = await readFile(join(testDir, 'fixtures', 'rogue-session.jsonl'), 'utf8');
  const events = parseTranscriptEvents(raw);
  const findings = detectSessionBehavior('C:/Dev/Demo', events);

  assert.ok(findings.some((finding) => finding.kind === 'write_outside_repo'));
  assert.ok(findings.some((finding) => finding.kind === 'mcp_tool_invoked'));
});

test('action.yml exposes session behavior outputs', async () => {
  const action = await readFile(join(packageRoot, 'action.yml'), 'utf8');
  assert.match(action, /name: SessionTrail/);
  assert.match(action, /transcript:/);
  assert.match(action, /tool-invocation-count/);
});
