import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectSessionBehavior } from '../dist/detectors/session-behavior.js';
import { compileAllowlist, loadAllowlist } from '../dist/config.js';

test('allowed MCP servers drop the finding to low severity', () => {
  const allowlist = compileAllowlist({ allowedMcpServers: ['github-pr-helper'] });
  const event = {
    tool: 'CallMCPTool',
    runtime: 'claude-code',
    line: 1,
    turn: 1,
    input: { server: 'github-pr-helper', toolName: 'create_review' }
  };
  const findings = detectSessionBehavior('C:/Dev/Demo', [event], allowlist);
  const mcp = findings.find((f) => f.kind === 'session_trail.mcp_tool_invoked');
  assert.ok(mcp);
  assert.equal(mcp.severity, 'low');
  assert.equal(mcp.data.allowed, true);
});

test('non-allowed MCP servers stay at medium', () => {
  const allowlist = compileAllowlist({ allowedMcpServers: ['github-pr-helper'] });
  const event = {
    tool: 'CallMCPTool',
    runtime: 'claude-code',
    line: 1,
    turn: 1,
    input: { server: 'cursor-app-control', toolName: 'move_agent_to_root' }
  };
  const findings = detectSessionBehavior('C:/Dev/Demo', [event], allowlist);
  const mcp = findings.find((f) => f.kind === 'session_trail.mcp_tool_invoked');
  assert.equal(mcp.severity, 'medium');
});

test('allowlisted shell pattern drops a non-risky command to low', () => {
  const allowlist = compileAllowlist({ benignShellPatterns: ['^cargo\\s+test'] });
  const event = {
    tool: 'Bash',
    runtime: 'claude-code',
    line: 1,
    turn: 1,
    input: { command: 'cargo test --workspace' }
  };
  const findings = detectSessionBehavior('C:/Dev/Demo', [event], allowlist);
  const shell = findings.find((f) => f.kind === 'session_trail.shell_command_invoked');
  assert.equal(shell.severity, 'low');
});

test('allowlisted shell pattern does NOT override RISKY_PATTERNS', () => {
  // Even if the user puts `^npm` in benignShellPatterns, `npm publish`
  // is a defined risky in-subcommand shape and stays at high. Allowlist
  // overrides RISKY_VERBS (the user vetted the prefix) but cannot
  // whitelist shapes like `npm publish` or `git push`.
  const allowlist = compileAllowlist({ benignShellPatterns: ['^npm\\b'] });
  const event = {
    tool: 'Bash',
    runtime: 'claude-code',
    line: 1,
    turn: 1,
    input: { command: 'npm publish' }
  };
  const findings = detectSessionBehavior('C:/Dev/Demo', [event], allowlist);
  const shell = findings.find((f) => f.kind === 'session_trail.shell_command_invoked');
  assert.equal(shell.severity, 'high');
});

test('allowed network host drops the finding to low severity', () => {
  const allowlist = compileAllowlist({ allowedNetworkHosts: ['internal.example.com'] });
  const event = {
    tool: 'WebFetch',
    runtime: 'claude-code',
    line: 1,
    turn: 1,
    input: { url: 'https://internal.example.com/api/v1/things' }
  };
  const findings = detectSessionBehavior('C:/Dev/Demo', [event], allowlist);
  const net = findings.find((f) => f.kind === 'session_trail.network_intent');
  assert.equal(net.severity, 'low');
});

test('loadAllowlist returns empty config when .sessiontrail.json is missing', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'sessiontrail-cfg-'));
  try {
    const allowlist = await loadAllowlist(tempDir);
    assert.equal(allowlist.allowedMcpServers.size, 0);
    assert.equal(allowlist.benignShellPatterns.length, 0);
    assert.equal(allowlist.allowedNetworkHosts.length, 0);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('loadAllowlist parses a .sessiontrail.json from the repo root', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'sessiontrail-cfg-'));
  try {
    await writeFile(
      join(tempDir, '.sessiontrail.json'),
      JSON.stringify({
        allowedMcpServers: ['github-pr-helper'],
        benignShellPatterns: ['^cargo\\s+test'],
        allowedNetworkHosts: ['internal.example.com']
      })
    );
    const allowlist = await loadAllowlist(tempDir);
    assert.ok(allowlist.allowedMcpServers.has('github-pr-helper'));
    assert.equal(allowlist.benignShellPatterns.length, 1);
    assert.equal(allowlist.allowedNetworkHosts[0], 'internal.example.com');
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('loadAllowlist throws on malformed .sessiontrail.json', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'sessiontrail-cfg-'));
  try {
    await writeFile(join(tempDir, '.sessiontrail.json'), '{ this is not json');
    await assert.rejects(loadAllowlist(tempDir), /Failed to parse .*\.sessiontrail\.json/);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
