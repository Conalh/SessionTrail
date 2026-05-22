import { getCommandHead, tokenizeShell } from 'agent-gov-core';
import {
  isBroadScanPath,
  isHomeDirectoryPath,
  isPathInsideRepo,
  isPrivilegedPath,
  isTranscriptPath,
  normalizePath
} from '../paths.js';
import { collectEventPaths, isShellTool, toolKey } from '../tool-paths.js';
import type { Finding, ToolEvent } from '../types.js';

export function detectSessionBehavior(repoRoot: string, events: ToolEvent[]): Finding[] {
  const findings: Finding[] = [];

  for (const event of events) {
    const eventFindings = [
      ...detectPathAccess(repoRoot, event),
      ...detectShell(event),
      ...detectMcp(event),
      ...detectNetwork(event),
      ...detectSubagent(event),
      ...detectBroadScan(event)
    ];

    // Stamp the originating transcript on each finding so the GitHub
    // renderer can anchor annotations at the transcript file/line.
    // Done once here rather than in every detector branch.
    for (const finding of eventFindings) {
      if (event.source && !finding.source) {
        finding.source = event.source;
      }
      findings.push(finding);
    }
  }

  return dedupeFindings(findings);
}

function detectPathAccess(repoRoot: string, event: ToolEvent): Finding[] {
  const findings: Finding[] = [];
  const paths = collectEventPaths(event);

  for (const entry of paths) {
    const normalized = normalizePath(entry.path);

    if (isTranscriptPath(normalized)) {
      findings.push({
        kind: 'session_trail.transcript_cross_read',
        severity: 'medium',
        file: normalized,
        line: event.line,
        subject: 'Cross-session transcript read',
        message: 'Agent read another session transcript outside the current task boundary.',
        recommendation: 'Review whether cross-session transcript access was necessary.'
      });
    }

    if (isPrivilegedPath(normalized) && !isPathInsideRepo(repoRoot, normalized)) {
      findings.push({
        kind: 'session_trail.privileged_path_access',
        severity: 'critical',
        file: normalized,
        line: event.line,
        subject: 'Privileged path access',
        message: 'Agent touched a credential, SSH, or system-config location outside the repository.',
        recommendation: 'Treat this access as a potential credential leak; review the session immediately.'
      });
    } else if (isHomeDirectoryPath(normalized) && !isPathInsideRepo(repoRoot, normalized)) {
      findings.push({
        kind: 'session_trail.home_directory_access',
        severity: 'high',
        file: normalized,
        line: event.line,
        subject: 'Home directory access',
        message: 'Agent accessed a path under the user home or an agent-metadata directory.',
        recommendation: 'Confirm the home-directory access was intentional and minimal.'
      });
    }

    if (!isPathInsideRepo(repoRoot, normalized)) {
      if (entry.kind === 'write') {
        findings.push({
          kind: 'session_trail.write_outside_repo',
          severity: 'critical',
          file: normalized,
          line: event.line,
          subject: 'Write outside repository',
          message: 'Agent attempted to write outside the declared repository root.',
          recommendation: 'Investigate out-of-repo writes immediately.'
        });
      } else {
        findings.push({
          kind: 'session_trail.read_outside_repo',
          severity: 'medium',
          file: normalized,
          line: event.line,
          subject: 'Read outside repository',
          message: 'Agent read a file outside the declared repository root.',
          recommendation: 'Review whether the external read was required for the task.'
        });
      }
    }
  }

  return findings;
}

// Risky-command verbs. Matched on the head of each chained subcommand
// rather than anywhere in the raw string — so `echo curl-up` doesn't fire,
// and obfuscated `c""url` does (we strip the quotes before matching).
const RISKY_VERBS = new Set([
  'curl', 'wget', 'invoke-webrequest', 'iwr',
  'rm', 'remove-item',
  'sudo', 'doas',
  'chmod', 'chown', 'setfacl',
  'kubectl', 'gcloud', 'aws', 'az',
  'dd', 'mkfs', 'fdisk'
]);

const RISKY_PATTERNS: RegExp[] = [
  /\bnpm\s+publish\b/i,
  /\bgit\s+push\b/i,
  /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r\b/i,
  /\bremove-item\b[^\n;|&]*\s-recurse/i,
  /\bcurl\b[^|]*\|\s*(?:ba)?sh\b/i,
  /\b(?:iwr|invoke-webrequest)\b[^|]*\|\s*(?:iex|invoke-expression)/i,
];

function detectShell(event: ToolEvent): Finding[] {
  if (!isShellTool(event.tool)) {
    return [];
  }

  const command = typeof event.input.command === 'string' ? event.input.command : '';
  if (!command.trim()) {
    return [];
  }

  const subcommands = tokenizeShell(command);
  let highest: 'medium' | 'high' = 'medium';
  for (const sub of subcommands) {
    // RISKY_PATTERNS still operates on the raw subcommand text because the
    // patterns describe shapes like `curl ... | sh` that survive light
    // obfuscation without explicit normalization. getCommandHead handles
    // the verb-level obfuscation (c""url, c\url, sudo/env wrappers).
    if (RISKY_PATTERNS.some((pattern) => pattern.test(sub))) {
      highest = 'high';
      break;
    }
    const head = getCommandHead(sub).toLowerCase();
    if (RISKY_VERBS.has(head)) {
      highest = 'high';
      break;
    }
  }

  return [
    {
      kind: 'session_trail.shell_command_invoked',
      severity: highest,
      file: 'session',
      line: event.line,
      subject: 'Shell command',
      message: `Agent invoked a shell command: ${truncate(command, 120)}`,
      recommendation: 'Review shell commands for scope and trust boundaries.'
    }
  ];
}

function detectMcp(event: ToolEvent): Finding[] {
  if (!isMcpTool(event.tool)) {
    return [];
  }

  const server = typeof event.input.server === 'string' ? event.input.server : 'unknown';
  const toolName = typeof event.input.toolName === 'string' ? event.input.toolName : 'unknown';

  return [
    {
      kind: 'session_trail.mcp_tool_invoked',
      severity: 'medium',
      file: 'session',
      line: event.line,
      subject: `${server}/${toolName}`,
      message: `Agent invoked MCP tool ${server}/${toolName}.`,
      recommendation: 'Confirm the MCP server and tool matched the declared session permissions.'
    }
  ];
}

function detectNetwork(event: ToolEvent): Finding[] {
  if (!isNetworkTool(event.tool)) {
    return [];
  }

  const target =
    typeof event.input.url === 'string'
      ? event.input.url
      : typeof event.input.search_term === 'string'
        ? event.input.search_term
        : 'external target';

  return [
    {
      kind: 'session_trail.network_intent',
      severity: 'medium',
      file: 'session',
      line: event.line,
      subject: event.tool,
      message: `Agent requested external network access via ${event.tool}: ${truncate(target, 120)}`,
      recommendation: 'Review external network use against declared permissions.'
    }
  ];
}

function detectSubagent(event: ToolEvent): Finding[] {
  if (toolKey(event.tool) !== 'task') {
    return [];
  }

  const subagentType = typeof event.input.subagent_type === 'string' ? event.input.subagent_type : 'unknown';
  return [
    {
      kind: 'session_trail.subagent_spawned',
      severity: 'low',
      file: 'session',
      line: event.line,
      subject: subagentType,
      message: `Agent spawned a ${subagentType} subagent.`,
      recommendation: 'Review subagent work for additional scope expansion.'
    }
  ];
}

function detectBroadScan(event: ToolEvent): Finding[] {
  if (!isSearchTool(event.tool)) {
    return [];
  }

  const scanPath =
    typeof event.input.target_directory === 'string'
      ? event.input.target_directory
      : typeof event.input.path === 'string'
        ? event.input.path
        : undefined;

  if (!isBroadScanPath(scanPath)) {
    return [];
  }

  return [
    {
      kind: 'session_trail.broad_path_scan',
      severity: 'high',
      file: scanPath ?? 'session',
      line: event.line,
      subject: 'Broad path scan',
      message: 'Agent scanned a very broad home-directory path.',
      recommendation: 'Prefer repository-scoped searches over home-directory scans.'
    }
  ];
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.kind}|${finding.file}|${finding.line ?? 0}|${finding.subject}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(finding);
  }

  return unique;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }

  return `${value.slice(0, max - 3)}...`;
}

function isMcpTool(tool: string): boolean {
  const normalized = tool.toLowerCase();
  return toolKey(tool) === 'callmcptool' || normalized.includes('mcp');
}

function isNetworkTool(tool: string): boolean {
  const key = toolKey(tool);
  const normalized = tool.toLowerCase();
  return key === 'webfetch' || key === 'websearch' || normalized === 'web.run';
}

function isSearchTool(tool: string): boolean {
  const key = toolKey(tool);
  return key === 'grep' || key === 'glob';
}
