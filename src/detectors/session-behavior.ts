import { getCommandHead, tokenizeShell } from 'agent-gov-core';
import {
  isBroadScanPath,
  isHomeDirectoryPath,
  isPathInsideRepo,
  isPrivilegedPath,
  isTranscriptPath,
  normalizePath
} from '../paths.js';
import type { Finding, ToolEvent } from '../types.js';

export function detectSessionBehavior(repoRoot: string, events: ToolEvent[]): Finding[] {
  const findings: Finding[] = [];

  for (const event of events) {
    findings.push(...detectPathAccess(repoRoot, event));
    findings.push(...detectShell(event));
    findings.push(...detectMcp(event));
    findings.push(...detectNetwork(event));
    findings.push(...detectSubagent(event));
    findings.push(...detectBroadScan(event));
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
        kind: 'transcript_cross_read',
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
        kind: 'privileged_path_access',
        severity: 'critical',
        file: normalized,
        line: event.line,
        subject: 'Privileged path access',
        message: 'Agent touched a credential, SSH, or system-config location outside the repository.',
        recommendation: 'Treat this access as a potential credential leak; review the session immediately.'
      });
    } else if (isHomeDirectoryPath(normalized) && !isPathInsideRepo(repoRoot, normalized)) {
      findings.push({
        kind: 'home_directory_access',
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
          kind: 'write_outside_repo',
          severity: 'critical',
          file: normalized,
          line: event.line,
          subject: 'Write outside repository',
          message: 'Agent attempted to write outside the declared repository root.',
          recommendation: 'Investigate out-of-repo writes immediately.'
        });
      } else {
        findings.push({
          kind: 'read_outside_repo',
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
      kind: 'shell_command_invoked',
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
      kind: 'mcp_tool_invoked',
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
      kind: 'network_intent',
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
      kind: 'subagent_spawned',
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
      kind: 'broad_path_scan',
      severity: 'high',
      file: scanPath ?? 'session',
      line: event.line,
      subject: 'Broad path scan',
      message: 'Agent scanned a very broad home-directory path.',
      recommendation: 'Prefer repository-scoped searches over home-directory scans.'
    }
  ];
}

function collectEventPaths(event: ToolEvent): Array<{ path: string; kind: 'read' | 'write' }> {
  const input = event.input;
  const paths: Array<{ path: string; kind: 'read' | 'write' }> = [];
  const add = (value: unknown, kind: 'read' | 'write') => {
    if (typeof value === 'string' && value.trim()) {
      paths.push({ path: value, kind });
    }
  };

  switch (event.tool) {
    case 'Read':
    case 'ReadLints':
      add(input.path, 'read');
      add(input.file_path, 'read');
      if (Array.isArray(input.paths)) {
        for (const path of input.paths) {
          add(path, 'read');
        }
      }
      break;
    case 'Write':
    case 'StrReplace':
    case 'Delete':
    case 'Edit':
    case 'MultiEdit':
      add(input.path, 'write');
      add(input.file_path, 'write');
      break;
    case 'Grep':
    case 'Glob':
      add(input.path ?? input.target_directory, 'read');
      break;
    default:
      if (isShellTool(event.tool)) {
        add(input.working_directory ?? input.workdir ?? input.cwd, 'read');
      } else if (toolKey(event.tool) === 'view_image') {
        add(input.path, 'read');
      } else if (toolKey(event.tool) === 'apply_patch') {
        for (const path of extractPatchPaths(input.patch)) {
          add(path, 'write');
        }
      }
      break;
  }

  return paths;
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

function toolKey(tool: string): string {
  return (tool.split('.').pop() ?? tool).toLowerCase();
}

function isShellTool(tool: string): boolean {
  const key = toolKey(tool);
  return key === 'shell' || key === 'bash' || key === 'shell_command';
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

function extractPatchPaths(value: unknown): string[] {
  if (typeof value !== 'string') {
    return [];
  }

  const paths: string[] = [];
  const pattern = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    paths.push(match[1].trim());
  }
  return paths;
}
