import {
  isBroadScanPath,
  isHomeDirectoryPath,
  isPathInsideRepo,
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

    if (isHomeDirectoryPath(normalized) && !isPathInsideRepo(repoRoot, normalized)) {
      findings.push({
        kind: 'home_directory_access',
        severity: 'high',
        file: normalized,
        line: event.line,
        subject: 'Home directory access',
        message: 'Agent accessed a path under the user home or Cursor metadata directories.',
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

function detectShell(event: ToolEvent): Finding[] {
  if (event.tool !== 'Shell') {
    return [];
  }

  const command = typeof event.input.command === 'string' ? event.input.command : '';
  const severity =
    /\b(curl|wget|Invoke-WebRequest|npm publish|git push|rm -rf|Remove-Item.*-Recurse)\b/i.test(command)
      ? 'high'
      : 'medium';

  return [
    {
      kind: 'shell_command_invoked',
      severity,
      file: 'session',
      line: event.line,
      subject: 'Shell command',
      message: `Agent invoked a shell command: ${truncate(command, 120)}`,
      recommendation: 'Review shell commands for scope and trust boundaries.'
    }
  ];
}

function detectMcp(event: ToolEvent): Finding[] {
  if (event.tool !== 'CallMcpTool') {
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
  if (event.tool !== 'WebFetch' && event.tool !== 'WebSearch') {
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
  if (event.tool !== 'Task') {
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
  if (event.tool !== 'Glob' && event.tool !== 'Grep') {
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
      if (Array.isArray(input.paths)) {
        for (const path of input.paths) {
          add(path, 'read');
        }
      }
      break;
    case 'Write':
    case 'StrReplace':
    case 'Delete':
      add(input.path, 'write');
      break;
    case 'Grep':
    case 'Glob':
      add(input.path ?? input.target_directory, 'read');
      break;
    default:
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
