import { createFinding, getCommandHead, tokenizeShell, fingerprintFinding } from 'agent-gov-core';
import {
  isBroadScanPath,
  isHomeDirectoryPath,
  isPathInsideRepo,
  isPrivilegedPath,
  isTranscriptPath,
  normalizePath
} from '../paths.js';
import { collectEventPaths, extractShellPaths, isShellTool, toolKey } from '../tool-paths.js';
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
    // Done once here rather than in every detector branch. Because the
    // location is finalized here, refingerprint after the stamp so the
    // dedupe key reflects the real annotation site.
    for (const finding of eventFindings) {
      if (event.source) {
        finding.location = {
          file: event.source,
          ...(event.line ? { line: event.line } : {})
        };
        finding.fingerprint = fingerprintFinding(finding);
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
      findings.push(createFinding({
        tool: 'session_trail',
        name: 'transcript_cross_read',
        severity: 'medium',
        message: 'Cross-session transcript read: agent read another session transcript outside the current task boundary.',
        detail: 'Review whether cross-session transcript access was necessary.',
        location: { file: event.source ?? 'session', line: event.line },
        data: { target: normalized },
        salientKey: normalized
      }));
    }

    if (isPrivilegedPath(normalized) && !isPathInsideRepo(repoRoot, normalized, event.cwd)) {
      findings.push(createFinding({
        tool: 'session_trail',
        name: 'privileged_path_access',
        severity: 'critical',
        message: 'Privileged path access: agent touched a credential, SSH, or system-config location outside the repository.',
        detail: 'Treat this access as a potential credential leak; review the session immediately.',
        location: { file: event.source ?? 'session', line: event.line },
        data: { target: normalized },
        salientKey: normalized
      }));
    } else if (isHomeDirectoryPath(normalized) && !isPathInsideRepo(repoRoot, normalized, event.cwd)) {
      findings.push(createFinding({
        tool: 'session_trail',
        name: 'home_directory_access',
        severity: 'high',
        message: 'Home directory access: agent accessed a path under the user home or an agent-metadata directory.',
        detail: 'Confirm the home-directory access was intentional and minimal.',
        location: { file: event.source ?? 'session', line: event.line },
        data: { target: normalized },
        salientKey: normalized
      }));
    }

    if (!isPathInsideRepo(repoRoot, normalized, event.cwd)) {
      if (entry.kind === 'write') {
        findings.push(createFinding({
          tool: 'session_trail',
          name: 'write_outside_repo',
          severity: 'critical',
          message: 'Write outside repository: agent attempted to write outside the declared repository root.',
          detail: 'Investigate out-of-repo writes immediately.',
          location: { file: event.source ?? 'session', line: event.line },
          data: { target: normalized },
          salientKey: normalized
        }));
      } else {
        findings.push(createFinding({
          tool: 'session_trail',
          name: 'read_outside_repo',
          severity: 'medium',
          message: 'Read outside repository: agent read a file outside the declared repository root.',
          detail: 'Review whether the external read was required for the task.',
          location: { file: event.source ?? 'session', line: event.line },
          data: { target: normalized },
          salientKey: normalized
        }));
      }
    }
  }

  // Shell command path extraction. We don't route shell-extracted paths
  // through the full read/write-outside-repo flow because absolute paths
  // are pervasive in shell (/bin/bash, /usr/bin/curl, /tmp/script.js)
  // and flagging every one as out-of-repo would flood the report. We do
  // still check them against the high-signal categories — privileged
  // credential dirs, home metadata dirs, and cross-session transcript
  // reads — which is where shell-based exfiltration actually lives.
  if (isShellTool(event.tool)) {
    const command = typeof event.input.command === 'string' ? event.input.command : '';
    for (const candidate of extractShellPaths(command)) {
      const normalized = normalizePath(candidate);

      if (isTranscriptPath(normalized)) {
        findings.push(createFinding({
          tool: 'session_trail',
          name: 'transcript_cross_read',
          severity: 'medium',
          message: 'Cross-session transcript read via shell command.',
          detail: 'Review whether cross-session transcript access was necessary.',
          location: { file: event.source ?? 'session', line: event.line },
          data: { target: normalized, viaShell: true },
          salientKey: normalized
        }));
        continue;
      }

      if (isPrivilegedPath(normalized) && !isPathInsideRepo(repoRoot, normalized, event.cwd)) {
        findings.push(createFinding({
          tool: 'session_trail',
          name: 'privileged_path_access',
          severity: 'critical',
          message: 'Privileged path referenced in shell command (credential, SSH, or system-config location).',
          detail: 'Treat this as a potential credential leak; review the shell command immediately.',
          location: { file: event.source ?? 'session', line: event.line },
          data: { target: normalized, viaShell: true },
          salientKey: normalized
        }));
      } else if (isHomeDirectoryPath(normalized) && !isPathInsideRepo(repoRoot, normalized, event.cwd)) {
        findings.push(createFinding({
          tool: 'session_trail',
          name: 'home_directory_access',
          severity: 'high',
          message: 'Home or agent-metadata path referenced in shell command.',
          detail: 'Confirm the home-directory access was intentional and minimal.',
          location: { file: event.source ?? 'session', line: event.line },
          data: { target: normalized, viaShell: true },
          salientKey: normalized
        }));
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

// Quiet, side-effect-free repo introspection that's nearly always noise
// in audits. Downgrading from medium → low keeps them visible in the
// step summary without tripping --fail-on at low/medium thresholds.
// Conservative on purpose: anything with side effects (install, build,
// run) or anything that could exfiltrate (cat, ls, echo of secrets)
// stays at medium. The shell path-extraction pass above still catches
// credential exfiltration if any of these are misused with privileged
// arguments — benign verb doesn't whitelist a privileged target.
const BENIGN_PATTERNS: RegExp[] = [
  /^npm\s+(?:test|version|outdated|view|info|list|ls|root)\b/i,
  /^(?:yarn|pnpm)\s+(?:test|version|info|why|list|ls)\b/i,
  /^git\s+(?:status|log|diff|show|branch|tag|fetch|pull|remote|config\s+--get|rev-parse)\b/i,
  /^(?:pwd|whoami|id|uname|hostname|date|tty|which|where)\b/i,
];

function isBenignCommand(sub: string): boolean {
  const trimmed = sub.trim();
  return BENIGN_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function detectShell(event: ToolEvent): Finding[] {
  if (!isShellTool(event.tool)) {
    return [];
  }

  const command = typeof event.input.command === 'string' ? event.input.command : '';
  if (!command.trim()) {
    return [];
  }

  const subcommands = tokenizeShell(command);
  // Severity climbs: low (all benign) → medium (any non-benign) → high
  // (anything risky). A single risky branch in a chain wins; a chain
  // that's entirely benign drops below medium.
  let severity: 'low' | 'medium' | 'high' = 'low';
  for (const sub of subcommands) {
    // RISKY_PATTERNS still operates on the raw subcommand text because the
    // patterns describe shapes like `curl ... | sh` that survive light
    // obfuscation without explicit normalization. getCommandHead handles
    // the verb-level obfuscation (c""url, c\url, sudo/env wrappers).
    if (RISKY_PATTERNS.some((pattern) => pattern.test(sub))) {
      severity = 'high';
      break;
    }
    const head = getCommandHead(sub).toLowerCase();
    if (RISKY_VERBS.has(head)) {
      severity = 'high';
      break;
    }
    if (severity === 'low' && !isBenignCommand(sub)) {
      severity = 'medium';
    }
  }

  return [createFinding({
    tool: 'session_trail',
    name: 'shell_command_invoked',
    severity,
    message: `Shell command: ${truncate(command, 120)}`,
    detail: 'Review shell commands for scope and trust boundaries.',
    location: { file: event.source ?? 'session', line: event.line },
    salientKey: command
  })];
}

function detectMcp(event: ToolEvent): Finding[] {
  if (!isMcpTool(event.tool)) {
    return [];
  }

  const server = typeof event.input.server === 'string' ? event.input.server : 'unknown';
  const toolName = typeof event.input.toolName === 'string' ? event.input.toolName : 'unknown';

  return [createFinding({
    tool: 'session_trail',
    name: 'mcp_tool_invoked',
    severity: 'medium',
    message: `MCP tool invoked: ${server}/${toolName}`,
    detail: 'Confirm the MCP server and tool matched the declared session permissions.',
    location: { file: event.source ?? 'session', line: event.line },
    data: { server, tool: toolName },
    salientKey: `${server}/${toolName}`
  })];
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

  return [createFinding({
    tool: 'session_trail',
    name: 'network_intent',
    severity: 'medium',
    message: `Network request via ${event.tool}: ${truncate(target, 120)}`,
    detail: 'Review external network use against declared permissions.',
    location: { file: event.source ?? 'session', line: event.line },
    data: { tool: event.tool, target },
    salientKey: target
  })];
}

function detectSubagent(event: ToolEvent): Finding[] {
  if (toolKey(event.tool) !== 'task') {
    return [];
  }

  const subagentType = typeof event.input.subagent_type === 'string' ? event.input.subagent_type : 'unknown';
  return [createFinding({
    tool: 'session_trail',
    name: 'subagent_spawned',
    severity: 'low',
    message: `Subagent spawned: ${subagentType}`,
    detail: 'Review subagent work for additional scope expansion.',
    location: { file: event.source ?? 'session', line: event.line },
    data: { subagentType },
    salientKey: subagentType
  })];
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

  return [createFinding({
    tool: 'session_trail',
    name: 'broad_path_scan',
    severity: 'high',
    message: 'Broad path scan: agent scanned a very broad home-directory path.',
    detail: 'Prefer repository-scoped searches over home-directory scans.',
    location: { file: event.source ?? 'session', line: event.line },
    data: { target: scanPath },
    salientKey: scanPath ?? 'session'
  })];
}

function dedupeFindings(findings: Finding[]): Finding[] {
  // createFinding stamps a deterministic fingerprint on each, so dedupe
  // by that. salientKey on each finding ensures two distinct targets at
  // the same (kind, file, line) site still get distinct fingerprints.
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const finding of findings) {
    const key = finding.fingerprint ?? `${finding.kind}|${finding.location?.file ?? ''}|${finding.location?.line ?? 0}`;
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
