import { createFinding, getCommandHead, tokenizeShell, fingerprintFinding } from 'agent-gov-core';
import {
  compileAllowlist,
  isMcpServerAllowed,
  isNetworkTargetAllowed,
  isShellSubcommandBenign,
  type CompiledAllowlist
} from '../config.js';
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

const EMPTY_ALLOWLIST = compileAllowlist({});

export function detectSessionBehavior(
  repoRoot: string,
  events: ToolEvent[],
  allowlist: CompiledAllowlist = EMPTY_ALLOWLIST
): Finding[] {
  const findings: Finding[] = [];

  for (const event of events) {
    const eventFindings = [
      ...detectPathAccess(repoRoot, event),
      ...detectShell(event, allowlist),
      ...detectMcp(event, allowlist),
      ...detectNetwork(event, allowlist),
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
// Conservative on purpose: anything that hits the network (`git fetch`,
// `npm view`), mutates state (`git pull`, `npm version`), runs
// arbitrary code (`npm test` still here only because it's idiomatic CI
// noise — users with stricter posture should rely on --fail-on
// thresholds), or could exfiltrate (cat, ls, echo of secrets) is
// excluded. The shell path-extraction pass above still catches
// credential exfiltration if any of these are misused with privileged
// arguments — benign verb doesn't whitelist a privileged target.
const BENIGN_PATTERNS: RegExp[] = [
  /^npm\s+(?:test|list|ls|root)\b/i,
  /^(?:yarn|pnpm)\s+(?:test|why|list|ls)\b/i,
  /^git\s+(?:status|log|diff|show|branch|tag|remote|config\s+--get|rev-parse)\b/i,
  /^(?:pwd|whoami|id|uname|hostname|date|tty|which|where)\b/i,
];

// Shell builtins that change directory/environment but don't themselves
// invoke external code. In a chain like `cd src && npm test`, `cd src`
// shouldn't bump severity to medium just because it's not in the benign
// list — it's a neutral setup step. Stripped from the ladder entirely.
// `eval`, `source`, and `.` are intentionally NOT here — they all
// execute arbitrary code (sourcing a script runs whatever's in it).
const NEUTRAL_VERBS = new Set([
  'cd', 'pushd', 'popd',
  'export', 'unset', 'set',
  ':', 'true', 'false'  // no-op shell builtins
]);

function isBenignCommand(sub: string): boolean {
  const trimmed = sub.trim();
  return BENIGN_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function isNeutralVerb(head: string): boolean {
  // head must already be lower-cased — caller does that once.
  return NEUTRAL_VERBS.has(head);
}

function detectShell(event: ToolEvent, allowlist: CompiledAllowlist): Finding[] {
  if (!isShellTool(event.tool)) {
    return [];
  }

  const command = typeof event.input.command === 'string' ? event.input.command : '';
  if (!command.trim()) {
    return [];
  }

  const subcommands = tokenizeShell(command);
  // Severity climbs: low (all benign/neutral) → medium (any non-benign)
  // → high (anything risky). A single risky branch in a chain wins; a
  // chain that's entirely benign or neutral drops below medium.
  // Risky patterns ALWAYS win — the allowlist can't whitelist `curl|sh`.
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
    // Compute the head once per subcommand; the neutral and risky-verb
    // checks both want the post-wrapper-stripped verb, so caching the
    // result avoids parsing the command string twice per branch.
    const head = getCommandHead(sub).toLowerCase();
    // Neutral setup verbs (cd, export, source, …) don't contribute to
    // severity. Before this, a chain like `cd src && npm test` got
    // bumped to medium because `cd src` matched neither benign nor
    // neutral — now it stays low when paired with a benign sibling.
    if (isNeutralVerb(head)) {
      continue;
    }
    // Allowlisted patterns and built-in benign verbs both contribute
    // 'low' to the ladder. The user-declared allowlist matters more
    // than the built-in benign list — it can be a legitimate `cargo
    // test` or an internal-only `curl` that shouldn't trip medium.
    if (isShellSubcommandBenign(sub, allowlist) || isBenignCommand(sub)) {
      continue;
    }
    if (RISKY_VERBS.has(head)) {
      severity = 'high';
      break;
    }
    if (severity === 'low') {
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

function detectMcp(event: ToolEvent, allowlist: CompiledAllowlist): Finding[] {
  if (!isMcpTool(event.tool)) {
    return [];
  }

  // MCP payload shapes vary across runtimes: Claude Code emits camelCase
  // `toolName`, Codex (and the JSON-RPC MCP spec) uses snake_case
  // `tool_name`. Likewise `server` vs `server_name`. Read all known
  // aliases so findings are actionable regardless of source format.
  const server =
    (typeof event.input.server === 'string' && event.input.server) ||
    (typeof event.input.server_name === 'string' && event.input.server_name) ||
    'unknown';
  const toolName =
    (typeof event.input.toolName === 'string' && event.input.toolName) ||
    (typeof event.input.tool_name === 'string' && event.input.tool_name) ||
    (typeof event.input.name === 'string' && event.input.name) ||
    'unknown';
  // Allowlisted MCP servers stay visible (we don't suppress) but drop
  // to 'low' so they don't trip --fail-on medium. A meta-reviewer can
  // still see the invocation in data; the user opted in.
  const severity = isMcpServerAllowed(server, allowlist) ? 'low' : 'medium';

  return [createFinding({
    tool: 'session_trail',
    name: 'mcp_tool_invoked',
    severity,
    message: `MCP tool invoked: ${server}/${toolName}`,
    detail: 'Confirm the MCP server and tool matched the declared session permissions.',
    location: { file: event.source ?? 'session', line: event.line },
    data: { server, tool: toolName, allowed: severity === 'low' },
    salientKey: `${server}/${toolName}`
  })];
}

function detectNetwork(event: ToolEvent, allowlist: CompiledAllowlist): Finding[] {
  if (!isNetworkTool(event.tool)) {
    return [];
  }

  const target = extractNetworkTarget(event.input);
  const severity = isNetworkTargetAllowed(target, allowlist) ? 'low' : 'medium';

  return [createFinding({
    tool: 'session_trail',
    name: 'network_intent',
    severity,
    message: `Network request via ${event.tool}: ${truncate(target, 120)}`,
    detail: 'Review external network use against declared permissions.',
    location: { file: event.source ?? 'session', line: event.line },
    data: { tool: event.tool, target, allowed: severity === 'low' },
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

// Pulls the actionable target out of a network tool's input. WebFetch
// gives us a URL; WebSearch gives us a search_term; Codex web.run uses
// nested arrays — search_query[].q, image_query[].q, open[].ref_id.
// Returning the literal "external target" placeholder when nothing
// matches makes findings unactionable, so we cover the known shapes.
function extractNetworkTarget(input: Record<string, unknown>): string {
  if (typeof input.url === 'string') return input.url;
  if (typeof input.search_term === 'string') return input.search_term;
  if (typeof input.query === 'string') return input.query;

  const firstQ = firstStringInArrayField(input.search_query, 'q')
    ?? firstStringInArrayField(input.image_query, 'q');
  if (firstQ) return firstQ;

  const firstRef = firstStringInArrayField(input.open, 'ref_id')
    ?? firstStringInArrayField(input.open, 'url');
  if (firstRef) return firstRef;

  return 'external target';
}

function firstStringInArrayField(value: unknown, field: string): string | undefined {
  if (!Array.isArray(value)) return undefined;
  for (const entry of value) {
    if (entry && typeof entry === 'object') {
      const v = (entry as Record<string, unknown>)[field];
      if (typeof v === 'string' && v.trim()) return v;
    }
  }
  return undefined;
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
