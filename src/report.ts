import { emitFindingAnnotation } from 'agent-gov-core';
import type { AgentRuntime, Finding, PathAccess, Severity, ToolEvent } from './types.js';

export type SessionRating = 'none' | Severity;
export type ReportFormat = 'text' | 'markdown' | 'json' | 'github' | 'sarif';

export interface SessionReport {
  rating: SessionRating;
  findingCount: number;
  toolInvocationCount: number;
  uniqueToolCount: number;
  runtimeUsage: Record<AgentRuntime, number>;
  behaviorSummary: string[];
  toolUsage: Record<string, number>;
  pathHeatMap: PathAccess[];
  findings: Finding[];
}

const severityRank: Record<SessionRating, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

// Keys must match the `session_trail.*` finding kinds emitted by the
// detector — the lookup is exact, so missing or unprefixed entries fall
// through to the raw kind string.
const SUMMARY_LABELS: Record<string, string> = {
  'session_trail.read_outside_repo': 'reads outside the repository',
  'session_trail.write_outside_repo': 'writes outside the repository',
  'session_trail.privileged_path_access': 'privileged credential or system-path access',
  'session_trail.home_directory_access': 'home or Cursor metadata access',
  'session_trail.transcript_cross_read': 'cross-session transcript reads',
  'session_trail.shell_command_invoked': 'shell command invocations',
  'session_trail.mcp_tool_invoked': 'MCP tool invocations',
  'session_trail.network_intent': 'external network requests',
  'session_trail.subagent_spawned': 'subagent spawns',
  'session_trail.broad_path_scan': 'broad home-directory scans'
};

export function createReport(
  findings: Finding[],
  context: {
    transcriptPath: string;
    repoRoot: string;
    events: ToolEvent[];
    runtimeUsage: Record<AgentRuntime, number>;
    toolUsage: Record<string, number>;
    pathAccess: PathAccess[];
  }
): SessionReport {
  return {
    rating: rateFindings(findings),
    findingCount: findings.length,
    toolInvocationCount: context.events.length,
    uniqueToolCount: Object.keys(context.toolUsage).length,
    runtimeUsage: context.runtimeUsage,
    behaviorSummary: buildBehaviorSummary(findings, context.toolUsage),
    toolUsage: context.toolUsage,
    pathHeatMap: context.pathAccess,
    findings
  };
}

export function renderReport(report: SessionReport, format: ReportFormat): string {
  if (format === 'json') {
    return `${JSON.stringify(report, null, 2)}\n`;
  }

  if (format === 'markdown') {
    return renderMarkdown(report);
  }

  if (format === 'github') {
    return renderGithubAnnotations(report);
  }

  if (format === 'sarif') {
    return renderSarif(report);
  }

  return renderText(report);
}

function buildBehaviorSummary(findings: Finding[], toolUsage: Record<string, number>): string[] {
  const summary = new Set<string>();

  for (const finding of findings) {
    summary.add(SUMMARY_LABELS[finding.kind] ?? finding.kind);
  }

  const topTools = Object.entries(toolUsage)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([tool, count]) => `${tool} x${count}`);

  if (topTools.length > 0) {
    summary.add(`top tools: ${topTools.join(', ')}`);
  }

  return [...summary];
}

function rateFindings(findings: Finding[]): SessionRating {
  let rating: SessionRating = 'none';
  for (const finding of findings) {
    if (severityRank[finding.severity] > severityRank[rating]) {
      rating = finding.severity;
    }
  }

  return rating;
}

// findingTarget returns the most useful "what was touched" string for a
// finding — the accessed path if we stashed one in `data.target`, else
// the location file (transcript), else 'session'.
function findingTarget(finding: Finding): string {
  const target = (finding.data as { target?: unknown } | undefined)?.target;
  if (typeof target === 'string' && target) {
    return target;
  }
  return finding.location?.file ?? 'session';
}

function renderMarkdown(report: SessionReport): string {
  const lines = [`# SessionTrail behavior review: ${report.rating.toUpperCase()}`, ''];

  lines.push(`Tool invocations: ${report.toolInvocationCount}`);
  lines.push(`Unique tools: ${report.uniqueToolCount}`);
  lines.push(`Agent runtimes: ${formatRuntimeUsage(report.runtimeUsage)}`);
  lines.push(`Findings: ${report.findingCount}`, '');

  if (report.findings.length === 0) {
    lines.push('No session behavior findings.');
    return `${lines.join('\n')}\n`;
  }

  if (report.behaviorSummary.length > 0) {
    lines.push('## Behavior summary', '');
    for (const item of report.behaviorSummary) {
      lines.push(`- ${item}`);
    }
    lines.push('');
  }

  if (report.pathHeatMap.length > 0) {
    lines.push('## Path heat map', '');
    const HEAT_MAP_LIMIT = 12;
    for (const entry of report.pathHeatMap.slice(0, HEAT_MAP_LIMIT)) {
      lines.push(`- ${entry.path} (reads: ${entry.reads}, writes: ${entry.writes})`);
    }
    if (report.pathHeatMap.length > HEAT_MAP_LIMIT) {
      lines.push(`- _(+${report.pathHeatMap.length - HEAT_MAP_LIMIT} more)_`);
    }
    lines.push('');
  }

  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const matches = report.findings.filter((finding) => finding.severity === severity);
    if (matches.length === 0) {
      continue;
    }

    lines.push(`## ${capitalize(severity)}`, '');
    for (const finding of matches) {
      // finding.message already leads with the human-readable subject
      // (see createFinding call sites). Add the touched target in
      // parens when it's distinct from the message context.
      const target = findingTarget(finding);
      const targetSuffix = target && target !== 'session' ? ` (${target})` : '';
      lines.push(`- ${finding.message}${targetSuffix}`);
      if (finding.detail) {
        lines.push(`  ${finding.detail}`);
      }
    }
    lines.push('');
  }

  return `${lines.join('\n').trimEnd()}\n`;
}

function renderText(report: SessionReport): string {
  const lines = [`SessionTrail behavior review: ${report.rating.toUpperCase()}`];
  lines.push(`Agent runtimes: ${formatRuntimeUsage(report.runtimeUsage)}`);
  if (report.behaviorSummary.length > 0) {
    lines.push(`Summary: ${report.behaviorSummary.join('; ')}`);
  }

  for (const finding of report.findings) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.message}`);
  }

  if (report.findings.length === 0) {
    lines.push('No session behavior findings.');
  }

  return `${lines.join('\n')}\n`;
}

function renderGithubAnnotations(report: SessionReport): string {
  if (report.findings.length === 0) {
    return '';
  }

  // emitFindingAnnotation handles severity-aware ::error/::warning, the
  // file/line params, escaping, and the title; it doesn't know about
  // SessionTrail's data.target convention, so fold the target into the
  // message before emitting so the inline annotation says what got
  // touched without needing a separate field.
  return (
    report.findings
      .map((finding) => {
        const target = (finding.data as { target?: unknown } | undefined)?.target;
        const isExternalTarget =
          typeof target === 'string' &&
          target &&
          target !== finding.location?.file;
        const annotated: Finding = isExternalTarget
          ? { ...finding, message: `${finding.message} (target: ${target as string})` }
          : finding;
        return emitFindingAnnotation(annotated);
      })
      .join('\n') + '\n'
  );
}

// SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// GitHub Code Scanning accepts this format directly via the
// `github/codeql-action/upload-sarif` action. Each Finding becomes a
// `result`; the kinds become tool rules (so GitHub can group findings
// by rule in the Code Scanning UI).
function renderSarif(report: SessionReport): string {
  // Map agent-gov severities to SARIF levels.
  // SARIF only has: none, note, warning, error.
  const SARIF_LEVEL: Record<string, 'note' | 'warning' | 'error'> = {
    low: 'note',
    medium: 'warning',
    high: 'error',
    critical: 'error'
  };

  // Build the rules array from observed kinds so the SARIF run is
  // self-describing — GitHub Code Scanning groups results by rule.
  const seenKinds = new Set<string>();
  for (const finding of report.findings) {
    seenKinds.add(finding.kind);
  }
  const rules = [...seenKinds].map((kind) => ({
    id: kind,
    name: kind,
    shortDescription: { text: SUMMARY_LABELS[kind] ?? kind },
    helpUri: 'https://github.com/Conalh/SessionTrail#current-findings'
  }));

  const results = report.findings.map((finding) => {
    const result: Record<string, unknown> = {
      ruleId: finding.kind,
      level: SARIF_LEVEL[finding.severity] ?? 'warning',
      message: { text: finding.message },
      // Stable identifier across runs so Code Scanning can dedupe.
      partialFingerprints: finding.fingerprint
        ? { sessionTrail: finding.fingerprint }
        : undefined
    };

    if (finding.location?.file) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.location.file },
            ...(finding.location.line
              ? { region: { startLine: finding.location.line } }
              : {})
          }
        }
      ];
    }

    if (finding.detail) {
      (result.message as { text: string; markdown?: string }).markdown =
        `${finding.message}\n\n_${finding.detail}_`;
    }

    return result;
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SessionTrail',
            informationUri: 'https://github.com/Conalh/SessionTrail',
            rules
          }
        },
        results
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function capitalize(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

function formatRuntimeUsage(runtimeUsage: Record<AgentRuntime, number>): string {
  const entries = Object.entries(runtimeUsage).filter(([, count]) => count > 0);
  if (entries.length === 0) {
    return 'none';
  }

  return entries.map(([runtime, count]) => `${runtime} x${count}`).join(', ');
}
