import type { AgentRuntime, Finding, PathAccess, Severity, ToolEvent } from './types.js';

export type SessionRating = 'none' | Severity;
export type ReportFormat = 'text' | 'markdown' | 'json' | 'github';

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

const SUMMARY_LABELS: Record<string, string> = {
  read_outside_repo: 'reads outside the repository',
  write_outside_repo: 'writes outside the repository',
  home_directory_access: 'home or Cursor metadata access',
  transcript_cross_read: 'cross-session transcript reads',
  shell_command_invoked: 'shell command invocations',
  mcp_tool_invoked: 'MCP tool invocations',
  network_intent: 'external network requests',
  subagent_spawned: 'subagent spawns',
  broad_path_scan: 'broad home-directory scans'
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
    for (const entry of report.pathHeatMap.slice(0, 12)) {
      lines.push(`- ${entry.path} (reads: ${entry.reads}, writes: ${entry.writes})`);
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
      lines.push(`- **${finding.subject}** (${finding.file}): ${finding.message}`);
      lines.push(`  Recommendation: ${finding.recommendation}`);
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
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.subject}: ${finding.message}`);
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

  return (
    report.findings
      .map((finding) => {
        const title = `SessionTrail ${finding.severity} behavior finding`;
        const message = `${finding.message} Recommendation: ${finding.recommendation}`;
        const properties = [`file=${escapeProperty(finding.file)}`];
        if (finding.line && finding.line > 0) {
          properties.push(`line=${finding.line}`);
        }
        properties.push(`title=${escapeProperty(title)}`);
        return `::warning ${properties.join(',')}::${escapeMessage(message)}`;
      })
      .join('\n') + '\n'
  );
}

function escapeMessage(value: string): string {
  return value.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
}

function escapeProperty(value: string): string {
  return escapeMessage(value).replaceAll(':', '%3A').replaceAll(',', '%2C');
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
