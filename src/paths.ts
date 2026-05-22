import { resolve } from 'node:path';

export function normalizePath(value: string): string {
  return value.replace(/\\/g, '/');
}

export function normalizeRepoRoot(repoRoot: string): string {
  // Same cross-OS hazard as in isPathInsideRepo: posix.resolve('C:/...')
  // on Linux and win32.resolve('/foo') on Windows both produce nonsense
  // by interpreting an absolute path from one namespace as relative in
  // the other. Skip resolve for absolute-looking roots so a POSIX repo
  // root from a Linux runner survives unchanged on a Windows test host
  // (and vice versa).
  if (isAbsolutePath(repoRoot)) {
    return normalizePath(repoRoot).replace(/\/$/, '');
  }
  return normalizePath(resolve(repoRoot)).replace(/\/$/, '');
}

export function isPathInsideRepo(repoRoot: string, targetPath: string, agentCwd?: string): boolean {
  // Unexpanded `~` and `~/...` refer to the user home directory. Node's
  // path.resolve doesn't expand them — it just tucks them under cwd. When
  // the action runs with `repo: .`, cwd IS the repo, so without this
  // short-circuit `~/secret.env` would falsely be classified as in-repo
  // and every downstream finding would get suppressed.
  if (isUnexpandedHomePath(targetPath)) {
    return false;
  }

  const normalizedRoot = normalizeRepoRoot(repoRoot).toLowerCase();

  // Absolute-looking targets (Windows drive letter, UNC, POSIX leading
  // slash) must NOT go through node:path.resolve on a foreign host:
  // path.posix.resolve('C:/Dev/Demo/x') on Linux returns
  // '/cwd/C:/Dev/Demo/x', which would falsely match a POSIX repo root.
  // Compare the path as-given instead.
  const normalizedTarget = isAbsolutePath(targetPath)
    ? normalizePath(targetPath).toLowerCase().replace(/\/$/, '')
    : resolveRelativeTarget(targetPath, agentCwd);

  return normalizedTarget === normalizedRoot || normalizedTarget.startsWith(`${normalizedRoot}/`);
}

// Resolve a relative target. When the agent's recorded cwd is available
// (Claude Code stores it per-message), prefer that over the audit CLI's
// process.cwd — `package.json` in a transcript means the agent's
// package.json, not whatever happens to be next to the CLI invocation.
function resolveRelativeTarget(targetPath: string, agentCwd: string | undefined): string {
  if (agentCwd && isAbsolutePath(agentCwd)) {
    const cwd = normalizePath(agentCwd).replace(/\/$/, '');
    const tail = normalizePath(targetPath).replace(/^\.\//, '');
    return `${cwd}/${tail}`.toLowerCase();
  }
  return normalizePath(resolve(targetPath)).toLowerCase();
}

function isUnexpandedHomePath(value: string): boolean {
  return value === '~' || value.startsWith('~/') || value.startsWith('~\\');
}

function isAbsolutePath(value: string): boolean {
  return /^[a-z]:[\\/]/i.test(value) || value.startsWith('\\\\') || value.startsWith('/');
}

export function isHomeDirectoryPath(targetPath: string): boolean {
  const normalized = normalizePath(targetPath).toLowerCase();

  // The user's home root by OS convention, plus the unexpanded `~` symbol
  // some agents pass through. WSL paths under \\wsl$\Distro\home\... show
  // up here so we catch them via the /home/ branch after normalization.
  if (
    /^[a-z]:\/users\//.test(normalized) ||
    normalized.startsWith('/users/') ||
    normalized.startsWith('/home/') ||
    normalized.startsWith('~/') ||
    normalized === '~' ||
    normalized.includes('//wsl$/') ||
    normalized.includes('//wsl.localhost/')
  ) {
    return true;
  }

  // Editor and agent metadata directories: anything an agent reads here is
  // by definition outside the current task's repository scope.
  return /(?:^|\/)(\.cursor|\.codex|\.claude|\.aider|\.continue|\.vscode-server)(?:\/|$)/.test(normalized);
}

// Sensitive credential and config locations — accessing any of these
// during an agent session is materially more dangerous than a generic
// out-of-repo read and gets its own finding kind.
//
// Matched as path segments rather than substrings so a relative path like
// `.ssh/id_rsa` is caught the same way an absolute `/home/u/.ssh/id_rsa`
// is. `resolve()` would conflate this with `process.cwd()` (where the
// audit CLI runs, not where the agent ran), so we use a segment regex.
const PRIVILEGED_DOT_SEGMENTS = [
  '.ssh', '.aws', '.gnupg', '.kube', '.docker', '.netrc'
];

const PRIVILEGED_NESTED_SEGMENTS = [
  '.config/gh', '.config/git', '.config/op',
  'appdata/roaming/microsoft/credentials',
  'localappdata/microsoft/credentials'
];

const PRIVILEGED_ABSOLUTE_PREFIXES = [
  '/etc/shadow', '/etc/passwd', '/etc/ssh',
  '/private/var', '/private/etc'
];

// Compile once at module load. The previous version built a fresh RegExp
// per segment per call, churning GC across thousand-path sessions.
const PRIVILEGED_SEGMENT_REGEXES = [
  ...PRIVILEGED_DOT_SEGMENTS,
  ...PRIVILEGED_NESTED_SEGMENTS
].map((segment) => new RegExp(`(?:^|/)${segment.replace(/\./g, '\\.')}(?:/|$)`));

export function isPrivilegedPath(targetPath: string): boolean {
  const normalized = normalizePath(targetPath).toLowerCase();

  for (const regex of PRIVILEGED_SEGMENT_REGEXES) {
    if (regex.test(normalized)) {
      return true;
    }
  }

  return PRIVILEGED_ABSOLUTE_PREFIXES.some((prefix) =>
    normalized === prefix || normalized.startsWith(`${prefix}/`)
  );
}

export function isTranscriptPath(targetPath: string): boolean {
  const normalized = normalizePath(targetPath).toLowerCase();
  return normalized.includes('/agent-transcripts/') && normalized.endsWith('.jsonl');
}

// A "broad scan" is one that walks a tree the agent has no business
// walking for a typical repository task: the user home root, the whole
// filesystem root, or a top-level user data tree like Documents.
const BROAD_USER_SUBDIRS = ['documents', 'downloads', 'desktop', 'pictures', 'videos'];

export function isBroadScanPath(targetPath: string | undefined): boolean {
  if (!targetPath) {
    return false;
  }

  const raw = normalizePath(targetPath).toLowerCase();
  const normalized = raw.length > 1 ? raw.replace(/\/+$/, '') : raw;

  if (
    normalized === '/' ||
    normalized === '~' ||
    /^[a-z]:$/.test(normalized) ||
    /^[a-z]:\/users\/[^/]+$/.test(normalized) ||
    /^\/users\/[^/]+$/.test(normalized) ||
    /^\/home\/[^/]+$/.test(normalized)
  ) {
    return true;
  }

  return BROAD_USER_SUBDIRS.some((sub) =>
    new RegExp(`^[a-z]:/users/[^/]+/${sub}$`).test(normalized)
    || new RegExp(`^/users/[^/]+/${sub}$`).test(normalized)
    || new RegExp(`^/home/[^/]+/${sub}$`).test(normalized)
  );
}
