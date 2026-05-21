import { resolve } from 'node:path';

export function normalizePath(value: string): string {
  return value.replace(/\\/g, '/');
}

export function normalizeRepoRoot(repoRoot: string): string {
  return normalizePath(resolve(repoRoot)).replace(/\/$/, '');
}

export function isPathInsideRepo(repoRoot: string, targetPath: string): boolean {
  const normalizedRoot = normalizeRepoRoot(repoRoot).toLowerCase();
  const normalizedTarget = normalizePath(resolve(targetPath)).toLowerCase();
  return normalizedTarget === normalizedRoot || normalizedTarget.startsWith(`${normalizedRoot}/`);
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
const PRIVILEGED_PATH_SEGMENTS = [
  '.ssh', '.aws', '.gnupg', '.kube', '.docker', '.netrc',
  '.config/gh', '.config/git', '.config/op',
  'appdata/roaming/microsoft/credentials',
  'localappdata/microsoft/credentials',
  '/etc/shadow', '/etc/passwd', '/etc/ssh',
  '/private/var', '/private/etc'
];

export function isPrivilegedPath(targetPath: string): boolean {
  const normalized = normalizePath(targetPath).toLowerCase();
  return PRIVILEGED_PATH_SEGMENTS.some((segment) =>
    normalized.includes(segment.startsWith('/') ? segment : `/${segment}`)
    || normalized.endsWith(segment)
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
