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
  return (
    /^[a-z]:\/users\//i.test(normalized) ||
    normalized.startsWith('/users/') ||
    normalized.startsWith('/home/') ||
    normalized.includes('/.cursor/')
  );
}

export function isTranscriptPath(targetPath: string): boolean {
  const normalized = normalizePath(targetPath).toLowerCase();
  return normalized.includes('/agent-transcripts/') && normalized.endsWith('.jsonl');
}

export function isBroadScanPath(targetPath: string | undefined): boolean {
  if (!targetPath) {
    return false;
  }

  const normalized = normalizePath(targetPath).toLowerCase();
  return /^[a-z]:\/users\/[^/]+\/?$/i.test(normalized) || /^\/users\/[^/]+\/?$/i.test(normalized);
}
