import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// Per-repo allowlist for behaviors that are noisy in normal operation
// but not security-relevant for a specific project. Lives at
// `<repo>/.sessiontrail.json`. Missing file is fine — every field is
// optional and the audit runs with an empty allowlist by default.
export interface AllowlistConfig {
  // MCP servers that are expected for this repo. Findings whose
  // data.server matches an entry drop to severity 'low' so they stay
  // visible in the report but don't trip --fail-on at medium+.
  allowedMcpServers?: string[];
  // Shell command patterns (RegExp source strings) that are expected
  // benign workflows for this repo — e.g. `^cargo\\s+test`,
  // `^deno\\s+task\\s+\\w+$`. Compiled with case-insensitive flag.
  // Matched against each tokenizeShell subcommand. A matching subcommand
  // contributes 'low' instead of 'medium' to the shell severity ladder;
  // RISKY_PATTERNS still win, so allowlist can't whitelist `curl | sh`.
  benignShellPatterns?: string[];
  // Network hosts (substring match, case-insensitive) that are expected
  // for this repo. Findings whose data.target contains a host match
  // drop to severity 'low'. Useful for legitimate internal APIs.
  allowedNetworkHosts?: string[];
}

export interface CompiledAllowlist {
  allowedMcpServers: Set<string>;
  benignShellPatterns: RegExp[];
  allowedNetworkHosts: string[];
}

const EMPTY: CompiledAllowlist = {
  allowedMcpServers: new Set(),
  benignShellPatterns: [],
  allowedNetworkHosts: []
};

export async function loadAllowlist(repoRoot: string, configPath?: string): Promise<CompiledAllowlist> {
  // Explicit --config path bypasses the default <repo>/.sessiontrail.json
  // lookup. When the user passes --config, missing-file is an ERROR
  // (they asked for a specific file) — only the auto-discovery path
  // silently falls back to empty when no config exists.
  const resolvedPath = configPath ?? join(repoRoot, '.sessiontrail.json');
  const allowMissing = configPath === undefined;

  let raw: string;
  try {
    raw = await readFile(resolvedPath, 'utf8');
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === 'ENOENT') {
      return EMPTY;
    }
    throw error;
  }

  let parsed: AllowlistConfig;
  try {
    parsed = JSON.parse(raw) as AllowlistConfig;
  } catch (error) {
    // A malformed config file is a user mistake worth surfacing —
    // silently ignoring it could mask an allowlist that didn't take
    // effect because of a typo.
    throw new Error(`Failed to parse ${resolvedPath}: ${(error as Error).message}`);
  }

  return compileAllowlist(parsed);
}

export function compileAllowlist(config: AllowlistConfig): CompiledAllowlist {
  return {
    allowedMcpServers: new Set((config.allowedMcpServers ?? []).map((s) => s.toLowerCase())),
    benignShellPatterns: (config.benignShellPatterns ?? []).map((source) => new RegExp(source, 'i')),
    allowedNetworkHosts: (config.allowedNetworkHosts ?? []).map((s) => s.toLowerCase())
  };
}

export function isMcpServerAllowed(server: string | undefined, allowlist: CompiledAllowlist): boolean {
  return typeof server === 'string' && allowlist.allowedMcpServers.has(server.toLowerCase());
}

export function isShellSubcommandBenign(sub: string, allowlist: CompiledAllowlist): boolean {
  return allowlist.benignShellPatterns.some((pattern) => pattern.test(sub));
}

export function isNetworkTargetAllowed(target: string | undefined, allowlist: CompiledAllowlist): boolean {
  if (typeof target !== 'string' || allowlist.allowedNetworkHosts.length === 0) {
    return false;
  }

  // Parse the URL and match against the hostname only, with an exact
  // or suffix-with-dot rule. Substring matching used to be the rule
  // and it had a homoglyph hazard: an attacker-controlled host like
  // `internal.example.com.evil.test` substring-matches the allowlist
  // entry `internal.example.com` and gets auto-trusted. Anchored host
  // matching closes that.
  //
  // If the target isn't a parseable URL (e.g. a WebSearch search term),
  // host matching can't apply — we can't safely allow it without a
  // host, so we don't.
  let host: string;
  try {
    host = new URL(target).hostname.toLowerCase();
  } catch {
    return false;
  }

  return allowlist.allowedNetworkHosts.some(
    (pattern) => host === pattern || host.endsWith(`.${pattern}`)
  );
}
