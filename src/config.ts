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

export async function loadAllowlist(repoRoot: string): Promise<CompiledAllowlist> {
  let raw: string;
  try {
    raw = await readFile(join(repoRoot, '.sessiontrail.json'), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
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
    throw new Error(`Failed to parse .sessiontrail.json: ${(error as Error).message}`);
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
  if (typeof target !== 'string') {
    return false;
  }
  const lowered = target.toLowerCase();
  return allowlist.allowedNetworkHosts.some((host) => lowered.includes(host));
}
