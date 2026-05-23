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

// Heuristic catastrophic-regex detector. Catches the classic nested-
// unbounded-quantifier shape (e.g. `(a+)+`, `(a*)*`, `(a*)+`) at
// compile time by looking for `[*+?]\)[*+]` in the source — an inner
// quantifier of any kind followed by a close paren followed by an
// UNBOUNDED outer quantifier (`*` or `+`). The unbounded outer is the
// load-bearing part: `(\d+)?` has `+)?` but `?` only lets the group
// match zero or one times, so no exponential blowup. `(\d+)+` and
// `(\d+)*` are the actual ReDoS shapes.
//
// Limitations: heuristic, not a proof. Sophisticated patterns that
// escape it (specific alternation arrangements, lookaround-driven
// blowups) can still cause ReDoS. The 4 KB input cap is belt-and-
// suspenders, and SECURITY.md is explicit that `.sessiontrail.json`
// is repo-owner-trusted.
const CATASTROPHIC_SHAPE = /[*+?]\)[*+]/;

export function compileAllowlist(config: AllowlistConfig): CompiledAllowlist {
  const patterns = (config.benignShellPatterns ?? []).map((source) => {
    if (CATASTROPHIC_SHAPE.test(source)) {
      throw new Error(
        `Refusing to compile benignShellPattern with nested-quantifier shape (potential ReDoS): ${source}`
      );
    }
    return new RegExp(source, 'i');
  });
  return {
    allowedMcpServers: new Set((config.allowedMcpServers ?? []).map((s) => s.toLowerCase())),
    benignShellPatterns: patterns,
    allowedNetworkHosts: (config.allowedNetworkHosts ?? []).map((s) => s.toLowerCase())
  };
}

export function isMcpServerAllowed(server: string | undefined, allowlist: CompiledAllowlist): boolean {
  return typeof server === 'string' && allowlist.allowedMcpServers.has(server.toLowerCase());
}

// Cap on the input length we hand to user-supplied regexes. The
// regex SOURCE comes from .sessiontrail.json, which in a CI workflow
// running on `pull_request` is effectively attacker-controlled — a PR
// can ship a malicious regex (catastrophic-backtracking shape) along
// with a long shell command in a transcript and DoS the runner.
// Truncating the input bounds work per .test() call to O(N * patterns)
// at worst. Legitimate shell subcommands are well under this cap;
// anything longer is either machine-generated paste or an attacker
// trying to make a regex chew on it.
const MAX_USER_REGEX_INPUT = 4096;

export function isShellSubcommandBenign(sub: string, allowlist: CompiledAllowlist): boolean {
  if (allowlist.benignShellPatterns.length === 0) {
    return false;
  }
  const bounded = sub.length > MAX_USER_REGEX_INPUT ? sub.slice(0, MAX_USER_REGEX_INPUT) : sub;
  return allowlist.benignShellPatterns.some((pattern) => pattern.test(bounded));
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
