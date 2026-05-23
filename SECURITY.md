# Security policy

## Reporting a vulnerability

If you find a security issue in SessionTrail, please **do not** open a public issue or PR. Instead, use GitHub's [Private vulnerability reporting](https://github.com/Conalh/SessionTrail/security/advisories/new) to disclose it privately.

I'll respond within 7 days and aim to ship a fix within 30 days of confirmation, depending on severity.

## Threat model

SessionTrail is an offline, read-only audit tool. It is **not** a hosted scanner and uploads nothing by default.

### Attacker input surfaces

| Surface | Trust level | What we do with it |
|---|---|---|
| Transcript JSONL files | Untrusted | Parsed (JSON.parse), tool inputs read as strings, paths compared lexically — never executed, never read as filesystem targets |
| `.sessiontrail.json` allowlist | Repo-owner-trusted | JSON-parsed; `benignShellPatterns` compiled as regexes |
| CLI flags (`--transcript`, `--repo`, `--config`, …) | User-trusted | Validated for existence (`--transcript`, `--config`); used as paths to read |
| GitHub Action inputs | Workflow-author-trusted | Passed via env vars to bash with quoted variable expansion; forwarded as quoted CLI args |

### What SessionTrail does not do

- No `child_process` / `spawn` / `exec` — SessionTrail does not run external commands.
- No `eval` / `Function` / dynamic code loading.
- No network calls — transcripts and config are read from local disk; the action uploads nothing unless the consumer explicitly chains `upload-sarif`.
- No reads of paths claimed inside transcripts — paths are normalized and string-compared, never opened.

### Known boundaries you should know about

**`.sessiontrail.json` is trusted.** Regex sources in `benignShellPatterns` are compiled and executed against shell subcommands during the audit. A malicious regex (catastrophic-backtracking shape) combined with a crafted shell command in a transcript could DoS the audit process.

Mitigations in place:
- `compileAllowlist` rejects regex sources containing the canonical nested-unbounded-quantifier shape (`(a+)+`, `(a*)*`, `(a*)+`, `(a+)*`) at config-load time — the catastrophic-backtracking pattern fails immediately with a clear error instead of hanging the runner.
- Input length passed to user-regex `.test()` is additionally capped at 4 KB ([config.ts](src/config.ts)) as defense in depth.
- The CLI runs as a single-shot process; a hung audit affects only that one CI run, not a long-running service.

The shape-detection heuristic is not exhaustive — sophisticated patterns can escape it (e.g. specific alternation arrangements). If you accept `.sessiontrail.json` changes from untrusted PRs, review them the way you'd review any executable config.

If you grant write access to `.sessiontrail.json` to untrusted contributors (e.g., by auto-merging Dependabot PRs that touch the config), review changes the same way you'd review changes to any executable config.

**Bundled dependencies.** The GitHub Action ships a single bundled `bundle/index.js` produced by `@vercel/ncc`, which inlines [agent-gov-core](https://github.com/Conalh/agent-gov-core) and its transitive dependencies. CI verifies the bundle is byte-identical to a fresh build (`git diff --exit-code -- bundle` after `npm run bundle`), so a dependency compromise that changes generated output is caught at PR time.

**Reads of large transcripts.** `loadTranscriptEvents` reads each `.jsonl` into memory in full. On a GitHub-hosted runner (~7 GB RAM) this caps the realistic input at hundreds of MB. SessionTrail does not currently stream-parse; a deliberately oversized transcript could cause OOM. This is a DoS, not a confidentiality or integrity issue.

### Severity rating philosophy

SessionTrail emits findings about agent behavior with severities `low`, `medium`, `high`, `critical`. Those severities describe **the audited agent's behavior**, not SessionTrail-the-tool's own security posture. A `critical` finding from SessionTrail means the agent did something that warrants immediate review; it does not mean SessionTrail itself has a vulnerability.

## Supported versions

| Version | Supported |
|---|---|
| `v0.5.x` | ✅ |
| `< v0.5.0` | ❌ — please upgrade |
