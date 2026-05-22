import type { ToolEvent } from './types.js';

export type PathAccessKind = 'read' | 'write';

export interface ToolPath {
  path: string;
  kind: PathAccessKind;
}

export function toolKey(tool: string): string {
  return (tool.split('.').pop() ?? tool).toLowerCase();
}

export function isShellTool(tool: string): boolean {
  const key = toolKey(tool);
  return key === 'shell' || key === 'bash' || key === 'shell_command';
}

export function extractPatchPaths(value: unknown): string[] {
  if (typeof value !== 'string') {
    return [];
  }

  const paths: string[] = [];
  const pattern = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    paths.push(match[1].trim());
  }
  return paths;
}

// High-signal path candidates inside a shell command string. Conservative
// on purpose — false positives would create a noisy out-of-repo finding
// for every random shell-arg-shaped word. We only match shapes that are
// almost certainly file paths:
//   - tilde-rooted: ~/foo, ~bar/baz
//   - Windows-absolute: C:\foo or C:/foo
//   - POSIX-absolute: /etc/foo, /home/u/x (also /var, /private, /Users…)
//   - dotfile-rooted: .ssh/id_rsa, .aws/credentials (key credential dirs)
// Bare relative tokens like `package.json` are NOT extracted — we have no
// way to distinguish them from non-path arguments without false positives.
const SHELL_PATH_CANDIDATES = [
  /(?:^|[\s'"`=()|&;<>])(~[\w./-]*)/g,
  /(?:^|[\s'"`=()|&;<>])([a-z]:[\\/][\w.\\/-]+)/gi,
  /(?:^|[\s'"`=()|&;<>])(\/[\w./-]+)/g,
  /(?:^|[\s'"`=()|&;<>])(\.(?:ssh|aws|gnupg|kube|docker|netrc)(?:[\\/][\w./-]+)?)/gi
];

export function extractShellPaths(command: string): string[] {
  if (!command) {
    return [];
  }

  const found = new Set<string>();
  for (const pattern of SHELL_PATH_CANDIDATES) {
    // Each pattern keeps its own lastIndex; defensive reset before reuse.
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(command)) !== null) {
      // Strip trailing punctuation that shell-quoted args drag along.
      const cleaned = match[1].replace(/[)>,;|&'"`]+$/, '');
      if (cleaned) {
        found.add(cleaned);
      }
    }
  }
  return [...found];
}

// Tools whose payload paths we know how to extract, keyed by the
// normalized tool key (lowercased, post-namespace). Transcript formats
// across runtimes use varying casing and namespacing — claude-code emits
// `Read`, codex emits `shell_command`, hypothetical futures might use
// `agent.read` or `READ` — so we normalize before matching.
const READ_TOOLS = new Set(['read', 'readlints']);
const WRITE_TOOLS = new Set(['write', 'strreplace', 'delete', 'edit', 'multiedit']);
const SEARCH_TOOLS = new Set(['grep', 'glob']);

// Pulls every path the tool event touched, tagged read vs write.
// Returns raw strings — callers decide whether to normalize (transcript.ts
// uses normalized paths as Map keys, the detector hands them to path
// predicates that normalize on their own).
export function collectEventPaths(event: ToolEvent): ToolPath[] {
  const input = event.input;
  const paths: ToolPath[] = [];
  const key = toolKey(event.tool);

  const add = (value: unknown, kind: PathAccessKind) => {
    if (typeof value === 'string' && value.trim()) {
      paths.push({ path: value, kind });
    }
  };

  if (READ_TOOLS.has(key)) {
    add(input.path, 'read');
    add(input.file_path, 'read');
    if (Array.isArray(input.paths)) {
      for (const path of input.paths) {
        add(path, 'read');
      }
    }
  } else if (WRITE_TOOLS.has(key)) {
    add(input.path, 'write');
    add(input.file_path, 'write');
  } else if (SEARCH_TOOLS.has(key)) {
    add(input.path ?? input.target_directory, 'read');
  } else if (isShellTool(event.tool)) {
    add(input.working_directory ?? input.workdir ?? input.cwd, 'read');
  } else if (key === 'view_image') {
    add(input.path, 'read');
  } else if (key === 'apply_patch') {
    for (const path of extractPatchPaths(input.patch)) {
      add(path, 'write');
    }
  }

  return paths;
}
