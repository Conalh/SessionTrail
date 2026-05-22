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

// Pulls every path the tool event touched, tagged read vs write.
// Returns raw strings — callers decide whether to normalize (transcript.ts
// uses normalized paths as Map keys, the detector hands them to path
// predicates that normalize on their own).
export function collectEventPaths(event: ToolEvent): ToolPath[] {
  const input = event.input;
  const paths: ToolPath[] = [];

  const add = (value: unknown, kind: PathAccessKind) => {
    if (typeof value === 'string' && value.trim()) {
      paths.push({ path: value, kind });
    }
  };

  switch (event.tool) {
    case 'Read':
    case 'ReadLints':
      add(input.path, 'read');
      add(input.file_path, 'read');
      if (Array.isArray(input.paths)) {
        for (const path of input.paths) {
          add(path, 'read');
        }
      }
      break;
    case 'Write':
    case 'StrReplace':
    case 'Delete':
    case 'Edit':
    case 'MultiEdit':
      add(input.path, 'write');
      add(input.file_path, 'write');
      break;
    case 'Grep':
    case 'Glob':
      add(input.path ?? input.target_directory, 'read');
      break;
    default:
      if (isShellTool(event.tool)) {
        add(input.working_directory ?? input.workdir ?? input.cwd, 'read');
      } else if (toolKey(event.tool) === 'view_image') {
        add(input.path, 'read');
      } else if (toolKey(event.tool) === 'apply_patch') {
        for (const path of extractPatchPaths(input.patch)) {
          add(path, 'write');
        }
      }
      break;
  }

  return paths;
}
