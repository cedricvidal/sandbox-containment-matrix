/**
 * Shared helpers for driving MXC sandboxes from the TypeScript SDK.
 *
 * MXC backends differ per host (processcontainer on Windows, bubblewrap on
 * Linux, seatbelt on macOS). Everything here stays on the cross-platform
 * `SandboxPolicy` surface so the same scenarios run everywhere MXC is
 * supported.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import {
  createConfigFromPolicy,
  getAvailableToolsPolicy,
  getPlatformSupport,
  getTemporaryFilesPolicy,
  spawnSandboxFromConfig,
} from '@microsoft/mxc-sdk';

/**
 * Schema 0.7.0-alpha is the lowest version accepted by every stable backend we
 * target: Seatbelt (macOS) requires >= 0.7.0-alpha, while ProcessContainer and
 * Bubblewrap accept it too. 0.8.0-alpha would force the directional
 * egress/ingress network shape, which is not what the upstream sample uses.
 */
export const SCHEMA_VERSION = '0.7.0-alpha' as const;

export interface SandboxRunOptions {
  /**
   * Confine the sandboxed process to every CPU except the first one this
   * process is allowed on, reserving that CPU for the trusted side.
   *
   * MXC has no CPU control of its own, and a container-wide cgroup quota
   * throttles the orchestrator just as hard as the workload. CPU affinity is
   * the one mechanism that discriminates between the two, and it needs no
   * cgroup delegation. Linux only; ignored elsewhere.
   */
  reserveHostCpu?: boolean;
  /** Command executed inside the sandbox. */
  commandLine: string;
  /** Allow outbound network access. Defaults to `false` (deny). */
  allowOutbound?: boolean;
  /** Extra read-only paths on top of the discovered host tool paths. */
  readonlyPaths?: string[];
  /** Extra read-write paths on top of the discovered temp directory. */
  readwritePaths?: string[];
  /** Wall-clock budget for the sandboxed process. Defaults to 30s. */
  timeoutMs?: number;
}

export interface SandboxRunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

export class MxcUnsupportedHostError extends Error {
  constructor(details: string) {
    super(`MXC is not available on this host: ${details}`);
    this.name = 'MxcUnsupportedHostError';
  }
}

/** Throws unless the native MXC runner supports the current host. */
export function assertMxcSupported(): void {
  const support = getPlatformSupport();
  if (!support.isSupported) {
    throw new MxcUnsupportedHostError(
      support.reason ?? `${process.platform}/${process.arch} has no available backend`,
    );
  }
}

/** Human-readable summary of what this host can contain. */
export function describePlatformSupport(): string {
  const support = getPlatformSupport();
  const lines = [
    `host      : ${process.platform}/${process.arch}`,
    `supported : ${support.isSupported}`,
    `backends  : ${support.availableMethods.join(', ') || '(none)'}`,
  ];
  if (support.reason) lines.push(`reason    : ${support.reason}`);
  if (support.isolationTier) lines.push(`tier      : ${support.isolationTier}`);
  if (support.isolationWarnings?.length) {
    lines.push(`warnings  : ${support.isolationWarnings.join('; ')}`);
  }
  return lines.join('\n');
}

/**
 * CPUs this process may run on, from `Cpus_allowed_list`. `os.cpus()` reports
 * every host core regardless of the container's cpuset, so it is the wrong
 * input for pinning.
 */
export function allowedCpus(): number[] {
  if (process.platform !== 'linux') return [];
  try {
    const line = /^Cpus_allowed_list:\s*(.+)$/m
      .exec(readFileSync('/proc/self/status', 'utf8'))?.[1]
      ?.trim();
    if (!line) return [];
    const cpus: number[] = [];
    for (const part of line.split(',')) {
      const [lo, hi] = part.split('-').map((n) => Number.parseInt(n, 10));
      for (let i = lo; i <= (Number.isNaN(hi) ? lo : hi); i += 1) cpus.push(i);
    }
    return cpus;
  } catch {
    return [];
  }
}

/**
 * Command prefix confining a child to every allowed CPU but the first.
 * Returns '' when that is impossible (non-Linux, no `taskset`, or a single
 * allowed CPU — you cannot reserve the only core you have).
 */
export function reserveHostCpuPrefix(): string {
  const cpus = allowedCpus();
  if (cpus.length < 2) return '';
  try {
    execFileSync('taskset', ['--version'], { stdio: 'ignore' });
  } catch {
    return '';
  }
  return `taskset -c ${cpus.slice(1).join(',')} `;
}

/**
 * Builds a least-privilege policy: host toolchain paths mounted read-only, the
 * temp directory read-write, network denied unless explicitly opted in.
 */
export function buildConfig(options: SandboxRunOptions) {
  const tools = getAvailableToolsPolicy(process.env);
  const temp = getTemporaryFilesPolicy();

  const config = createConfigFromPolicy(
    {
      version: SCHEMA_VERSION,
      filesystem: {
        readonlyPaths: [...tools.readonlyPaths, ...(options.readonlyPaths ?? [])],
        readwritePaths: [...temp.readwritePaths, ...(options.readwritePaths ?? [])],
      },
      network: { allowOutbound: options.allowOutbound ?? false },
      timeoutMs: options.timeoutMs ?? 30_000,
    },
    'process',
  );

  const prefix = options.reserveHostCpu ? reserveHostCpuPrefix() : '';
  config.process!.commandLine = `${prefix}${options.commandLine}`;
  return config;
}

/**
 * Runs a command inside a one-shot sandbox in pipe mode (`usePty: false`) so
 * stdout and stderr stay separated and the exit code is reliable.
 */
export function runInSandbox(options: SandboxRunOptions): Promise<SandboxRunResult> {
  const config = buildConfig(options);

  return new Promise((resolve, reject) => {
    const child = spawnSandboxFromConfig(config, { usePty: false });
    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (exitCode: number | null) => {
      resolve({ stdout, stderr, exitCode });
    });
  });
}

/** Trims and indents captured output for readable console reports. */
export function indent(text: string, prefix = '    '): string {
  const trimmed = text.trim();
  if (!trimmed) return `${prefix}(empty)`;
  return trimmed
    .split('\n')
    .map((line) => `${prefix}${line}`)
    .join('\n');
}
