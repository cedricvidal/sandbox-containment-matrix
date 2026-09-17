/**
 * Does the trusted side keep breathing while the sandboxed workload saturates
 * the CPU?
 *
 * MXC has no CPU limit (see docs/findings.md §12), so a sandboxed workload
 * competes for the same cores as the orchestrator that launched it. This
 * measures the orchestrator's own responsiveness — event-loop delay and timer
 * tick completion — while a hog runs inside the sandbox.
 *
 * The subtlety: a container-wide cgroup cap does NOT separate the two. It
 * throttles the trusted process just as hard as the untrusted one. Scheduling
 * priority does separate them, which is what the `nice` arm demonstrates.
 *
 * Run with: pnpm latency
 */
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { getTemporaryFilesPolicy } from '@microsoft/mxc-sdk';
import { assertMxcSupported, describePlatformSupport, runInSandbox } from './mxc-utils.js';

const NODE = process.execPath;
const TEMP_DIR = getTemporaryFilesPolicy().readwritePaths[0] ?? os.tmpdir();
const LOAD_MS = 4_000;
/** The trusted side's "service": a timer that should fire every 20ms. */
const TICK_MS = 20;
/**
 * Each tick does real CPU work, so the trusted side genuinely competes for a
 * core. Measuring an idle event loop proves nothing: an orchestrator merely
 * awaiting a child process needs almost no CPU and never looks starved.
 */
const TICK_WORK_MS = 5;

interface Sample {
  label: string;
  p50: number;
  p99: number;
  max: number;
  ticks: number;
  expectedTicks: number;
  /** Wall time actually taken by the TICK_WORK_MS of work, p99. */
  workP99: number;
  hogExit?: number | null;
}

/** Busy-work standing in for the orchestrator's own processing. */
function doTickWork(): number {
  const started = process.hrtime.bigint();
  const deadline = Date.now() + TICK_WORK_MS;
  while (Date.now() < deadline) crypto.createHash('sha256').update('x').digest();
  return Number(process.hrtime.bigint() - started) / 1e6;
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

/**
 * Runs the trusted-side measurement for `durationMs`, optionally with a
 * sandboxed CPU hog running concurrently.
 */
async function measure(label: string, hogCommand?: string): Promise<Sample> {
  const histogram = monitorEventLoopDelay({ resolution: 5 });
  let ticks = 0;
  const workDurations: number[] = [];
  const started = Date.now();

  histogram.enable();
  const timer = setInterval(() => {
    ticks += 1;
    workDurations.push(doTickWork());
  }, TICK_MS);

  let hogExit: number | null | undefined;
  if (hogCommand) {
    const result = await runInSandbox({ commandLine: hogCommand, timeoutMs: 60_000 });
    hogExit = result.exitCode;
  } else {
    await new Promise((resolve) => setTimeout(resolve, LOAD_MS));
  }

  clearInterval(timer);
  histogram.disable();

  const elapsed = Date.now() - started;
  return {
    label,
    p50: histogram.percentile(50) / 1e6,
    p99: histogram.percentile(99) / 1e6,
    max: histogram.max / 1e6,
    ticks,
    expectedTicks: Math.round(elapsed / TICK_MS),
    workP99: percentile(workDurations, 99),
    hogExit,
  };
}

/** One spinner per visible core, for LOAD_MS. */
async function writeHogScript(): Promise<string> {
  const scriptPath = path.join(TEMP_DIR, `mxc-hog-${process.pid}.cjs`);
  await fs.writeFile(
    scriptPath,
    `
const os = require('os');
const { Worker } = require('worker_threads');
const src = 'const e = Date.now() + ${LOAD_MS}; while (Date.now() < e) { Math.sqrt(Math.random()); }';
const ws = Array.from({ length: os.cpus().length }, () => new Worker(src, { eval: true }));
Promise.all(ws.map((w) => new Promise((r) => w.on('exit', r)))).then(() => console.log('hog done'));
`,
  );
  return scriptPath;
}

/** `taskset` ships with util-linux; absent on macOS. */
function hasTaskset(): boolean {
  try {
    execFileSync('taskset', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * CPUs this process is actually allowed to run on. `os.cpus()` reports every
 * host core regardless of the container's cpuset, so pinning against it would
 * name CPUs outside the allowed set and fail.
 */
function allowedCpus(): number[] {
  try {
    const status = readFileSync('/proc/self/status', 'utf8');
    const line = /^Cpus_allowed_list:\s*(.+)$/m.exec(status)?.[1]?.trim();
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

function report(s: Sample): void {
  const served = ((s.ticks / s.expectedTicks) * 100).toFixed(0);
  console.log(`\n--- ${s.label}`);
  console.log(`  event-loop delay : p50 ${s.p50.toFixed(1)}ms  p99 ${s.p99.toFixed(1)}ms  max ${s.max.toFixed(1)}ms`);
  console.log(`  ${TICK_MS}ms service ticks: ${s.ticks}/${s.expectedTicks} (${served}% served)`);
  console.log(`  ${TICK_WORK_MS}ms of work took : p99 ${s.workP99.toFixed(1)}ms (stretch ${(s.workP99 / TICK_WORK_MS).toFixed(1)}x)`);
}

async function main(): Promise<void> {
  console.log('=== Trusted-side responsiveness under sandboxed CPU load ===');
  console.log(describePlatformSupport());
  console.log(`\ncores visible   : ${os.cpus().length}`);
  console.log(`load duration   : ${LOAD_MS}ms, one spinner per core`);
  console.log(`trusted service : every ${TICK_MS}ms, do ${TICK_WORK_MS}ms of real CPU work\n`);

  assertMxcSupported();

  const hog = await writeHogScript();
  try {
    const idle = await measure('baseline — no sandboxed load');
    report(idle);

    const loaded = await measure('sandboxed hog at normal priority', `${NODE} ${hog}`);
    report(loaded);

    // `commandLine` runs through `sh -c`, so a `nice` prefix is simply part of
    // the command. This is the one CPU control available without cgroup
    // delegation: it separates the two sides by priority rather than by quota.
    const niced = await measure(
      'sandboxed hog at nice 19 (lowest priority)',
      `nice -n 19 ${NODE} ${hog}`,
    );
    report(niced);

    // Constrain the *sandbox* rather than the whole container: reserve the
    // first allowed CPU for the trusted side and confine the hog to the rest.
    // Unlike a cgroup quota this discriminates between the two sides — the
    // quota throttles the whole group, this bounds only the workload.
    const allowed = allowedCpus();
    let pinned: Sample | undefined;
    if (hasTaskset() && allowed.length > 1) {
      const reserved = allowed[0];
      const forHog = allowed.slice(1).join(',');
      pinned = await measure(
        `hog confined to CPUs ${forHog}, CPU ${reserved} reserved for trusted`,
        `taskset -c ${forHog} ${NODE} ${hog}`,
      );
      report(pinned);
    } else if (allowed.length === 1) {
      console.log(
        `\n--- affinity arm skipped: only CPU ${allowed[0]} is allowed, ` +
          'nothing can be reserved',
      );
    }

    console.log('\n=== Summary ===');
    const rows: Array<[string, Sample]> = [
      ['idle', idle],
      ['hog', loaded],
      ['hog + nice 19', niced],
    ];
    if (pinned) rows.push(['hog + affinity', pinned]);
    console.log(
      `  ${'scenario'.padEnd(14)} ${'loop p99'.padStart(9)} ${'work p99'.padStart(9)} ${'stretch'.padStart(8)} ${'served'.padStart(7)}`,
    );
    for (const [name, s] of rows) {
      const served = (s.ticks / s.expectedTicks) * 100;
      console.log(
        `  ${name.padEnd(14)} ${s.p99.toFixed(1).padStart(7)}ms ${s.workP99.toFixed(1).padStart(7)}ms ` +
          `${(s.workP99 / TICK_WORK_MS).toFixed(1).padStart(7)}x ${served.toFixed(0).padStart(6)}%`,
      );
    }

    // Work stretch is the honest headline: how much longer a fixed slice of
    // trusted-side work takes while the sandbox is saturating the machine.
    const stretch = loaded.workP99 / Math.max(idle.workP99, 0.01);
    const nicedStretch = niced.workP99 / Math.max(idle.workP99, 0.01);
    console.log(
      `\n  trusted work slowdown vs idle: ${stretch.toFixed(1)}x at normal priority, ` +
        `${nicedStretch.toFixed(1)}x at nice 19`,
    );
    console.log(
      '\nNote: a container-wide cgroup cap (mxc-limits) throttles this trusted\n' +
        'process too — it bounds total consumption but does not reserve headroom.\n' +
        'To protect the trusted side, constrain the sandbox specifically (CPU\n' +
        'affinity, or a child cgroup) rather than capping the whole container.\n' +
        'See docs/findings.md §16.',
    );
  } finally {
    await fs.rm(hog, { force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
