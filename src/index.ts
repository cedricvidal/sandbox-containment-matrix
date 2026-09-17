/**
 * MXC TypeScript SDK experiment — runs a series of sandbox scenarios and
 * asserts that MXC enforces the policy it was given.
 *
 * Run with: pnpm dev
 */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getTemporaryFilesPolicy } from '@microsoft/mxc-sdk';
import {
  MxcUnsupportedHostError,
  assertMxcSupported,
  describePlatformSupport,
  indent,
  runInSandbox,
  type SandboxRunOptions,
  type SandboxRunResult,
} from './mxc-utils.js';

/**
 * The sandbox does not inherit `process.env`, so `PATH` lookups resolve
 * against the backend default rather than the host shell. Always drive
 * sandboxed commands with absolute interpreter paths.
 */
const NODE = process.execPath;

/** First read-write path the SDK discovered — the only writable place by default. */
const TEMP_DIR = getTemporaryFilesPolicy().readwritePaths[0] ?? os.tmpdir();

type Status = 'pass' | 'fail' | 'skip' | 'error';

interface Outcome {
  status: Status;
  detail: string;
}

interface Scenario {
  name: string;
  what: string;
  run: () => Promise<Outcome>;
}

/** Host-side fixture used by the read-only mount scenarios. */
interface Fixture {
  dir: string;
  file: string;
}

async function createFixture(): Promise<Fixture> {
  // Deliberately *outside* the discovered temp dir: anything under the policy's
  // readwritePaths would already be reachable, which would defeat the point of
  // the "not granted" scenario.
  const dir = await fs.mkdtemp(fileURLToPath(new URL('../.fixture-', import.meta.url)));
  const file = path.join(dir, 'secret-recipe.txt');
  await fs.writeFile(file, SECRET);
  return { dir, file };
}

const SECRET = 'sourdough starter: flour + water + patience\n';

/**
 * A sandbox that never started is not evidence of containment. Bubblewrap
 * reports setup failures on stderr before the workload runs, and a scenario
 * that merely expects "non-zero exit" would otherwise score those as passes.
 */
function launchFailure(result: SandboxRunResult): string | null {
  const match = result.stderr.match(/^\s*(bwrap|lxc-exec|mxc-exec[\w-]*|wxc-exec[\w.-]*):\s*(.+)$/m);
  return match ? match[0].trim() : null;
}

async function exists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

/** Runs a command and checks the outcome against an expectation. */
async function expectRun(
  options: SandboxRunOptions,
  expectation: {
    succeeds: boolean;
    outputIncludes?: string;
    outputExcludes?: string;
    /** Extra host-side assertion, e.g. "the file was never created". */
    andThen?: () => Promise<string | null>;
  },
): Promise<Outcome> {
  const result = await runInSandbox(options);

  const failure = launchFailure(result);
  if (failure) {
    return { status: 'error', detail: `sandbox did not start: ${failure}` };
  }

  const succeeded = result.exitCode === 0;
  const stream = succeeded ? result.stdout : result.stderr || result.stdout;
  const detail = `exit=${result.exitCode}\n${indent(summarize(stream))}`;

  if (succeeded !== expectation.succeeds) return { status: 'fail', detail };
  if (expectation.outputIncludes && !result.stdout.includes(expectation.outputIncludes)) {
    return { status: 'fail', detail };
  }
  if (expectation.outputExcludes && result.stdout.includes(expectation.outputExcludes)) {
    return { status: 'fail', detail: `${detail}\n    leaked: ${expectation.outputExcludes}` };
  }

  const problem = await expectation.andThen?.();
  if (problem) return { status: 'fail', detail: `${detail}\n    ${problem}` };

  return { status: 'pass', detail };
}

/**
 * Node prints a full stack trace on a denied syscall. Keep the line that
 * actually explains the outcome (`Error: EPERM: ...`) instead of the framing.
 */
function summarize(text: string): string {
  const lines = text.trim().split('\n');
  const signal = lines.filter((line) => /^(Error|[A-Za-z]*Error:|blocked:|bwrap:)/.test(line.trim()));
  return (signal.length > 0 ? signal : lines).slice(0, 3).join('\n');
}

function readFileCommand(file: string): string {
  return `${NODE} -e "process.stdout.write(require('fs').readFileSync('${file}','utf8'))"`;
}

function writeFileCommand(file: string): string {
  return `${NODE} -e "require('fs').writeFileSync('${file}','x');console.log('wrote')"`;
}

function outboundProbe(): string {
  const script = [
    "fetch('https://example.com',{signal:AbortSignal.timeout(8000)})",
    ".then(r=>console.log('HTTP',r.status))",
    ".catch(e=>{console.error('blocked:',e.message);process.exit(7)})",
  ].join('');
  return `${NODE} -e "${script}"`;
}

function buildScenarios(fixture: Fixture): Scenario[] {
  const escapeTarget = fileURLToPath(new URL('../escape.txt', import.meta.url));
  const tamperTarget = path.join(fixture.dir, 'tampered.txt');
  const sshDir = path.join(os.homedir(), '.ssh');

  return [
    {
      name: 'hello-world',
      what: 'runs a trivial command inside the sandbox',
      run: () =>
        expectRun(
          { commandLine: `${NODE} -e "console.log('hello from sandbox')"` },
          { succeeds: true, outputIncludes: 'hello from sandbox' },
        ),
    },
    {
      name: 'fs-write-allowed',
      what: 'writes into a path listed in readwritePaths',
      run: () => {
        const target = path.join(TEMP_DIR, 'mxc-experiment.txt');
        return expectRun(
          { commandLine: writeFileCommand(target) },
          { succeeds: true, outputIncludes: 'wrote' },
        );
      },
    },
    {
      name: 'fs-write-contained',
      what: 'a write outside readwritePaths never reaches the host',
      run: async () => {
        // Seatbelt denies the syscall outright; Bubblewrap instead hides the
        // path, so the write "succeeds" into a throwaway namespace. Both are
        // acceptable — what matters is that the host file does not appear.
        const result = await runInSandbox({ commandLine: writeFileCommand(escapeTarget) });
        const failure = launchFailure(result);
        if (failure) return { status: 'error', detail: `sandbox did not start: ${failure}` };

        const leaked = await exists(escapeTarget);
        if (leaked) await fs.rm(escapeTarget, { force: true });

        const how = result.exitCode === 0 ? 'write redirected into the sandbox' : 'write denied';
        return {
          status: leaked ? 'fail' : 'pass',
          detail: leaked
            ? `host file was created at ${escapeTarget}`
            : `${how} (exit=${result.exitCode}); host file absent`,
        };
      },
    },
    {
      name: 'fs-read-denied',
      what: 'reading sensitive host paths (~/.ssh) is refused',
      run: async () => {
        if (!(await exists(sshDir))) {
          return { status: 'skip', detail: `${sshDir} does not exist on this host` };
        }
        return expectRun(
          { commandLine: `${NODE} -e "console.log(require('fs').readdirSync('${sshDir}').join(','))"` },
          { succeeds: false },
        );
      },
    },
    {
      name: 'net-denied',
      what: 'outbound network is blocked with allowOutbound: false',
      run: () => expectRun({ commandLine: outboundProbe() }, { succeeds: false }),
    },
    {
      name: 'net-allowed',
      what: 'outbound network works when the policy opts in',
      run: () =>
        expectRun(
          { commandLine: outboundProbe(), allowOutbound: true },
          { succeeds: true, outputIncludes: 'HTTP' },
        ),
    },
    {
      name: 'extra-path-denied',
      what: 'a host directory absent from the policy discloses nothing',
      run: () =>
        expectRun(
          { commandLine: readFileCommand(fixture.file) },
          { succeeds: false, outputExcludes: 'sourdough' },
        ),
    },
    {
      name: 'extra-path-granted',
      what: 'the same directory becomes readable once added to readonlyPaths',
      run: () =>
        expectRun(
          { commandLine: readFileCommand(fixture.file), readonlyPaths: [fixture.dir] },
          { succeeds: true, outputIncludes: 'sourdough' },
        ),
    },
    {
      name: 'readonly-stays-readonly',
      what: 'a readonlyPaths grant does not allow writes into that directory',
      run: () =>
        expectRun(
          { commandLine: writeFileCommand(tamperTarget), readonlyPaths: [fixture.dir] },
          {
            succeeds: false,
            andThen: async () =>
              (await exists(tamperTarget)) ? `host file was created at ${tamperTarget}` : null,
          },
        ),
    },
  ];
}

const MARKER: Record<Status, string> = {
  pass: 'PASS',
  fail: 'FAIL',
  skip: 'SKIP',
  error: 'ERROR',
};

async function main(): Promise<void> {
  console.log('=== MXC platform support ===');
  console.log(describePlatformSupport());
  console.log(`\ntemp (readwrite): ${TEMP_DIR}`);
  console.log(`interpreter     : ${NODE}\n`);

  assertMxcSupported();

  const fixture = await createFixture();
  try {
    const scenarios = buildScenarios(fixture);
    const tally: Record<Status, number> = { pass: 0, fail: 0, skip: 0, error: 0 };

    for (const scenario of scenarios) {
      process.stdout.write(`\n--- ${scenario.name}: ${scenario.what}\n`);
      let outcome: Outcome;
      try {
        outcome = await scenario.run();
      } catch (error) {
        outcome = { status: 'error', detail: `threw: ${(error as Error).message}` };
      }
      tally[outcome.status] += 1;
      console.log(`  ${MARKER[outcome.status]}  ${outcome.detail.replace(/\n/g, '\n  ')}`);

      // Without a working sandbox every "denied" expectation passes for the
      // wrong reason, so stop instead of reporting meaningless results.
      if (outcome.status === 'error' && scenario.name === 'hello-world') {
        console.error(
          '\nThe baseline scenario could not start a sandbox — aborting.\n' +
            'In a container this usually means the runtime blocks the mounts bwrap needs.\n' +
            'See the "Running in Docker" section of the README.',
        );
        process.exitCode = 3;
        return;
      }
    }

    console.log(
      `\n=== ${tally.pass} passed, ${tally.fail} failed, ${tally.error} errored, ${tally.skip} skipped ===`,
    );
    process.exitCode = tally.fail === 0 && tally.error === 0 ? 0 : 1;
  } finally {
    await fs.rm(fixture.dir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  if (error instanceof MxcUnsupportedHostError) {
    console.error(error.message);
    process.exitCode = 2;
    return;
  }
  console.error(error);
  process.exitCode = 1;
});
