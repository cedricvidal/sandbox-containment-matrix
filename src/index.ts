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
} from './mxc-utils.js';

/**
 * The sandbox does not inherit `process.env`, so `PATH` lookups resolve
 * against the backend default rather than the host shell. Always drive
 * sandboxed commands with absolute interpreter paths.
 */
const NODE = process.execPath;

/** First read-write path the SDK discovered — the only writable place by default. */
const TEMP_DIR = getTemporaryFilesPolicy().readwritePaths[0] ?? os.tmpdir();

interface Scenario {
  name: string;
  what: string;
  run: () => Promise<{ ok: boolean; detail: string }>;
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
  await fs.writeFile(file, 'sourdough starter: flour + water + patience\n');
  return { dir, file };
}

/** Runs a command and checks the outcome against an expectation. */
async function expectRun(
  options: SandboxRunOptions,
  expectation: { succeeds: boolean; outputIncludes?: string },
): Promise<{ ok: boolean; detail: string }> {
  const result = await runInSandbox(options);
  const succeeded = result.exitCode === 0;
  const outputOk =
    expectation.outputIncludes === undefined ||
    result.stdout.includes(expectation.outputIncludes);
  const ok = succeeded === expectation.succeeds && (!expectation.succeeds || outputOk);

  const stream = succeeded ? result.stdout : result.stderr || result.stdout;
  const detail = `exit=${result.exitCode}\n${indent(summarize(stream))}`;
  return { ok, detail };
}

/**
 * Node prints a full stack trace on a denied syscall. Keep the line that
 * actually explains the outcome (`Error: EPERM: ...`) instead of the framing.
 */
function summarize(text: string): string {
  const lines = text.trim().split('\n');
  const signal = lines.filter((line) => /^(Error|[A-Za-z]*Error:|blocked:)/.test(line.trim()));
  return (signal.length > 0 ? signal : lines).slice(0, 3).join('\n');
}

function buildScenarios(fixture: Fixture): Scenario[] {
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
        {
          commandLine: `${NODE} -e "require('fs').writeFileSync('${target}','ok');console.log('wrote ' + '${target}')"`,
        },
        { succeeds: true, outputIncludes: 'wrote' },
      );
    },
  },
  {
    name: 'fs-write-denied',
    what: 'writing outside readwritePaths is refused (EPERM)',
    run: () =>
      expectRun(
        {
          commandLine: `${NODE} -e "require('fs').writeFileSync('${path.join(process.cwd(), 'escape.txt')}','x');console.log('escaped')"`,
        },
        { succeeds: false },
      ),
  },
  {
    name: 'fs-read-denied',
    what: 'reading sensitive host paths (~/.ssh) is refused',
    run: () =>
      expectRun(
        {
          commandLine: `${NODE} -e "console.log(require('fs').readdirSync('${path.join(os.homedir(), '.ssh')}').join(','))"`,
        },
        { succeeds: false },
      ),
  },
  {
    name: 'net-denied',
    what: 'outbound network is blocked with allowOutbound: false',
    run: () =>
      expectRun(
        { commandLine: outboundProbe() },
        { succeeds: false },
      ),
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
    what: 'a host directory absent from the policy is unreadable',
    run: () =>
      expectRun(
        { commandLine: readFileCommand(fixture.file) },
        { succeeds: false },
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
        {
          commandLine: `${NODE} -e "require('fs').writeFileSync('${path.join(fixture.dir, 'tampered.txt')}','x');console.log('tampered')"`,
          readonlyPaths: [fixture.dir],
        },
        { succeeds: false },
      ),
  },
  ];
}

function readFileCommand(file: string): string {
  return `${NODE} -e "process.stdout.write(require('fs').readFileSync('${file}','utf8'))"`;
}

function outboundProbe(): string {
  const script = [
    "fetch('https://example.com',{signal:AbortSignal.timeout(8000)})",
    ".then(r=>console.log('HTTP',r.status))",
    ".catch(e=>{console.error('blocked:',e.message);process.exit(7)})",
  ].join('');
  return `${NODE} -e "${script}"`;
}

async function main(): Promise<void> {
  console.log('=== MXC platform support ===');
  console.log(describePlatformSupport());
  console.log(`\ntemp (readwrite): ${TEMP_DIR}`);
  console.log(`interpreter     : ${NODE}\n`);

  assertMxcSupported();

  const fixture = await createFixture();
  const scenarios = buildScenarios(fixture);

  let failures = 0;
  for (const scenario of scenarios) {
    process.stdout.write(`\n--- ${scenario.name}: ${scenario.what}\n`);
    try {
      const { ok, detail } = await scenario.run();
      if (!ok) failures += 1;
      console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${detail.replace(/\n/g, '\n  ')}`);
    } catch (error) {
      failures += 1;
      console.log(`  FAIL  threw: ${(error as Error).message}`);
    }
  }

  await fs.rm(fixture.dir, { recursive: true, force: true });

  console.log(
    `\n=== ${scenarios.length - failures}/${scenarios.length} scenarios behaved as expected ===`,
  );
  process.exitCode = failures === 0 ? 0 : 1;
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
