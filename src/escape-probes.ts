/**
 * Adversarial probes — the scenarios in `index.ts` only prove that *cooperative*
 * code is confined to its policy. These probes actively try to get out.
 *
 * A FAIL here is not necessarily an MXC bug: upstream states plainly that MXC
 * profiles are not security boundaries yet. The point is to record, concretely,
 * which parts of the threat model hold today.
 *
 * Run with: pnpm probes
 */
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getTemporaryFilesPolicy } from '@microsoft/mxc-sdk';
import { assertMxcSupported, describePlatformSupport, runInSandbox } from './mxc-utils.js';

const NODE = process.execPath;
const TEMP_DIR = getTemporaryFilesPolicy().readwritePaths[0] ?? os.tmpdir();
const SECRET = 'TOP-SECRET-CANARY';

type Verdict = 'contained' | 'ESCAPED' | 'inconclusive';

interface Probe {
  name: string;
  threat: string;
  run: () => Promise<{ verdict: Verdict; detail: string }>;
}

async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

const probes: Probe[] = [
  {
    name: 'symlink-read-escape',
    threat: 'plant a symlink in a writable dir that points at a secret outside the policy',
    run: async () => {
      const secretDir = await fs.mkdtemp(fileURLToPath(new URL('../.secret-', import.meta.url)));
      const secretFile = path.join(secretDir, 'canary.txt');
      await fs.writeFile(secretFile, SECRET);
      const link = path.join(TEMP_DIR, `mxc-escape-link-${process.pid}`);
      await fs.rm(link, { force: true });
      await fs.symlink(secretFile, link);
      try {
        const r = await runInSandbox({
          commandLine: `${NODE} -e "process.stdout.write(require('fs').readFileSync('${link}','utf8'))"`,
        });
        const leaked = r.stdout.includes(SECRET);
        return {
          verdict: leaked ? 'ESCAPED' : 'contained',
          detail: leaked
            ? 'read the secret through a symlink out of a granted rw path'
            : `blocked (exit=${r.exitCode})`,
        };
      } finally {
        await fs.rm(link, { force: true });
        await fs.rm(secretDir, { recursive: true, force: true });
      }
    },
  },
  {
    name: 'symlink-write-escape',
    threat: 'write through a symlink that leaves the sandbox',
    run: async () => {
      const outDir = await fs.mkdtemp(fileURLToPath(new URL('../.target-', import.meta.url)));
      const target = path.join(outDir, 'written.txt');
      const link = path.join(TEMP_DIR, `mxc-escape-wlink-${process.pid}`);
      await fs.rm(link, { force: true });
      await fs.symlink(target, link);
      try {
        const r = await runInSandbox({
          commandLine: `${NODE} -e "require('fs').writeFileSync('${link}','pwned');console.log('wrote')"`,
        });
        const leaked = await exists(target);
        return {
          verdict: leaked ? 'ESCAPED' : 'contained',
          detail: leaked ? `created ${target} outside the policy` : `blocked (exit=${r.exitCode})`,
        };
      } finally {
        await fs.rm(link, { force: true });
        await fs.rm(outDir, { recursive: true, force: true });
      }
    },
  },
  {
    name: 'env-leak',
    threat: 'inherit host environment variables (tokens, API keys)',
    run: async () => {
      process.env.MXC_CANARY = SECRET;
      const r = await runInSandbox({
        commandLine: `${NODE} -e "console.log(JSON.stringify(process.env))"`,
      });
      delete process.env.MXC_CANARY;
      const leaked = r.stdout.includes(SECRET);
      return {
        verdict: leaked ? 'ESCAPED' : 'contained',
        detail: leaked ? 'host env var visible inside sandbox' : 'host env not inherited',
      };
    },
  },
  {
    name: 'loopback-egress',
    threat: 'reach a service on the host loopback while allowOutbound is false',
    run: async () => {
      const server = http.createServer((_req, res) => res.end(SECRET));
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const port = (server.address() as { port: number }).port;
      try {
        const script = `fetch('http://127.0.0.1:${port}/',{signal:AbortSignal.timeout(5000)}).then(r=>r.text()).then(t=>console.log(t)).catch(e=>{console.error('blocked:',e.message);process.exit(7)})`;
        const r = await runInSandbox({ commandLine: `${NODE} -e "${script}"` });
        const leaked = r.stdout.includes(SECRET);
        return {
          verdict: leaked ? 'ESCAPED' : 'contained',
          detail: leaked
            ? `reached host service on 127.0.0.1:${port} despite allowOutbound:false`
            : `blocked (exit=${r.exitCode})`,
        };
      } finally {
        server.close();
      }
    },
  },
  {
    name: 'signal-host-process',
    threat: 'signal or inspect a process outside the sandbox',
    run: async () => {
      const r = await runInSandbox({
        commandLine: `${NODE} -e "try{process.kill(${process.pid},0);console.log('VISIBLE')}catch(e){console.log('hidden:'+e.code)}"`,
      });
      const visible = r.stdout.includes('VISIBLE');
      return {
        verdict: visible ? 'ESCAPED' : 'contained',
        detail: visible
          ? `could signal the launching process (pid ${process.pid})`
          : r.stdout.trim() || `exit=${r.exitCode}`,
      };
    },
  },
  {
    name: 'timeout-enforced',
    threat: 'ignore timeoutMs and run forever (resource exhaustion)',
    run: async () => {
      const started = Date.now();
      const r = await runInSandbox({
        commandLine: `${NODE} -e "setTimeout(()=>console.log('STILL ALIVE'),60000)"`,
        timeoutMs: 5_000,
      });
      const elapsed = Date.now() - started;
      const overran = elapsed > 20_000;
      return {
        verdict: overran ? 'ESCAPED' : 'contained',
        detail: `exit=${r.exitCode} after ${(elapsed / 1000).toFixed(1)}s (timeoutMs=5)`,
      };
    },
  },
  {
    name: 'home-dir-read',
    threat: 'read arbitrary files in $HOME that the policy never granted',
    run: async () => {
      const canary = path.join(os.homedir(), '.mxc-canary-probe');
      await fs.writeFile(canary, SECRET);
      try {
        const r = await runInSandbox({
          commandLine: `${NODE} -e "try{process.stdout.write(require('fs').readFileSync('${canary}','utf8'))}catch(e){console.log('denied:'+e.code)}"`,
        });
        const leaked = r.stdout.includes(SECRET);
        return {
          verdict: leaked ? 'ESCAPED' : 'contained',
          detail: leaked ? `read ${canary}` : r.stdout.trim() || `exit=${r.exitCode}`,
        };
      } finally {
        await fs.rm(canary, { force: true });
      }
    },
  },
];

async function main(): Promise<void> {
  console.log('=== MXC adversarial probes ===');
  console.log(describePlatformSupport());
  console.log(
    '\nNOTE: upstream states MXC profiles are not security boundaries yet.\n' +
      'ESCAPED below documents reality, it is not a vulnerability report.\n',
  );

  assertMxcSupported();

  let escaped = 0;
  for (const probe of probes) {
    process.stdout.write(`\n--- ${probe.name}: ${probe.threat}\n`);
    try {
      const { verdict, detail } = await probe.run();
      if (verdict === 'ESCAPED') escaped += 1;
      console.log(`  ${verdict.toUpperCase()}  ${detail}`);
    } catch (error) {
      console.log(`  INCONCLUSIVE  threw: ${(error as Error).message}`);
    }
  }

  console.log(`\n=== ${probes.length - escaped}/${probes.length} probes contained ===`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
