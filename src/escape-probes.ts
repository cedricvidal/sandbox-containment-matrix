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
import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createConfigFromPolicy,
  getAvailableToolsPolicy,
  getTemporaryFilesPolicy,
  spawnSandboxFromConfig,
} from '@microsoft/mxc-sdk';
import { assertMxcSupported, describePlatformSupport, runInSandbox } from './mxc-utils.js';

const NODE = process.execPath;
const TEMP_DIR = getTemporaryFilesPolicy().readwritePaths[0] ?? os.tmpdir();
const SECRET = 'TOP-SECRET-CANARY';

type Verdict = 'contained' | 'ESCAPED' | 'unsupported' | 'inconclusive';

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
  {
    name: 'network-allowlist',
    threat: 'block the internet except one site, then reach a different site anyway',
    run: async () => {
      // Rules must be IP literals or CIDRs — MXC rejects DNS names rather than
      // resolving them, because the sandbox resolves names itself and could be
      // handed an address the rules never authorised. So resolve here, and have
      // the sandbox connect by IP over plain HTTP: no DNS dependency inside the
      // sandbox, and no TLS certificate mismatch from an IP-literal URL.
      const [allowedIp] = await dns.resolve4('example.com');
      const [blockedIp] = await dns.resolve4('www.iana.org');
      if (!allowedIp || !blockedIp || allowedIp === blockedIp) {
        return { verdict: 'inconclusive', detail: 'could not resolve two distinct test IPs' };
      }

      const reach = (ip: string, hostHeader: string) => {
        const script =
          `fetch('http://${ip}/',{headers:{host:'${hostHeader}'},signal:AbortSignal.timeout(8000)})` +
          `.then(r=>console.log('HTTP',r.status)).catch(e=>{console.error('blocked:',e.message);process.exit(7)})`;
        return `${NODE} -e "${script}"`;
      };

      const buildAllowlistConfig = (commandLine: string) => {
        const tools = getAvailableToolsPolicy(process.env);
        const temp = getTemporaryFilesPolicy();
        // Schema 0.8 directional networking: default-deny egress with a single
        // allow rule. Legacy allowOutbound must not be mixed with this shape.
        const config = createConfigFromPolicy(
          {
            version: '0.8.0-alpha',
            filesystem: {
              readonlyPaths: tools.readonlyPaths,
              readwritePaths: temp.readwritePaths,
            },
            network: {
              egress: {
                default: 'deny',
                allow: [
                  {
                    to: [{ cidr: `${allowedIp}/32` }],
                    ports: [{ protocol: 'tcp', port: 80 }],
                  },
                ],
              },
              ingress: { default: 'deny', hostLoopback: 'deny' },
            },
            timeoutMs: 20_000,
          },
          'process',
        );
        config.process!.commandLine = commandLine;
        return config;
      };

      const run = (commandLine: string) =>
        new Promise<{ stdout: string; stderr: string; exitCode: number | null }>(
          (resolve, reject) => {
            let child;
            try {
              child = spawnSandboxFromConfig(buildAllowlistConfig(commandLine), { usePty: false });
            } catch (error) {
              reject(error);
              return;
            }
            let stdout = '';
            let stderr = '';
            child.stdout?.on('data', (c: Buffer) => (stdout += c.toString()));
            child.stderr?.on('data', (c: Buffer) => (stderr += c.toString()));
            child.on('error', reject);
            child.on('close', (exitCode: number | null) => resolve({ stdout, stderr, exitCode }));
          },
        );

      let allowed;
      try {
        allowed = await run(reach(allowedIp, 'example.com'));
      } catch (error) {
        // Seatbelt declares no EGRESS_RULES capability and rejects the policy
        // outright rather than silently ignoring it — the honest failure mode.
        return {
          verdict: 'unsupported',
          detail: `backend rejected per-CIDR egress rules: ${(error as Error).message.split('\n')[0]}`,
        };
      }

      const rejected = /not supported|unsupported|rejected|EGRESS_RULES|capability/i.test(
        allowed.stderr,
      );
      if (rejected && allowed.exitCode !== 0) {
        return {
          verdict: 'unsupported',
          detail: `backend rejected per-CIDR egress rules: ${allowed.stderr.trim().split('\n')[0]}`,
        };
      }

      const blocked = await run(reach(blockedIp, 'www.iana.org'));
      const reachedAllowed = allowed.stdout.includes('HTTP');
      const reachedBlocked = blocked.stdout.includes('HTTP');

      if (reachedBlocked) {
        return {
          verdict: 'ESCAPED',
          detail: `reached ${blockedIp} despite an allowlist naming only ${allowedIp}`,
        };
      }
      if (!reachedAllowed) {
        return {
          verdict: 'inconclusive',
          detail:
            `the allowlisted host ${allowedIp} was also unreachable ` +
            `(exit=${allowed.exitCode}) — default-deny may simply block everything`,
        };
      }
      return {
        verdict: 'contained',
        detail: `allowlisted ${allowedIp} reachable, ${blockedIp} blocked (exit=${blocked.exitCode})`,
      };
    },
  },
  {
    name: 'resource-limits',
    threat: 'exhaust CPU and memory — MXC expresses no cgroup-style limits',
    run: async () => {
      // 512 MB is enough to trip a typical container cap without threatening a
      // developer machine; 1s of spin is enough to measure parallelism.
      const MB = 512;
      const SPIN_MS = 1000;

      // Written to a file rather than passed via `node -e`: commandLine is run
      // through `sh -c`, so an inline script full of quotes and parentheses
      // gets mangled by the shell.
      const scriptPath = path.join(TEMP_DIR, `mxc-resource-probe-${process.pid}.cjs`);
      const script = `
const os = require('os');
const { Worker } = require('worker_threads');

let mem = 'none';
try {
  const b = Buffer.alloc(${MB} * 1024 * 1024);
  // Touch every page. A large Buffer.alloc only reserves lazily-mapped zero
  // pages; until each page is written nothing is charged to the cgroup, so an
  // untouched allocation sails past a memory limit that would otherwise kill.
  for (let i = 0; i < b.length; i += 4096) b[i] = 1;
  mem = 'committed';
} catch (e) { mem = 'denied:' + e.code; }

// One spinner per visible core: a genuine saturation attempt, and the demand
// figure the achieved parallelism is measured against. A fixed worker count
// would silently cap the demand and make any limit above it undetectable.
const demand = os.cpus().length;
const t0 = Date.now();
const c0 = process.cpuUsage();
const src = 'const e = Date.now() + ${SPIN_MS}; while (Date.now() < e) { Math.sqrt(Math.random()); }';
const ws = Array.from({ length: demand }, () => new Worker(src, { eval: true }));
Promise.all(ws.map((w) => new Promise((r) => w.on('exit', r)))).then(() => {
  const wall = Date.now() - t0;
  const c = process.cpuUsage(c0);
  const cpuMs = Math.round((c.user + c.system) / 1000);
  console.log(JSON.stringify({
    mem, demand, wall, cpuMs,
    achieved: +(cpuMs / wall).toFixed(2),
  }));
});
`;
      await fs.writeFile(scriptPath, script);
      try {
        const r = await runInSandbox({
          commandLine: `${NODE} ${scriptPath}`,
          timeoutMs: 60_000,
        });

        const failure = r.stderr.match(/^\s*(bwrap|lxc-exec|mxc-exec[\w-]*):\s*(.+)$/m);
        if (failure) {
          return { verdict: 'inconclusive', detail: `sandbox did not start: ${failure[0].trim()}` };
        }

        // A memory cap kills the process outright before it can report.
        if (r.exitCode === 137 || /\bKilled\b|out of memory/i.test(r.stderr)) {
          return {
            verdict: 'contained',
            detail:
              'memory: OOM-killed (exit=137) by an out-of-band cap. ' +
              'Enforced by the container cgroup, not by any MXC policy field',
          };
        }

        let d: { mem: string; demand: number; wall: number; cpuMs: number; achieved: number };
        try {
          d = JSON.parse(r.stdout.trim().split('\n').pop() ?? '');
        } catch {
          return {
            verdict: 'inconclusive',
            detail: `could not parse output (exit=${r.exitCode}): ${r.stderr.trim().slice(0, 140)}`,
          };
        }

        // Report the two resources separately: they are enforced by different
        // controls and can differ. Collapsing them into one boolean produced a
        // "no cap" verdict on a host where CPU was in fact capped at 0.5.
        const memCapped = d.mem !== 'committed';
        // Achieved parallelism is compared against *demand*, not a fixed
        // threshold: demand is one spinner per visible core, so falling
        // meaningfully short is the signature of a cgroup quota.
        const cpuCapped = d.achieved < d.demand * 0.8;

        const memNote = memCapped
          ? `memory: ${d.mem}`
          : `memory: ${MB}MB committed, uncapped`;
        const cpuNote = cpuCapped
          ? `cpu: throttled to ~${d.achieved} of ${d.demand} cores demanded`
          : `cpu: ${d.achieved}/${d.demand} cores, uncapped`;
        const detail = `${memNote}; ${cpuNote}`;

        if (memCapped || cpuCapped) {
          return {
            verdict: 'contained',
            detail: `${detail} — enforced by the container cgroup, not by MXC`,
          };
        }
        return {
          verdict: 'ESCAPED',
          detail: `${detail}. MXC has no CPU/memory field — cap it with cgroups`,
        };
      } finally {
        await fs.rm(scriptPath, { force: true });
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
  let unsupported = 0;
  for (const probe of probes) {
    process.stdout.write(`\n--- ${probe.name}: ${probe.threat}\n`);
    try {
      const { verdict, detail } = await probe.run();
      if (verdict === 'ESCAPED') escaped += 1;
      if (verdict === 'unsupported') unsupported += 1;
      console.log(`  ${verdict.toUpperCase()}  ${detail}`);
    } catch (error) {
      console.log(`  INCONCLUSIVE  threw: ${(error as Error).message}`);
    }
  }

  // An unsupported control is not a contained one — it means the policy you
  // asked for cannot be expressed on this backend at all.
  const enforced = probes.length - escaped - unsupported;
  console.log(
    `\n=== ${enforced}/${probes.length} probes contained, ` +
      `${escaped} escaped, ${unsupported} unsupported by this backend ===`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
