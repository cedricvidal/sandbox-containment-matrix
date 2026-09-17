/**
 * The MXC README sample, minimally adapted so it actually runs:
 *
 *  - schema `0.7.0-alpha` instead of `0.6.0-alpha` — the macOS Seatbelt
 *    backend rejects anything below 0.7.0-alpha.
 *  - an absolute interpreter path instead of a bare `python` — the SDK never
 *    copies `process.env` into the sandbox, so a bare command name resolves
 *    against the backend's default PATH, not your shell's.
 *
 * Run with: pnpm hello
 */
import {
  createConfigFromPolicy,
  getAvailableToolsPolicy,
  getPlatformSupport,
  getTemporaryFilesPolicy,
  spawnSandboxFromConfig,
} from '@microsoft/mxc-sdk';

if (!getPlatformSupport().isSupported) {
  throw new Error('MXC not available on this host');
}

const tools = getAvailableToolsPolicy(process.env);
const temp = getTemporaryFilesPolicy();

const config = createConfigFromPolicy({
  version: '0.7.0-alpha',
  filesystem: {
    readonlyPaths: tools.readonlyPaths,
    readwritePaths: temp.readwritePaths,
  },
  network: { allowOutbound: false },
  timeoutMs: 30_000,
});

// `process.execPath` is the Node binary already running this script, so it is
// guaranteed to exist and to sit under one of the discovered readonlyPaths.
config.process!.commandLine = `${process.execPath} -e "console.log('hello from sandbox')"`;

const child = spawnSandboxFromConfig(config, { usePty: false });
child.stdout!.on('data', (d) => process.stdout.write(d));
child.stderr!.on('data', (d) => process.stderr.write(d));
child.on('close', (code) => console.log('exit:', code));
