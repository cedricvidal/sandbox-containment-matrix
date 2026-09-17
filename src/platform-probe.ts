/**
 * Prints what MXC can do on this host: supported backends, discovered host
 * tool paths, and the temp directory used for read-write access.
 *
 * Run with: pnpm probe
 */
import { getAvailableToolsPolicy, getTemporaryFilesPolicy } from '@microsoft/mxc-sdk';
import { describePlatformSupport } from './mxc-utils.js';

console.log('=== MXC platform support ===');
console.log(describePlatformSupport());

const tools = getAvailableToolsPolicy(process.env);
const temp = getTemporaryFilesPolicy();

console.log('\n=== Discovered read-only tool paths ===');
for (const path of tools.readonlyPaths) console.log(`  ${path}`);

console.log('\n=== Discovered read-write temp paths ===');
for (const path of temp.readwritePaths) console.log(`  ${path}`);
