/**
 * Real A/B measurement: serial foreground wait vs. concurrent background jobs.
 *
 * The guard refuses foreground sleeps >=20s, so every delay here is 2s. That
 * keeps the measurement runnable and does not change the ratio being measured:
 * the question is whether N waits overlap or queue up.
 *
 * Also measures the guard's own per-call cost.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { findBlocking } from '../index.js';

const SLEEP_MS = 2000;
const PARALLEL = 3;
const ROUNDS = 3;

/**
 * A shell that can run `sleep`. Windows has no `sleep` in cmd.exe, so prefer the
 * Git Bash that ships with Git for Windows; POSIX just uses /bin/sh.
 * DSH_SLEEP_GUARD_SHELL overrides the probe when neither is right.
 */
function findShell() {
    const override = process.env.DSH_SLEEP_GUARD_SHELL;
    if (override) return override;
    if (process.platform !== 'win32') return '/bin/sh';
    const candidates = [
        'C:/Program Files/Git/bin/bash.exe',
        'C:/Program Files (x86)/Git/bin/bash.exe',
        process.env.LOCALAPPDATA && `${process.env.LOCALAPPDATA}/Programs/Git/bin/bash.exe`,
    ].filter(Boolean);
    return candidates.find(path => existsSync(path)) ?? 'bash';
}

const bash = findShell();

/** Run one `sleep 2` and resolve when it exits. */
function sleepOnce() {
    return new Promise((resolve, reject) => {
        const child = spawn(bash, ['-c', `sleep ${SLEEP_MS / 1000}`], { stdio: 'ignore' });
        child.on('error', reject);
        child.on('exit', () => resolve());
    });
}

/** A: three waits, one after another. */
async function runSerial() {
    const start = performance.now();
    for (let i = 0; i < PARALLEL; i += 1) await sleepOnce();
    return performance.now() - start;
}

/** B: three waits, started together. */
async function runParallel() {
    const start = performance.now();
    await Promise.all(Array.from({ length: PARALLEL }, () => sleepOnce()));
    return performance.now() - start;
}

const median = values => {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
};

const serial = [];
const parallel = [];
for (let round = 1; round <= ROUNDS; round += 1) {
    const a = await runSerial();
    const b = await runParallel();
    serial.push(a);
    parallel.push(b);
    console.log(`round ${round}: serial ${a.toFixed(0)}ms  parallel ${b.toFixed(0)}ms  ratio ${(a / b).toFixed(2)}x`);
}

const serialMedian = median(serial);
const parallelMedian = median(parallel);
const ratio = serialMedian / parallelMedian;

console.log('');
console.log(`serial   median ${serialMedian.toFixed(0)}ms`);
console.log(`parallel median ${parallelMedian.toFixed(0)}ms`);
console.log(`speedup  ${ratio.toFixed(2)}x  (${PARALLEL} waits of ${SLEEP_MS}ms)`);

// --- guard's own cost ---
const SAMPLE = 20000;
const commands = [
    'ls -la',
    'git status',
    'sleep 5',
    'npm run build',
    'tail -n 20 app.log',
    'docker ps',
    'echo hi',
    'curl -s https://example.com',
];
const started = performance.now();
let hits = 0;
for (let i = 0; i < SAMPLE; i += 1) {
    if (findBlocking(commands[i % commands.length]) !== null) hits += 1;
}
const elapsed = performance.now() - started;
console.log('');
console.log(`guard cost: ${SAMPLE} calls in ${elapsed.toFixed(1)}ms = ${((elapsed / SAMPLE) * 1000).toFixed(2)}us per call (${hits} blocked)`);

// --- extrapolation ---
const HISTORICAL_DECLARED_SECONDS = 4763;
const HISTORICAL_WALL_SECONDS = 5388;
console.log('');
console.log('extrapolation (measured ratio applied to the historical sample):');
console.log(`  historical declared sleep : ${HISTORICAL_DECLARED_SECONDS}s`);
console.log(`  historical measured wall  : ${HISTORICAL_WALL_SECONDS}s`);
console.log(`  at ${ratio.toFixed(2)}x speedup, wall becomes ~${(HISTORICAL_WALL_SECONDS / ratio).toFixed(0)}s`);
console.log(`  reclaimable (upper bound): ~${((HISTORICAL_WALL_SECONDS - HISTORICAL_WALL_SECONDS / ratio) / 60).toFixed(1)}min`);
