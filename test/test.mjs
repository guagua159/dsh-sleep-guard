/**
 * Test suite for dsh-sleep-guard.
 *
 * Runs entirely in-process: no real delay is ever executed, because the guard
 * would refuse its own test command. Detector cases call findBlocking(); handler
 * cases call apply() with a stub `next`.
 *
 * Exit code: 0 = all pass, 1 = at least one failure.
 */

import { findBlocking, apply, name } from '../index.js';

/** Detector cases: category, command line, expected verdict. */
const DETECT = [
    // --- sleep, POSIX threshold and units ---
    ['sleep', 'sleep 19', 'ALLOW'],
    ['sleep', 'sleep 20', 'BLOCK'],
    ['sleep', 'sleep 19.9', 'ALLOW'],
    ['sleep', 'sleep 0.5', 'ALLOW'],
    ['sleep', 'sleep 60', 'BLOCK'],
    ['sleep', 'sleep 300', 'BLOCK'],
    ['sleep', 'sleep 20s', 'BLOCK'],
    ['sleep', 'sleep 2m', 'BLOCK'],
    ['sleep', 'sleep 1h', 'BLOCK'],
    ['sleep', 'sleep 1d', 'BLOCK'],
    ['sleep', 'sleep 3600', 'BLOCK'],
    ['sleep', 'sleep 99999', 'BLOCK'],
    ['sleep', 'sleep abc', 'ALLOW'],
    ['sleep', 'sleep', 'ALLOW'],
    ['sleep', 'sleep.exe 300', 'BLOCK'],

    // --- absolute and relative paths must resolve to the same command ---
    ['path', '/usr/bin/sleep 300', 'BLOCK'],
    ['path', '/bin/sleep 300', 'BLOCK'],
    ['path', './sleep 300', 'BLOCK'],
    ['path', '../bin/sleep 300', 'BLOCK'],
    ['path', 'C:/Windows/System32/PING.EXE example.com', 'BLOCK'],
    ['path', '/usr/bin/tail -f app.log', 'BLOCK'],
    ['path', '/usr/bin/tail -n 20 app.log', 'ALLOW'],
    ['path', '/usr/bin/sleep 5', 'ALLOW'],

    // --- segmentation and wrappers ---
    ['structure', 'ls; sleep 60', 'BLOCK'],
    ['structure', 'ls && sleep 60', 'BLOCK'],
    ['structure', 'ls || sleep 60', 'BLOCK'],
    ['structure', 'sleep 60 | cat', 'BLOCK'],
    ['structure', 'sudo sleep 300', 'BLOCK'],
    ['structure', 'FOO=1 sleep 300', 'BLOCK'],
    ['structure', 'env A=b sleep 300', 'BLOCK'],
    ['structure', 'nohup sleep 300', 'BLOCK'],
    ['structure', 'time sleep 300', 'BLOCK'],
    ['structure', 'ls\ntail -f x.log', 'BLOCK'],

    // --- tail ---
    ['tail', 'tail -f app.log', 'BLOCK'],
    ['tail', 'tail -F app.log', 'BLOCK'],
    ['tail', 'tail --follow app.log', 'BLOCK'],
    ['tail', 'tail --follow=name app.log', 'BLOCK'],
    ['tail', 'tail -n 20 app.log', 'ALLOW'],
    ['tail', 'tail -100 app.log', 'ALLOW'],
    ['tail', 'tail app.log', 'ALLOW'],

    // --- watch ---
    ['watch', 'watch -n 1 date', 'BLOCK'],
    ['watch', 'watch date', 'BLOCK'],

    // --- ping ---
    // Windows: -n count, -w timeout(ms), -t infinite, -a resolve, -l size.
    // MSYS/Linux: -c count, -w deadline(s), -W timeout(s).
    ['ping', 'ping example.com', 'BLOCK'],
    ['ping', 'ping -t example.com', 'BLOCK'],
    ['ping', 'ping -c 4 example.com', 'ALLOW'],
    ['ping', 'ping -c4 example.com', 'ALLOW'],
    ['ping', 'ping -n 4 example.com', 'ALLOW'],
    ['ping', 'ping -n4 example.com', 'ALLOW'],
    // -w is a per-reply timeout, never a count: the ping still never ends.
    ['ping', 'ping -w 1000 example.com', 'BLOCK'],
    ['ping', 'ping -l 64 example.com', 'BLOCK'],
    ['ping', 'ping -a example.com', 'BLOCK'],
    ['ping', 'ping -n 4 -w 1000 example.com', 'ALLOW'],

    // --- follow-mode log readers ---
    ['logs', 'journalctl -f', 'BLOCK'],
    ['logs', 'journalctl --follow', 'BLOCK'],
    ['logs', 'journalctl -n 100', 'ALLOW'],
    ['logs', 'docker logs -f web', 'BLOCK'],
    ['logs', 'docker logs --follow web', 'BLOCK'],
    ['logs', 'docker logs web', 'ALLOW'],
    ['logs', 'docker compose logs -f', 'BLOCK'],
    ['logs', 'docker compose logs --follow web', 'BLOCK'],
    ['logs', 'docker compose logs', 'ALLOW'],
    ['logs', 'docker-compose logs -f', 'BLOCK'],
    ['logs', 'kubectl logs -f pod/web', 'BLOCK'],
    ['logs', 'kubectl logs --follow pod/web', 'BLOCK'],
    ['logs', 'kubectl logs pod/web', 'ALLOW'],
    ['logs', 'kubectl -n prod logs -f pod/web', 'BLOCK'],

    // --- dev servers ---
    ['server', 'npm start', 'BLOCK'],
    ['server', 'npm run dev', 'BLOCK'],
    ['server', 'npm run serve', 'BLOCK'],
    ['server', 'npm run watch', 'BLOCK'],
    ['server', 'pnpm run dev', 'BLOCK'],
    ['server', 'yarn start', 'BLOCK'],
    ['server', 'npm test', 'ALLOW'],
    ['server', 'npm run build', 'ALLOW'],
    ['server', 'npm install', 'ALLOW'],
    ['server', 'npm ci', 'ALLOW'],
    ['server', 'vite', 'BLOCK'],
    ['server', 'nodemon app.js', 'BLOCK'],
    ['server', 'webpack serve', 'BLOCK'],
    ['server', 'webpack --mode production', 'ALLOW'],

    // --- PowerShell ---
    ['powershell', 'Start-Sleep -Seconds 60', 'BLOCK'],
    ['powershell', 'Start-Sleep -Seconds 19', 'ALLOW'],
    ['powershell', 'Start-Sleep -Milliseconds 30000', 'BLOCK'],
    ['powershell', 'Start-Sleep -Milliseconds 5000', 'ALLOW'],

    // --- quoting must not create false positives ---
    ['quoting', 'echo "sleep 240"', 'ALLOW'],
    ['quoting', "echo 'tail -f x'", 'ALLOW'],
    ['quoting', 'git commit -m "sleep 300 fix"', 'ALLOW'],
    ['quoting', 'grep "npm start" package.json', 'ALLOW'],

    // --- unrelated commands ---
    ['other', 'echo hi', 'ALLOW'],
    ['other', 'ls -la', 'ALLOW'],
    ['other', 'git status', 'ALLOW'],
    ['other', 'curl -s https://example.com', 'ALLOW'],
    ['other', 'cat app.log', 'ALLOW'],
    ['other', 'docker build -f Dockerfile .', 'ALLOW'],
    ['other', 'docker ps', 'ALLOW'],
    ['other', 'docker compose up -d', 'ALLOW'],
    ['other', 'kubectl get pods', 'ALLOW'],
    ['other', '', 'ALLOW'],
    ['other', null, 'ALLOW'],
];

/** Handler cases: the full apply() pipeline, including exemptions. */
const HANDLER = [
    ['deny', { name: 'pwsh', arguments: { command: 'sleep 240' } }, 'DENY'],
    ['deny', { name: 'pwsh', arguments: { command: 'tail -f x' } }, 'DENY'],
    ['deny', { name: 'bash', arguments: { command: 'npm run dev' } }, 'DENY'],
    ['deny', { name: 'pwsh', arguments: { command: 'Start-Sleep -Seconds 30' } }, 'DENY'],
    ['deny', { name: 'shell', arguments: { command: 'watch date' } }, 'DENY'],
    ['deny', { name: 'pwsh', arguments: { command: '/usr/bin/sleep 300' } }, 'DENY'],
    ['deny', { name: 'pwsh_persistent', arguments: { command: 'sleep 240' } }, 'DENY'],
    // `ops_bash` ships with the separate dsh-ops package; the name stays in
    // SHELL_TOOLS so profiles that install it keep working. It never matches
    // when that package is absent, which is why no live tool uses it here.
    ['deny', { name: 'ops_bash', arguments: { command: 'sleep 240' } }, 'DENY'],
    ['exempt', { name: 'pwsh', arguments: { command: 'sleep 240', run_in_background: true } }, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: { command: 'tail -f x', run_in_background: true } }, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: { command: 'sleep 240', script_path: 'a.sh' } }, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: { command: 'sleep 240', script_path: '' } }, 'DENY'],
    ['exempt', { name: 'read', arguments: { path: 'x' } }, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: {} }, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: null }, 'ALLOW'],
    ['exempt', { name: 'pwsh' }, 'ALLOW'],
    ['exempt', {}, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: { command: 'sleep 5' } }, 'ALLOW'],
    ['exempt', { name: 'pwsh', arguments: { command: 'ls -la' } }, 'ALLOW'],
];

/** Legal commands that must never be refused (false-positive watch list). */
const FALSE_POSITIVE = [
    'ls -la',
    'git status',
    'git commit -m "fix: sleep timeout handling"',
    'tail -n 50 app.log',
    // `tail -f --pid=N` terminates only when that process dies, which may be never
    // or an hour from now; refusing it is deliberate, so it is not listed here.
    'ping -c 3 localhost',
    'ping -n 4 localhost',
    'npm ci',
    'npm run build',
    'npm test',
    'docker build -f Dockerfile .',
    'docker compose up -d',
    'docker compose logs',
    'kubectl logs pod/web',
    'kubectl get pods',
    'curl -s https://api.example.com/health',
    'cat /var/log/app.log',
    'grep -r "watch" src/',
    'echo "Start-Sleep -Seconds 60"',
    'webpack --mode production',
    'journalctl -n 200',
    'docker logs web',
    'sleep 5',
    'sleep 19',
];

function mountHandler() {
    const handlers = [];
    apply({ on: (_event, fn) => { handlers.push(fn); } });
    if (handlers.length !== 1) throw new Error(`expected 1 handler, got ${handlers.length}`);
    return handlers[0];
}

const failures = [];
const stats = new Map();

function bump(category, passed) {
    const row = stats.get(category) ?? { total: 0, passed: 0 };
    row.total += 1;
    if (passed) row.passed += 1;
    stats.set(category, row);
}

for (const [category, command, expected] of DETECT) {
    let actual;
    let detail = '';
    try {
        const reason = findBlocking(command);
        actual = reason === null ? 'ALLOW' : 'BLOCK';
        detail = reason ?? '';
    } catch (error) {
        actual = 'THREW';
        detail = String(error?.message ?? error);
    }
    const passed = actual === expected;
    bump(category, passed);
    if (!passed) failures.push({ category, command, expected, actual, detail });
}

const handler = mountHandler();
for (const [category, exec, expected] of HANDLER) {
    let actual;
    let detail = '';
    try {
        const decision = await handler(exec, async () => ({ kind: 'accept' }));
        actual = decision?.kind === 'deny' ? 'DENY' : 'ALLOW';
        detail = decision?.reason ?? '';
    } catch (error) {
        actual = 'THREW';
        detail = String(error?.message ?? error);
    }
    const passed = actual === expected;
    bump(category, passed);
    if (!passed) failures.push({ category, command: JSON.stringify(exec), expected, actual, detail });
}

const falsePositives = [];
for (const command of FALSE_POSITIVE) {
    let reason = null;
    try {
        reason = findBlocking(command);
    } catch (error) {
        reason = `THREW: ${String(error?.message ?? error)}`;
    }
    if (reason !== null) falsePositives.push({ command, reason });
}

const rows = [...stats.entries()].sort((a, b) => a[0].localeCompare(b[0]));
let total = 0;
let passed = 0;
for (const [, row] of rows) {
    total += row.total;
    passed += row.passed;
}

console.log(`plugin: ${name}`);
console.log('');
console.log('category      total  passed  failed');
for (const [category, row] of rows) {
    console.log(`${category.padEnd(13)} ${String(row.total).padStart(5)}  ${String(row.passed).padStart(6)}  ${String(row.total - row.passed).padStart(6)}`);
}
console.log(`${'TOTAL'.padEnd(13)} ${String(total).padStart(5)}  ${String(passed).padStart(6)}  ${String(total - passed).padStart(6)}`);
console.log('');
console.log(`false-positive watch list: ${FALSE_POSITIVE.length} legal commands, ${falsePositives.length} wrongly refused`);

if (failures.length > 0) {
    console.log('');
    console.log('FAILURES:');
    for (const f of failures) {
        console.log(`  [${f.category}] ${f.command}`);
        console.log(`    expected=${f.expected} actual=${f.actual} ${f.detail}`);
    }
}
if (falsePositives.length > 0) {
    console.log('');
    console.log('FALSE POSITIVES:');
    for (const f of falsePositives) console.log(`  ${f.command}  ->  ${f.reason}`);
}

const ok = failures.length === 0 && falsePositives.length === 0;
console.log('');
console.log(ok ? 'RESULT: PASS' : 'RESULT: FAIL');
process.exit(ok ? 0 : 1);
