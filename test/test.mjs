/**
 * Test suite for dsh-sleep-guard.
 *
 * Runs entirely in-process: no real delay is ever executed, because the guard
 * would refuse its own test command. Detector cases call findBlocking(); guard
 * cases call apply() with a stub context whose `tools.guard` records the guard.
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
    ['sleep', 'sleep 1.5e3', 'BLOCK'],
    ['sleep', 'sleep 1e1', 'ALLOW'],
    ['sleep', 'sleep abc', 'ALLOW'],
    ['sleep', 'sleep', 'ALLOW'],
    ['sleep', 'sleep.exe 300', 'BLOCK'],
    ['sleep', 'sleep 300 2>&1', 'BLOCK'],

    // --- absolute and relative paths must resolve to the same command ---
    ['path', '/usr/bin/sleep 300', 'BLOCK'],
    ['path', '/bin/sleep 300', 'BLOCK'],
    ['path', './sleep 300', 'BLOCK'],
    ['path', '../bin/sleep 300', 'BLOCK'],
    ['path', 'C:/Windows/System32/PING.EXE example.com', 'BLOCK', 'linux'],
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
    // every line-break form separates commands, including a lone carriage return
    ['structure', 'ls\r\ntail -f x.log', 'BLOCK'],
    ['structure', 'ls\rtail -f x.log', 'BLOCK'],
    ['structure', 'ls\r', 'ALLOW'],
    // wrappers carry options of their own
    ['wrapper', 'sudo -u root sleep 300', 'BLOCK'],
    ['wrapper', 'sudo -E sleep 300', 'BLOCK'],
    ['wrapper', 'sudo -- sleep 300', 'BLOCK'],
    ['wrapper', 'sudo -u root -E sleep 300', 'BLOCK'],
    ['wrapper', 'time -p sleep 300', 'BLOCK'],
    ['wrapper', 'nice -n 10 sleep 300', 'BLOCK'],
    ['wrapper', 'stdbuf -oL sleep 300', 'BLOCK'],
    ['wrapper', 'env -i sleep 300', 'BLOCK'],
    ['wrapper', 'env -u HOME sleep 300', 'BLOCK'],
    ['wrapper', 'busybox sleep 300', 'BLOCK'],
    // `command -v sleep` only prints a path
    ['wrapper', 'command -v sleep', 'ALLOW'],
    ['wrapper', 'command -v tail', 'ALLOW'],
    // runners
    ['wrapper', 'npx vite', 'BLOCK'],
    ['wrapper', 'npx --yes vite', 'BLOCK'],
    ['wrapper', 'npx webpack serve', 'BLOCK'],
    ['wrapper', 'bunx nodemon app.js', 'BLOCK'],
    ['wrapper', 'pnpm dlx vite', 'BLOCK'],
    ['wrapper', 'yarn exec vite', 'BLOCK'],
    ['wrapper', 'npx tsc --noEmit', 'ALLOW'],
    ['wrapper', 'pnpm dlx serve dist', 'ALLOW'],
    // backgrounded work returns at once
    ['background', 'sleep 300 &', 'ALLOW'],
    ['background', 'sleep 300&', 'ALLOW'],
    ['background', 'npm start &', 'ALLOW'],
    ['background', 'nohup npm start > out.log 2>&1 &', 'ALLOW'],
    ['background', 'tail -f x & echo ok', 'ALLOW'],
    ['background', 'sleep 300 & sleep 300', 'BLOCK'],
    ['background', 'sleep 300 2>&1', 'BLOCK'],

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
    ['watch', 'watch --version', 'ALLOW'],
    ['watch', 'watch -h', 'ALLOW'],

    // --- ping ---
    // A bare `ping` is bounded on Windows (four echoes, ~3 s) but not on
    // MSYS/Linux, so the platform is passed explicitly to keep CI deterministic
    // on both runners.
    ['ping', 'ping example.com', 'BLOCK', 'linux'],
    ['ping', 'ping 127.0.0.1', 'BLOCK', 'linux'],
    ['ping', 'ping -t example.com', 'BLOCK', 'linux'],
    ['ping', 'ping -c 4 example.com', 'ALLOW', 'linux'],
    ['ping', 'ping -c4 example.com', 'ALLOW', 'linux'],
    ['ping', 'ping -n 4 example.com', 'ALLOW', 'linux'],
    ['ping', 'ping -n4 example.com', 'ALLOW', 'linux'],
    ['ping', 'ping --count 4 example.com', 'ALLOW', 'linux'],
    // -w is a per-reply timeout, never a count: the ping still never ends.
    ['ping', 'ping -w 1000 example.com', 'BLOCK', 'linux'],
    ['ping', 'ping -l 64 example.com', 'BLOCK', 'linux'],
    ['ping', 'ping -a example.com', 'BLOCK', 'linux'],
    ['ping', 'ping -n 4 -w 1000 example.com', 'ALLOW', 'linux'],
    // A bare -n with no number is Linux "numeric output", not a count.
    ['ping', 'ping -n example.com', 'BLOCK', 'linux'],
    ['ping', 'ping6 example.com', 'BLOCK', 'linux'],
    ['ping', 'ping6 -c 4 example.com', 'ALLOW', 'linux'],
    // Windows: only -t runs until interrupted; the rest returns on its own.
    ['ping', 'ping example.com', 'ALLOW', 'win32'],
    ['ping', 'ping 127.0.0.1', 'ALLOW', 'win32'],
    ['ping', 'ping -l 64 127.0.0.1', 'ALLOW', 'win32'],
    ['ping', 'ping -w 1000 127.0.0.1', 'ALLOW', 'win32'],
    ['ping', 'ping -n 4 127.0.0.1', 'ALLOW', 'win32'],
    ['ping', 'ping -t 127.0.0.1', 'BLOCK', 'win32'],
    // Help and version print and return on both: the one real false refusal
    // found in the historical command corpus.
    ['ping', 'ping -h', 'ALLOW', 'linux'],
    ['ping', 'ping -h', 'ALLOW', 'win32'],
    ['ping', 'ping --help', 'ALLOW', 'win32'],
    ['ping', 'ping -V', 'ALLOW', 'win32'],
    ['ping', 'ping --version', 'ALLOW', 'linux'],

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
    // compose global options shift the verb, but `logs` is still there
    ['logs', 'docker compose -f docker-compose.yml logs -f api', 'BLOCK'],
    ['logs', 'docker compose --file docker-compose.yml logs -f', 'BLOCK'],
    ['logs', 'docker compose -p myproj logs -f', 'BLOCK'],
    ['logs', 'docker compose -f docker-compose.yml logs', 'ALLOW'],
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
    ['server', 'pnpm dev', 'BLOCK'],
    ['server', 'yarn start', 'BLOCK'],
    ['server', 'yarn dev', 'BLOCK'],
    ['server', 'bun dev', 'BLOCK'],
    ['server', 'npm test', 'ALLOW'],
    ['server', 'npm run build', 'ALLOW'],
    ['server', 'npm install', 'ALLOW'],
    ['server', 'npm ci', 'ALLOW'],
    ['server', 'yarn --version', 'ALLOW'],
    ['server', 'vite', 'BLOCK'],
    ['server', 'vite preview', 'BLOCK'],
    ['server', 'vite --host', 'BLOCK'],
    ['server', 'vite build', 'ALLOW'],
    ['server', 'vite build --mode production', 'ALLOW'],
    ['server', 'vite optimize', 'ALLOW'],
    ['server', 'vite --version', 'ALLOW'],
    ['server', 'nodemon app.js', 'BLOCK'],
    ['server', 'nodemon --version', 'ALLOW'],
    ['server', 'nodemon --help', 'ALLOW'],
    ['server', 'webpack serve', 'BLOCK'],
    ['server', 'webpack --mode production', 'ALLOW'],

    // --- PowerShell ---
    ['powershell', 'Start-Sleep -Seconds 60', 'BLOCK'],
    ['powershell', 'Start-Sleep -Seconds 19', 'ALLOW'],
    ['powershell', 'Start-Sleep -Milliseconds 30000', 'BLOCK'],
    ['powershell', 'Start-Sleep -Milliseconds 5000', 'ALLOW'],
    ['powershell', 'Start-Sleep 30', 'BLOCK'],
    ['powershell', 'Start-Sleep 5', 'ALLOW'],
    ['powershell', 'Start-Sleep -s 30', 'BLOCK'],
    ['powershell', 'Start-Sleep -S 30', 'BLOCK'],
    ['powershell', 'Start-Sleep -sec 30', 'BLOCK'],
    ['powershell', 'Start-Sleep -m 30000', 'BLOCK'],
    ['powershell', 'Start-Sleep -m 5000', 'ALLOW'],
    ['powershell', 'Start-Sleep -Seconds:30', 'BLOCK'],
    ['powershell', 'Start-Sleep -Seconds $t', 'ALLOW'],
    ['powershell', 'Sleep 30', 'BLOCK'],
    ['powershell', 'ls; Start-Sleep -Seconds 30', 'BLOCK'],
    ['powershell', 'Write-Host hi; Start-Sleep -Seconds 30; Write-Host done', 'BLOCK'],
    ['powershell', 'Get-Process | Start-Sleep 30', 'BLOCK'],
    ['powershell', 'Start-Sleep -Seconds 30 -Verbose', 'BLOCK'],

    // --- PowerShell assignment prefixes ---
    // `$out = sleep 300` still runs sleep; splitting on whitespace left `$out` as the
    // command word, so the assignment hid the delay entirely.
    ['powershell', '$out = sleep 300', 'BLOCK'],
    ['powershell', '$out = sleep 300 2>&1 | Out-String', 'BLOCK'],
    ['powershell', '$out=sleep 300', 'BLOCK'],
    ['powershell', '$null = sleep 300', 'BLOCK'],
    ['powershell', '$a.b = sleep 300', 'BLOCK'],
    ['powershell', '$env:X = sleep 300', 'BLOCK'],
    ['powershell', '$script:x = sleep 300', 'BLOCK'],
    ['powershell', '$out=Start-Sleep -Seconds 30', 'BLOCK'],
    ['powershell', '$x = sleep 300; Write-Host hi', 'BLOCK'],
    ['powershell', '$a = $b = sleep 300', 'BLOCK'],
    ['powershell', '$log = tail -f app.log', 'BLOCK'],
    // Assigning a value, or reading a variable, runs nothing that blocks.
    ['powershell', '$out = 5', 'ALLOW'],
    ['powershell', '$x = "hello world"', 'ALLOW'],
    ['powershell', 'Write-Host $out', 'ALLOW'],
    ['powershell', '$out = git status', 'ALLOW'],
    ['powershell', '$out = 5 -eq 5', 'ALLOW'],
    ['powershell', '$out = $(Get-Date)', 'ALLOW'],
    ['powershell', '$t = 30; Start-Sleep -Seconds $t', 'ALLOW'],

    // --- quoting must not create false positives ---
    ['quoting', 'echo "sleep 240"', 'ALLOW'],
    ['quoting', "echo 'tail -f x'", 'ALLOW'],
    ['quoting', 'git commit -m "sleep 300 fix"', 'ALLOW'],
    ['quoting', 'grep "npm start" package.json', 'ALLOW'],

    // --- an unpaired apostrophe must not swallow the rest of the line ---
    ['quoting', "echo it's && sleep 300", 'BLOCK'],
    ['quoting', "git commit -m don't care; sleep 300", 'BLOCK'],
    ['quoting', "echo don't; sleep 300", 'BLOCK'],
    ['quoting', "echo it's fine", 'ALLOW'],
    ['quoting', 'echo "unterminated; sleep 300', 'BLOCK'],

    // --- heredoc bodies are file contents, not commands ---
    ['heredoc', "cat > run.sh <<'EOF'\nsleep 300\nEOF", 'ALLOW'],
    ['heredoc', 'cat > run.sh <<EOF\nnpm start\nEOF', 'ALLOW'],
    ['heredoc', "cat > run.sh <<'EOF'\nsleep 300\nEOF\nsleep 300", 'BLOCK'],
    ['heredoc', "cat > a.txt <<'A'\nx\nA\ncat > b.txt <<'B'\ny\nB", 'ALLOW'],
    // `<<` inside quotes is not an opener: the next line is still a command
    ['heredoc', 'echo "a << b"\nsleep 300', 'BLOCK'],
    // an unterminated heredoc swallows what follows, so nothing after it runs
    ['heredoc', 'echo hi << x\nsleep 300', 'ALLOW'],
    // a bit shift is not a heredoc opener: the next line still runs
    ['heredoc', 'x=$((1<<n))\nsleep 300', 'BLOCK'],
    ['heredoc', '(( x = 1<<3 ))\nsleep 300', 'BLOCK'],
    ['heredoc', 'echo $((1<<n)); sleep 300', 'BLOCK'],
    ['heredoc', 'y=$((2<<3))\ntail -f log', 'BLOCK'],
    ['heredoc', 'x=$((1<<3))', 'ALLOW'],

    // --- foreground polling loops ---
    // A loop hides its delay from the per-segment check: `segments()` splits at the
    // `;` inside `do … done`, so the loop is matched on the whole text first.
    ['loop', 'for i in $(seq 1 40); do sleep 30; done', 'BLOCK'],
    ['loop', 'for i in $(seq 1 20); do sleep 30; if ! tasklist //FI x; then break; fi; done', 'BLOCK'],
    ['loop', 'for i in $(seq 1 30); do D=$(ls -td logs/*gui* | head -1); sleep 10; done', 'BLOCK'],
    ['loop', 'while true; do sleep 30; done', 'BLOCK'],
    ['loop', 'until grep -q DONE log; do sleep 60; done', 'BLOCK'],
    // Iterations come from the word list, so quoted arguments must still count as words.
    ['loop', 'for m in "" "-M:8G" "-M:20G"; do echo $m; sleep 9; done', 'BLOCK'],
    // Total hold decides: 30 passes of 10 s is five minutes even though no single
    // sleep crosses the 20 s threshold; 2 passes of 5 s stays under it.
    ['loop', 'for i in $(seq 1 2); do sleep 5; done', 'ALLOW'],
    ['loop', 'for i in $(seq 1 4); do sleep 10; done', 'BLOCK'],
    // A loop with no sleep in its body ends when the glob or the stream does.
    ['loop', 'for f in *.txt; do wc -l "$f"; done', 'ALLOW'],
    ['loop', 'for i in $(seq 1 100); do echo $i; done', 'ALLOW'],
    ['loop', 'while read -r line; do echo "$line"; done < file.txt', 'ALLOW'],
    ['loop', 'for m in "" "-M:8G" "-M:20G"; do echo $m; done', 'ALLOW'],
    // Below the threshold in total, and a body the guard cannot measure.
    ['loop', 'for i in $(seq 1 40); do sleep 0.2; done', 'ALLOW'],
    ['loop', 'for i in 1 2 3 4 5 6; do ./bench.exe --selftest; done', 'ALLOW'],

    // --- here-strings are source text, not commands ---
    ['heredoc', "$s = @'\nfor i in $(seq 1 40); do sleep 30; done\n'@\nWrite-Host $s", 'ALLOW'],
    ['heredoc', "$s = @'\nimport x from 'y';\nfor (const a of b) { c(a); }\n'@\nSet-Content f.mjs $s", 'ALLOW'],
    // A real loop after a closed here-string is still a command.
    ['heredoc', "$s = @'\nsleep 300\n'@\nfor i in $(seq 1 40); do sleep 30; done", 'BLOCK'],

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

/** Guard cases: the full apply() pipeline, including exemptions. */
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
    // Blocking waits are judged by their requested ceiling, not by a command.
    ['wait', { name: 'wait_agent', arguments: { timeout_ms: 3600000 } }, 'DENY'],
    ['wait', { name: 'wait_agent', arguments: { timeout_ms: 360000 } }, 'DENY'],
    ['wait', { name: 'wait_agent', arguments: { timeout_ms: 300000 } }, 'ALLOW'],
    ['wait', { name: 'wait_agent', arguments: { timeout_ms: 10000 } }, 'ALLOW'],
    ['wait', { name: 'wait_agent', arguments: {} }, 'ALLOW'],
    ['wait', { name: 'wait_agent', arguments: null }, 'ALLOW'],
    ['wait', { name: 'job_output', arguments: { job_id: 'x', wait: true, timeout_ms: 600000 } }, 'DENY'],
    ['wait', { name: 'job_output', arguments: { job_id: 'x', wait: true, timeout_ms: 240000 } }, 'ALLOW'],
    ['wait', { name: 'job_output', arguments: { job_id: 'x', wait: true } }, 'ALLOW'],
    // A plain read returns what is already there, so its timeout is irrelevant.
    ['wait', { name: 'job_output', arguments: { job_id: 'x', timeout_ms: 600000 } }, 'ALLOW'],
    ['wait', { name: 'job_output', arguments: { job_id: 'x', wait: false, timeout_ms: 600000 } }, 'ALLOW'],
    ['wait', { name: 'job_list', arguments: {} }, 'ALLOW'],
    // A shell tool that happens to carry a timeout named for a wait is not one.
    ['exempt', { name: 'pwsh', arguments: { command: 'git status', timeout_ms: 600000 } }, 'ALLOW'],
];

/** Legal commands that must never be refused (false-positive watch list). */
const FALSE_POSITIVE = [
    'ls -la',
    'git status',
    'git commit -m "fix: sleep timeout handling"',
    'git commit -m don\'t care',
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
    'vite build',
    'nodemon --version',
    'watch --version',
    'command -v sleep',
    'sleep 300 &',
    "cat > run.sh <<'EOF'\nsleep 300\nEOF",
];

/** Config cases: [category, config, exec, expected]. Each mounts its own guard. */
const CONFIG = [
    ['config', undefined, { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'DENY'],
    ['config', null, { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'DENY'],
    ['config', 'nonsense', { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'DENY'],
    ['config', { minSeconds: 60 }, { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'ALLOW'],
    ['config', { minSeconds: 60 }, { name: 'pwsh', arguments: { command: 'sleep 60' } }, 'DENY'],
    ['config', { minSeconds: 60 }, { name: 'pwsh', arguments: { command: 'Start-Sleep 30' } }, 'ALLOW'],
    ['config', { minSeconds: 5 }, { name: 'pwsh', arguments: { command: 'sleep 5' } }, 'DENY'],
    ['config', { minSeconds: 'abc' }, { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'DENY'],
    ['config', { minSeconds: -5 }, { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'DENY'],
    ['config', { minSeconds: 0 }, { name: 'pwsh', arguments: { command: 'sleep 30' } }, 'DENY'],
    ['config', { shellTools: ['bash'] }, { name: 'bash', arguments: { command: 'sleep 240' } }, 'DENY'],
    ['config', { shellTools: ['bash'] }, { name: 'pwsh', arguments: { command: 'sleep 240' } }, 'ALLOW'],
    ['config', { shellTools: [] }, { name: 'pwsh', arguments: { command: 'sleep 240' } }, 'DENY'],
    ['config', { shellTools: ['bash', 'custom_shell'] }, { name: 'custom_shell', arguments: { command: 'tail -f x' } }, 'DENY'],
    // `maxWaitMs` bounds a blocking wait; omit it and the shipped 5 minutes apply.
    ['config', { maxWaitMs: 600000 }, { name: 'job_output', arguments: { job_id: 'x', wait: true, timeout_ms: 540000 } }, 'ALLOW'],
    ['config', { maxWaitMs: 60000 }, { name: 'job_output', arguments: { job_id: 'x', wait: true, timeout_ms: 540000 } }, 'DENY'],
    ['config', { maxWaitMs: 60000 }, { name: 'wait_agent', arguments: { timeout_ms: 30000 } }, 'ALLOW'],
    ['config', { maxWaitMs: 'abc' }, { name: 'wait_agent', arguments: { timeout_ms: 360000 } }, 'DENY'],
    ['config', { maxWaitMs: -1 }, { name: 'wait_agent', arguments: { timeout_ms: 360000 } }, 'DENY'],
];

let warnings = [];

function mountGuard(config) {
    const guards = [];
    warnings = [];
    apply({
        tools: { guard: (fn) => { guards.push(fn); return () => {}; } },
        logger: { warn: (...args) => { warnings.push(args); } },
    }, config);
    if (guards.length !== 1) throw new Error(`expected 1 guard, got ${guards.length}`);
    return guards[0];
}

const failures = [];
const stats = new Map();

function bump(category, passed) {
    const row = stats.get(category) ?? { total: 0, passed: 0 };
    row.total += 1;
    if (passed) row.passed += 1;
    stats.set(category, row);
}

for (const [category, command, expected, platform] of DETECT) {
    let actual;
    let detail = '';
    try {
        const reason = platform === undefined ? findBlocking(command) : findBlocking(command, 20, platform);
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

const guard = mountGuard();
for (const [category, exec, expected] of HANDLER) {
    let actual;
    let detail = '';
    try {
        const denial = guard(exec);
        actual = typeof denial === 'string' ? 'DENY' : 'ALLOW';
        detail = typeof denial === 'string' ? denial : '';
    } catch (error) {
        actual = 'THREW';
        detail = String(error?.message ?? error);
    }
    const passed = actual === expected;
    bump(category, passed);
    if (!passed) failures.push({ category, command: JSON.stringify(exec), expected, actual, detail });
}

for (const [category, config, exec, expected] of CONFIG) {
    let actual;
    let detail = '';
    try {
        const mounted = mountGuard(config);
        const denial = mounted(exec);
        actual = typeof denial === 'string' ? 'DENY' : 'ALLOW';
        detail = typeof denial === 'string' ? denial : '';
    } catch (error) {
        actual = 'THREW';
        detail = String(error?.message ?? error);
    }
    const passed = actual === expected;
    bump(category, passed);
    if (!passed) {
        failures.push({ category, command: `config=${JSON.stringify(config)} exec=${JSON.stringify(exec)}`, expected, actual, detail });
    }
}

// A throwing detector must fail open and say so, rather than passing silently.
{
    const exploding = mountGuard({ shellTools: ['bash'], minSeconds: 20 });
    let actual;
    let detail = '';
    try {
        const denial = exploding({ name: 'bash', arguments: Object.defineProperty({}, 'command', {
            get() { throw new TypeError('detector blew up'); },
        }) });
        actual = denial === undefined ? 'ALLOW' : 'DENY';
        detail = warnings.length > 0 ? `warned:${warnings.length}` : 'no-warning';
    } catch (error) {
        actual = 'THREW';
        detail = String(error?.message ?? error);
    }
    const passed = actual === 'ALLOW' && warnings.length > 0;
    bump('config', passed);
    if (!passed) failures.push({ category: 'config', command: 'throwing detector fails open + logs', expected: 'ALLOW', actual, detail });
}

// The refusal names a direction to try next, and the direction matches the shape
// of what was refused. A direction, not a replacement command: the guard cannot
// see why the call was written, so it must not claim to know the fix.
{
    const GUIDANCE = [
        ['sleep', 'sleep 300', /Say what the delay is waiting for/],
        ['sleep', 'Start-Sleep -Seconds 30', /Say what the delay is waiting for/],
        ['loop', 'for i in $(seq 1 40); do sleep 30; done', /Decide what the loop is really waiting for/],
        ['loop', 'until grep -q x log; do sleep 60; done', /Decide what the loop is really waiting for/],
        ['watch', 'watch date', /a command that re-runs itself/],
        ['follow', 'tail -f app.log', /Read the end of the log once/],
        ['follow', 'docker compose logs -f', /Read the end of the log once/],
        ['server', 'vite', /a server is meant to outlive/],
        ['server', 'npm run dev', /a server is meant to outlive/],
    ];
    for (const [category, command, pattern] of GUIDANCE) {
        const mounted = mountGuard();
        const denial = mounted({ name: 'pwsh', arguments: { command } });
        const passed = typeof denial === 'string' && pattern.test(denial);
        bump('guidance', passed);
        if (!passed) {
            failures.push({ category: 'guidance', command, expected: String(pattern), actual: typeof denial === 'string' ? denial : 'ALLOW', detail: '' });
        }
    }

    // The wait tools keep their own advice: the fix is a shorter ceiling, not a
    // background job, and the two are not interchangeable.
    const forWait = mountGuard();
    const waitDenial = forWait({ name: 'job_output', arguments: { job_id: 'x', wait: true, timeout_ms: 600000 } });
    const waitOk = typeof waitDenial === 'string' && /timeout_ms of 300000 or less/.test(waitDenial);
    bump('guidance', waitOk);
    if (!waitOk) failures.push({ category: 'guidance', command: 'wait tool keeps its own advice', expected: 'ceiling advice', actual: String(waitDenial), detail: '' });
}

// Repeated refusals escalate once, at the third, and then stay put: an agent that
// is refused again is usually rephrasing the same intent, not changing approach.
{
    const mounted = mountGuard();
    const lines = [];
    for (let i = 1; i <= 5; i += 1) {
        lines.push(mounted({ name: 'pwsh', arguments: { command: `sleep ${100 + i}` } }));
    }
    const escalatesAtThird = !/refusal #/.test(lines[0])
        && !/refusal #/.test(lines[1])
        && /refusal #3 in this session/.test(lines[2]);
    bump('guidance', escalatesAtThird);
    if (!escalatesAtThird) failures.push({ category: 'guidance', command: 'escalation starts at the third refusal', expected: 'no,no,yes', actual: lines.map((l) => (/refusal #/.test(l) ? 'yes' : 'no')).join(','), detail: '' });

    // It does not keep escalating: the wording is added once and only the number
    // moves after that. A second sentence per refusal would be noise.
    const sentences = (line) => (line.match(/[.!?](?:\s|$)/g) ?? []).length;
    const stable = sentences(lines[2]) === sentences(lines[4]);
    bump('guidance', stable);
    if (!stable) failures.push({ category: 'guidance', command: 'escalated text stops growing', expected: 'same sentence count', actual: `${sentences(lines[2])} vs ${sentences(lines[4])}`, detail: '' });

    // Allowed calls and background jobs are not refusals, so they do not advance it.
    const fresh = mountGuard();
    fresh({ name: 'pwsh', arguments: { command: 'git status' } });
    fresh({ name: 'pwsh', arguments: { command: 'sleep 300', run_in_background: true } });
    fresh({ name: 'read', arguments: { path: 'x' } });
    const firstCounted = fresh({ name: 'pwsh', arguments: { command: 'sleep 300' } });
    const notCounted = !/refusal #/.test(firstCounted);
    bump('guidance', notCounted);
    if (!notCounted) failures.push({ category: 'guidance', command: 'only refusals advance the counter', expected: 'plain', actual: firstCounted, detail: '' });
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

// Refusal logging is capped and rate-limited: a guard firing in a loop must not
// turn the session log into a wall of one-line warnings.
{
    const refusals = [];
    let burst = null;
    apply({
        tools: { guard: (fn) => { burst = fn; return () => {}; } },
        logger: { warn: (...args) => { refusals.push(args.join(' ')); } },
    });
    for (let i = 0; i < 500; i += 1) burst({ name: 'pwsh', arguments: { command: 'sleep 300' } });
    // 500 refusals in one burst collapse to a single line, because of the gap.
    const burstOk = refusals.length === 1;
    bump('logging', burstOk);
    if (!burstOk) failures.push({ category: 'logging', command: '500 refusals in one burst', expected: '1 line', actual: `${refusals.length} lines`, detail: refusals.slice(0, 3).join(' | ') });

    // Nothing is logged for a command that is allowed through.
    const before = refusals.length;
    burst({ name: 'pwsh', arguments: { command: 'git status' } });
    const quietOk = refusals.length === before;
    bump('logging', quietOk);
    if (!quietOk) failures.push({ category: 'logging', command: 'allowed command stays quiet', expected: 'no line', actual: `${refusals.length - before} line(s)`, detail: '' });

    // A logger that throws must not break the guard: checkGuards() has no
    // try/catch of its own, so an exception here would escape into the pipeline.
    let fragile = null;
    apply({
        tools: { guard: (fn) => { fragile = fn; return () => {}; } },
        logger: { warn: () => { throw new Error('logger exploded'); } },
    });
    let survived;
    try {
        survived = typeof fragile({ name: 'pwsh', arguments: { command: 'sleep 300' } }) === 'string';
    } catch {
        survived = false;
    }
    bump('logging', survived);
    if (!survived) failures.push({ category: 'logging', command: 'throwing logger still yields a denial', expected: 'denial string', actual: 'threw or allowed', detail: '' });
}

// An oversized command is analyzed only up to the scan bound; past it the guard
// fails open rather than guessing.
{
    const filler = 'git status\n'.repeat(7000);
    const headOk = findBlocking('sleep 300\n' + filler) !== null;
    bump('logging', headOk);
    if (!headOk) failures.push({ category: 'logging', command: 'blocking command at the head of an oversized line', expected: 'BLOCK', actual: 'ALLOW', detail: '' });

    const tailOk = findBlocking(filler + 'sleep 300') === null;
    bump('logging', tailOk);
    if (!tailOk) failures.push({ category: 'logging', command: 'blocking command past the scan bound', expected: 'ALLOW (fails open)', actual: 'BLOCK', detail: '' });
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
