/**
 * dsh-sleep-guard — refuse commands that would block a whole foreground turn.
 *
 * A foreground blocking command returns only after a long delay (or never), and
 * the agent can do nothing meanwhile. Work that outlives its step belongs in
 * `run_in_background` + `job_output({wait: true})`, which returns immediately and
 * lets the job be collected later.
 *
 * This is the same extension point the host uses for its own guards
 * (`tools/pre-execute`), so it costs no third-party dependency and has no
 * rule-count ceiling. It is hygiene, not a security boundary: a guard bug must
 * never block an unrelated command, so every path below fails open. Destructive
 * command analysis stays with cc-safety-net, which parses shell structure far
 * more thoroughly than this file tries to.
 */

export const name = 'dsh-sleep-guard';

/** Tools whose `command` argument is a shell command line. */
const SHELL_TOOLS = new Set(['ops_bash', 'bash', 'pwsh', 'pwsh_persistent', 'shell']);

/** Shortest foreground delay worth refusing, in seconds. */
const MIN_SECONDS = 20;

const UNIT_SECONDS = Object.freeze({ '': 1, s: 1, m: 60, h: 3600, d: 86400 });

/**
 * Remove quoted text so `echo "sleep 240"` is not read as a sleep call.
 * Only the *unquoted* remainder is analyzed; an unterminated quote simply ends
 * the scan, which fails open.
 *
 * @param {string} command
 * @returns {string}
 */
function stripQuoted(command) {
    let out = '';
    let quote = '';
    for (let i = 0; i < command.length; i += 1) {
        const char = command[i];
        if (quote !== '') {
            if (char === quote) quote = '';
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            out += ' ';
            continue;
        }
        out += char;
    }
    return out;
}

/**
 * Split a command line into its simple-command segments, so per-command checks
 * do not run across `&&`, `||`, `;`, `|`, or newlines.
 *
 * @param {string} text - quote-stripped command line.
 * @returns {string[]}
 */
function segments(text) {
    return text.split(/&&|\|\||[;|\n]/u).map(part => part.trim()).filter(part => part !== '');
}

/** Words that may precede the real command in a segment. */
const WRAPPERS = new Set(['sudo', 'env', 'nohup', 'time', 'command', 'exec', 'nice', 'stdbuf']);

/**
 * The command word of a segment, with leading wrappers and assignments skipped.
 *
 * The word is reduced to its basename so `/usr/bin/sleep`, `./sleep`, `../bin/sleep`
 * and `C:/Windows/System32/PING.EXE` all compare as `sleep` / `ping`. Only a plain
 * basename is produced; no filesystem lookup happens here.
 *
 * @param {string} segment
 * @returns {{ word: string, args: string[] }}
 */
function commandOf(segment) {
    const words = segment.split(/\s+/u).filter(word => word !== '');
    let i = 0;
    while (i < words.length) {
        const word = words[i];
        // `VAR=value` prefixes and wrapper commands are not the command itself.
        if (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(word) || WRAPPERS.has(word)) { i += 1; continue; }
        break;
    }
    const raw = words[i] ?? '';
    // Split on both separators: a Windows path uses '\' and a POSIX path '/'.
    const base = raw.split(/[\\/]/u).pop() ?? '';
    return { word: base.replace(/\.exe$/iu, '').toLowerCase(), args: words.slice(i + 1) };
}

/** Whether any argument matches one of the given patterns. */
function hasArg(args, patterns) {
    return args.some(arg => patterns.some(pattern => pattern.test(arg)));
}

/**
 * Find the reason a command would block the turn, if any.
 *
 * @param {string} command - the raw shell command.
 * @returns {string | null} a human-readable reason, or null when nothing blocks.
 */
export function findBlocking(command) {
    if (typeof command !== 'string' || command === '') return null;
    const text = stripQuoted(command);

    // PowerShell has its own delay and follow verbs.
    const powershell = /(?:^|[;&|(\n]|\s)Start-Sleep\s+-(?:Seconds|Milliseconds)\s+(\d+(?:\.\d+)?)(?![\w.])/gi;
    for (const match of text.matchAll(powershell)) {
        const raw = Number(match[1]);
        const seconds = /-Seconds/iu.test(match[0]) ? raw : raw / 1000;
        if (Number.isFinite(seconds) && seconds >= MIN_SECONDS) {
            return `a ${seconds}s foreground sleep`;
        }
    }

    for (const segment of segments(text)) {
        const { word, args } = commandOf(segment);

        // POSIX sleep, optionally by absolute path.
        if (word === 'sleep') {
            const amount = args[0];
            const match = /^(\d+(?:\.\d+)?)([smhd]?)$/iu.exec(amount ?? '');
            if (match !== null) {
                const seconds = Number(match[1]) * UNIT_SECONDS[(match[2] ?? '').toLowerCase()];
                if (Number.isFinite(seconds) && seconds >= MIN_SECONDS) {
                    return `a ${seconds}s foreground sleep`;
                }
            }
            continue;
        }

        // `tail -f` / `-F` / `--follow` never returns on its own.
        if (word === 'tail' && hasArg(args, [/^-f$/u, /^-F$/u, /^--follow(=.*)?$/u])) {
            return 'a following `tail` that never returns';
        }

        // `watch` re-runs its command forever.
        if (word === 'watch') return 'a `watch` loop that never returns';

        // `ping` without a count runs until interrupted.
        // Windows: -n count (joined or separate), -t infinite, -w timeout(ms),
        //          -l size, -a resolve, -i TTL, -f flag — none of these bound the run.
        // MSYS/Linux: -c count, -w deadline(s), -W timeout(s).
        // Only a count bounds the run, so only -n/-c (and the MSYS -cN form) exempt it.
        if (word === 'ping' && !hasArg(args, [/^-c\d+$/u, /^-n\d+$/u, /^-c$/u, /^-n$/u])) {
            return 'a `ping` without a count that never returns';
        }

        // Follow-mode log readers. `-f` only means follow after a `logs` verb:
        // `docker build -f Dockerfile` and `kubectl apply -f x.yaml` name a file,
        // so the flag alone must not match.
        const FOLLOW = [/^-f$/u, /^--follow(=.*)?$/u];
        if (word === 'journalctl' && hasArg(args, FOLLOW)) {
            return 'a follow-mode log reader that never returns';
        }
        // `docker logs`, `docker compose logs`, `docker-compose logs`, `kubectl logs`.
        // Global options that take a separate value must be skipped together with that
        // value, or `kubectl -n prod logs -f` reads `prod` as the verb.
        const VALUE_OPTIONS = new Set(['-n', '--namespace', '-c', '--container', '--context', '--kubeconfig']);
        const positional = [];
        for (let i = 0; i < args.length; i += 1) {
            const arg = args[i];
            if (VALUE_OPTIONS.has(arg)) { i += 1; continue; }
            if (arg.startsWith('-')) continue;
            positional.push(arg);
        }
        const verb = positional[0] ?? '';
        if (word === 'docker' || word === 'docker-compose' || word === 'kubectl') {
            if (verb === 'logs' && hasArg(args, FOLLOW)) {
                return 'a follow-mode log reader that never returns';
            }
            // `docker compose logs -f`: the `logs` verb sits one position further in.
            if (word === 'docker' && verb === 'compose' && positional[1] === 'logs' && hasArg(args, FOLLOW)) {
                return 'a follow-mode log reader that never returns';
            }
        }

        // Dev servers are foreground processes by nature.
        if (word === 'vite' || word === 'nodemon') return 'a dev server that never returns';
        if (word === 'webpack' && args.includes('serve')) return 'a dev server that never returns';
        if (word === 'npm' || word === 'pnpm' || word === 'yarn') {
            const sub = args.find(arg => !arg.startsWith('-'));
            if (sub === 'start') return 'a dev server that never returns';
            if (sub === 'run' && /^(dev|serve|start|watch)$/u.test(args.find(arg => !arg.startsWith('-') && arg !== 'run') ?? '')) {
                return 'a dev server that never returns';
            }
        }
    }
    return null;
}

/**
 * Mount the guard row.
 *
 * @param {import('cordis').Context} ctx - the row's cordis context.
 */
export function apply(ctx) {
    ctx.on('tools/pre-execute', async (exec, next) => {
        try {
            const toolName = typeof exec?.name === 'string' ? exec.name : '';
            if (!SHELL_TOOLS.has(toolName)) return next();
            const args = exec?.arguments;
            if (args === null || typeof args !== 'object') return next();
            // A background job returns at once, so its delay costs nothing.
            if (args.run_in_background === true) return next();
            // File contents are not part of this call; do not read or guess them.
            if (typeof args.script_path === 'string' && args.script_path !== '') return next();
            const blocking = findBlocking(args.command);
            if (blocking === null) return next();
            return {
                kind: 'deny',
                reason: `Refusing ${blocking}: it would hold the whole turn. `
                    + 'Start it with run_in_background and collect it with job_output({ wait: true }), '
                    + 'or add a bound so it returns on its own.',
            };
        } catch {
            // A detector bug must never block an unrelated command.
            return next();
        }
    });
}
