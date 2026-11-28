/**
 * dsh-sleep-guard — refuse calls that would block a whole foreground turn.
 *
 * A foreground blocking command returns only after a long delay (or never), and
 * the agent can do nothing meanwhile. Work that outlives its step belongs in
 * `run_in_background` + `job_output({wait: true})`, which returns immediately and
 * lets the job be collected later.
 *
 * The row registers a monotonic `ctx.tools.guard()`: the decision is synchronous,
 * cannot be re-granted by a later listener, and has no waterfall to hand back to.
 * It is hygiene, not a security boundary: a guard bug must never block an
 * unrelated command, so every path below fails open. Destructive command analysis
 * stays with cc-safety-net, which parses shell structure far more thoroughly
 * than this file tries to.
 *
 * Two kinds of call hold a turn: a foreground command that returns late or never,
 * and a blocking wait (`job_output` with `wait: true`, `wait_agent`) whose ceiling
 * is longer than one step should last. Both are judged here.
 */

export const name = 'dsh-sleep-guard';

/** The tools service must exist before this row can register its guard. */
export const inject = ['tools'];

/**
 * Tools whose `command` argument is a shell command line.
 *
 * `bash` and `pwsh` cover both the regular and the persistent variants: the
 * persistent tools register under the same names and take only `{ command }`,
 * with no `run_in_background`, so they are the ones most in need of a guard.
 * `pwsh_persistent`, `shell` and `ops_bash` are not registered by any shipped
 * package on this profile; they are kept for profiles that install a matching
 * tool (dsh-ops provides `ops_bash`) and never match otherwise.
 */
const SHELL_TOOLS = new Set(['ops_bash', 'bash', 'pwsh', 'pwsh_persistent', 'shell']);

/** Shortest foreground delay worth refusing, in seconds. */
const MIN_SECONDS = 20;

/**
 * Tools that block the turn with a `timeout_ms` wait instead of a command.
 *
 * `wait_agent` always blocks; `job_output` blocks only when `wait: true`. Both
 * return the moment their condition is met, so a large timeout is a ceiling, not
 * a planned delay — which is why the limit below is generous and why the refusal
 * targets the requested ceiling rather than the time actually spent.
 */
const WAIT_TOOLS = new Set(['wait_agent', 'job_output']);

/** Longest single blocking wait worth allowing, in milliseconds. */
const MAX_WAIT_MS = 300000;

/** The timeout the host applies to a blocking wait that names none. */
const DEFAULT_WAIT_MS = 30000;

const UNIT_SECONDS = Object.freeze({ '': 1, s: 1, m: 60, h: 3600, d: 86400 });

/**
 * Longest command line analyzed in full.
 *
 * Real shell calls sit around a few hundred characters; the longest one seen in
 * this profile was 2.5 KB. A command past this bound is almost certainly a
 * generated blob, and scanning it whole costs milliseconds per tool call for no
 * benefit. The head is analyzed and the tail is not, which fails open: a delay
 * past the cut is allowed rather than guessed at.
 */
const MAX_SCAN_CHARS = 65536;

/** Most refusal lines one mounted guard may write, across its whole lifetime. */
const LOG_LIMIT = 100;

/** Shortest gap between two refusal lines, so a burst collapses into one. */
const LOG_GAP_MS = 1000;

/**
 * Refusal number at which the message stops assuming a one-off mistake.
 *
 * Three is the point where "I typed a long sleep" has usually become "I want to
 * wait and I keep restating it". The message changes once, at that count, and
 * never escalates again: a running count in every line would be noise, and a
 * further escalation would only repeat what the first one said.
 */
const REPEAT_AT = 3;

/**
 * Read the `config` a patch row carries.
 *
 * The package keeps its knobs dependency-free: there is no `Config` schema, so
 * cordis hands the patch layer's object to `apply` untouched. Each key falls
 * back to its shipped default when it is missing or malformed, because a typo
 * in a patch must not silently disable the guard.
 *
 * @param {unknown} config - the raw `config` of the patch row, if any.
 * @returns {{ shellTools: Set<string>, minSeconds: number, maxWaitMs: number }} the active settings.
 */
function resolveSettings(config) {
    const raw = config !== null && typeof config === 'object' ? config : {};
    const minSeconds = typeof raw.minSeconds === 'number'
        && Number.isFinite(raw.minSeconds) && raw.minSeconds > 0
        ? raw.minSeconds
        : MIN_SECONDS;
    const maxWaitMs = typeof raw.maxWaitMs === 'number'
        && Number.isFinite(raw.maxWaitMs) && raw.maxWaitMs > 0
        ? raw.maxWaitMs
        : MAX_WAIT_MS;
    const listed = Array.isArray(raw.shellTools)
        ? raw.shellTools.filter(tool => typeof tool === 'string' && tool !== '')
        : [];
    return { shellTools: listed.length > 0 ? new Set(listed) : SHELL_TOOLS, minSeconds, maxWaitMs };
}

/** Flags that make an otherwise long-running command print something and return. */
const SHORT_CIRCUIT = [/^--version$/u, /^--help$/u, /^-v$/u, /^-h$/u];

/** Follow-mode flags shared by the log readers. */
const FOLLOW = [/^-f$/u, /^--follow(=.*)?$/u];

/**
 * Drop PowerShell here-string bodies.
 *
 * `$script = @' … '@` — and the `@" … "@` form — carries file contents or source
 * text, exactly like a heredoc. Without this pass the body is ordinary text to
 * every later stage: an embedded JavaScript loop reads as a shell loop, and the
 * apostrophes inside it close `stripQuoted` at the wrong place, exposing the
 * rest of the body.
 *
 * @param {string} command - the raw shell command.
 * @returns {string} the command with here-string bodies blanked out.
 */
function dropHereStrings(command) {
    if (!command.includes("@'") && !command.includes('@"')) return command;
    const lines = command.split('\n');
    if (lines.length === 1) return command;
    const kept = [];
    let terminator = '';
    for (const line of lines) {
        if (terminator !== '') {
            if (line.trim() === terminator) terminator = '';
            kept.push('');
            continue;
        }
        kept.push(line);
        // PowerShell opens a here-string with `@'` or `@"` at the end of a line.
        const opened = /@(['"])\s*$/u.exec(line);
        if (opened !== null) terminator = `${opened[1]}@`;
    }
    return kept.join('\n');
}

/**
 * Drop heredoc bodies.
 *
 * `cat > run.sh <<'EOF'` is followed by file contents, not by commands; reading
 * the body as a command line refuses an innocent script writer.
 *
 * @param {string} command - the raw shell command.
 * @returns {string} the command with heredoc bodies blanked out.
 */
function dropHeredocs(command) {
    if (!command.includes('<<')) return command;
    const lines = command.split('\n');
    if (lines.length === 1) return command;
    const kept = [];
    let terminator = '';
    for (const line of lines) {
        if (terminator !== '') {
            if (line.trim() === terminator) terminator = '';
            kept.push('');
            continue;
        }
        kept.push(line);
        // `<` right after `<<` is a here-string, which passes its text as one value.
        if (line.includes('<<<')) continue;
        const opened = heredocTerminator(line);
        if (opened !== '') terminator = opened;
    }
    return kept.join('\n');
}

/**
 * Find a heredoc opener in one line, ignoring `<<` inside quotes and arithmetic.
 *
 * `echo "a << b"` is an echo of four characters, not the start of a heredoc.
 * Taking it as one blanks the following line and hides a real block.
 *
 * `x=$((1<<n))` is a bit shift, not a heredoc, and treating it as one would
 * blank the line after it — which is how `x=$((1<<n))` followed by `sleep 300`
 * used to slip through.
 *
 * @param {string} line
 * @returns {string} the delimiter, or an empty string when the line opens none.
 */
function heredocTerminator(line) {
    let quote = '';
    // `$((1<<n))` and `(( x = 1<<3 ))` shift bits; that `<<` opens no heredoc.
    let arithmetic = 0;
    for (let i = 0; i < line.length; i += 1) {
        const char = line[i];
        if (quote !== '') {
            if (char === quote) quote = '';
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            continue;
        }
        if (char === '(' && line[i + 1] === '(') {
            arithmetic += 1;
            i += 1;
            continue;
        }
        if (arithmetic > 0 && char === ')' && line[i + 1] === ')') {
            arithmetic -= 1;
            i += 1;
            continue;
        }
        if (char !== '<' || line[i + 1] !== '<') continue;
        if (arithmetic > 0) continue;
        const match = /^<<-?\s*(?:'([^']*)'|"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*))/u.exec(line.slice(i));
        if (match !== null) return match[1] ?? match[2] ?? match[3] ?? '';
    }
    return '';
}

/**
 * Remove quoted text so `echo "sleep 240"` is not read as a sleep call.
 *
 * A quote only opens a passage when a matching quote follows it. Taking a lone
 * apostrophe as an opening quote — `git commit -m don't` — would blank out the
 * rest of the line and hide a real block, so an unpaired quote stays literal
 * text and the tail keeps being analyzed.
 *
 * The passage is replaced with one placeholder word rather than a single space,
 * so a quoted argument still counts as one word: in `for m in "" "-M:8G"; do …
 * done` the list length decides how many times the body runs, and collapsing the
 * quotes to nothing would read the loop as a single pass.
 *
 * @param {string} command
 * @returns {string}
 */
function stripQuoted(command) {
    let out = '';
    let i = 0;
    while (i < command.length) {
        const char = command[i];
        if (char === '"' || char === "'") {
            const closing = command.indexOf(char, i + 1);
            if (closing < 0) {
                out += char;
                i += 1;
                continue;
            }
            out += ' quoted ';
            i = closing + 1;
            continue;
        }
        out += char;
        i += 1;
    }
    return out;
}

/**
 * Remove descriptor redirections so `2>&1` is not mistaken for a background `&`.
 *
 * @param {string} text - quote-stripped command line.
 * @returns {string}
 */
function dropRedirections(text) {
    return text
        .replace(/\d*>&\d*/gu, ' ')
        .replace(/&>>?/gu, ' ')
        .replace(/<\d*&/gu, ' ');
}

/**
 * Split a command line into its simple-command segments, so per-command checks
 * do not run across `&&`, `||`, `;`, `|`, `&`, or line breaks. A lone `\r`
 * separates commands too: old Mac and some Windows-produced scripts use it.
 *
 * A segment ended by a bare `&` was backgrounded: the shell returns at once, so
 * its delay costs nothing and it must not be refused.
 *
 * @param {string} text - quote-stripped command line.
 * @returns {{ text: string, background: boolean }[]}
 */
function segments(text) {
    const parts = text.split(/(&&|\|\||[;|\r\n]|&)/u);
    const out = [];
    for (let i = 0; i < parts.length; i += 2) {
        const body = (parts[i] ?? '').trim();
        if (body === '') continue;
        out.push({ text: body, background: parts[i + 1] === '&' });
    }
    return out;
}

/** Words that may precede the real command in a segment. */
const WRAPPERS = new Set(['sudo', 'env', 'nohup', 'time', 'command', 'exec', 'nice', 'stdbuf']);

/**
 * Options each wrapper consumes a separate value for, so that value is skipped
 * instead of being read as the command word (`sudo -u root sleep 300`).
 */
const WRAPPER_VALUE_OPTIONS = new Map([
    ['sudo', new Set(['-u', '--user', '-g', '--group', '-p', '--prompt', '-C', '--close-from', '-r', '--role', '-t', '--type', '-D', '--chdir', '-R', '--chroot', '-T', '--command-timeout', '-U', '--other-user'])],
    ['env', new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string', '-P', '--path'])],
    ['nice', new Set(['-n', '--adjustment'])],
    ['time', new Set(['-f', '--format', '-o', '--output'])],
    ['stdbuf', new Set(['-i', '--input', '-o', '--output', '-e', '--error'])],
    ['exec', new Set(['-a'])],
]);

/** Busybox-style dispatchers: the applet that follows is the real command. */
const MULTICALL = new Set(['busybox']);

/** Runners that execute the command named after them. */
const LAUNCHERS = new Set(['npx', 'bunx', 'pnpx']);
const LAUNCHER_VALUE_OPTIONS = new Set(['-p', '--package', '-c', '--call']);

/** Package managers, whose `dlx`/`exec` subcommand runs another command. */
const PACKAGE_MANAGERS = new Set(['npm', 'pnpm', 'yarn', 'bun']);

/** The basename of a path-like word, without a Windows executable suffix. */
function basename(word) {
    const base = word.split(/[\\/]/u).pop() ?? '';
    return base.replace(/\.(?:exe|cmd|bat)$/iu, '').toLowerCase();
}

/**
 * Step over a wrapper and its own options.
 *
 * @param {string} wrapper - lower-cased wrapper word.
 * @param {string[]} words - the segment's words.
 * @param {number} start - index just after the wrapper.
 * @returns {number | null} index of the wrapper's command, or null when the
 *   wrapper never runs a command (`command -v sleep` only prints a path).
 */
function skipWrapperOptions(wrapper, words, start) {
    const valueOptions = WRAPPER_VALUE_OPTIONS.get(wrapper);
    let i = start;
    while (i < words.length) {
        const token = words[i];
        if (token === '--') return i + 1;
        if (!token.startsWith('-')) return i;
        // `command -v` / `-V` look the command up instead of running it.
        if (wrapper === 'command' && (token === '-v' || token === '-V')) return null;
        i += valueOptions !== undefined && valueOptions.has(token) ? 2 : 1;
    }
    return i;
}

/**
 * Step over a runner and its options.
 *
 * @param {string[]} words - the segment's words.
 * @param {number} start - index just after the runner.
 * @returns {number} index of the command the runner will start.
 */
function skipLauncherOptions(words, start) {
    let i = start;
    while (i < words.length && words[i].startsWith('-')) {
        i += LAUNCHER_VALUE_OPTIONS.has(words[i]) ? 2 : 1;
    }
    return i;
}

/**
 * The command word of a segment, with leading assignments, wrappers, and
 * command runners skipped.
 *
 * The word is reduced to its basename so `/usr/bin/sleep`, `./sleep`, `../bin/sleep`
 * and `C:/Windows/System32/PING.EXE` all compare as `sleep` / `ping`. Only a plain
 * basename is produced; no filesystem lookup happens here.
 *
 * @param {string} segment
 * @returns {{ word: string, args: string[] } | null} null when the segment never
 *   runs a command.
 */
function commandOf(segment) {
    const words = segment.split(/\s+/u).filter(word => word !== '');
    let i = 0;
    while (i < words.length) {
        const word = basename(words[i]);
        // `VAR=value` prefixes are not the command itself.
        if (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(words[i])) { i += 1; continue; }
        if (MULTICALL.has(word)) { i += 1; continue; }
        if (WRAPPERS.has(word)) {
            const next = skipWrapperOptions(word, words, i + 1);
            if (next === null) return null;
            i = next;
            continue;
        }
        if (LAUNCHERS.has(word)) { i = skipLauncherOptions(words, i + 1); continue; }
        if (PACKAGE_MANAGERS.has(word) && (words[i + 1] === 'dlx' || words[i + 1] === 'exec')) {
            i += 2;
            continue;
        }
        break;
    }
    const raw = words[i] ?? '';
    return { word: basename(raw), args: words.slice(i + 1) };
}

/** Whether any argument matches one of the given patterns. */
function hasArg(args, patterns) {
    return args.some(arg => patterns.some(pattern => pattern.test(arg)));
}

/** PowerShell accepts any unambiguous prefix of `-Seconds` / `-Milliseconds`. */
const SECOND_FLAG = /^-(?:s|se|sec|seco|secon|second|seconds)(?:[:=](.*))?$/iu;
const MILLI_FLAG = /^-(?:m|mi|mil|mill|milli|millis|millise|millisec|milliseco|millisecond|milliseconds)(?:[:=](.*))?$/iu;

/**
 * Parse a delay written the way `sleep` and `Start-Sleep` accept it.
 *
 * @param {string} text - a bare number, optionally with a POSIX unit suffix.
 * @returns {number | null} seconds, or null when the text is not a literal delay.
 */
function toSeconds(text) {
    const match = /^(\d+(?:\.\d+)?(?:e[+-]?\d+)?)([smhd]?)$/iu.exec(text ?? '');
    if (match === null) return null;
    const value = Number(match[1]);
    const unit = UNIT_SECONDS[(match[2] ?? '').toLowerCase()];
    if (!Number.isFinite(value) || unit === undefined) return null;
    return value * unit;
}

/**
 * The foreground delay a `sleep` / `Start-Sleep` invocation asks for.
 *
 * Handles the flag form (`-Seconds 60`, `-Milliseconds:30000`, the `-s` / `-m`
 * prefixes PowerShell allows) and the positional form (`Start-Sleep 60`). A
 * non-literal argument such as `$t` is not evaluated, which fails open.
 *
 * @param {string[]} args
 * @returns {number | null} seconds, or null when no literal delay is present.
 */
function sleepSeconds(args) {
    for (let i = 0; i < args.length; i += 1) {
        const token = args[i];
        for (const [pattern, scale] of [[SECOND_FLAG, 1], [MILLI_FLAG, 0.001]]) {
            const match = pattern.exec(token);
            if (match === null) continue;
            const seconds = toSeconds(match[1] ?? args[i + 1]);
            return seconds === null ? null : seconds * scale;
        }
        if (!token.startsWith('-')) return toSeconds(token);
    }
    return null;
}

/** `ping` flags that bound the run: a numeric count, joined or separate. */
const PING_COUNT_FLAGS = new Set(['-c', '-n', '--count']);

/**
 * Whether a `ping` invocation carries a packet count.
 *
 * Windows spells the count `-n 4`; MSYS/Linux spells it `-c 4`. A bare `-n`
 * with no number after it is the Linux "numeric output" flag, which does not
 * bound the run, so the value has to be checked rather than the flag alone.
 *
 * @param {string[]} args
 * @returns {boolean}
 */
function pingHasCount(args) {
    for (let i = 0; i < args.length; i += 1) {
        const arg = args[i];
        if (PING_COUNT_FLAGS.has(arg) && /^\d+$/u.test(args[i + 1] ?? '')) return true;
        if (/^-[cn]\d+$/u.test(arg)) return true;
        if (arg.startsWith('--count=') && /^\d+$/u.test(arg.slice('--count='.length))) return true;
    }
    return false;
}

/**
 * Whether a `ping` invocation is bounded without an explicit count.
 *
 * The two `ping` implementations disagree here, so the rule is per platform:
 *
 * - Windows `ping.exe` sends four echoes and returns on its own (measured
 *   3035 ms for `ping 127.0.0.1`); only `-t` runs until interrupted. An
 *   unreachable host costs about 15 s, still under the 20 s threshold.
 * - MSYS/Linux `ping` runs until interrupted unless `-c` bounds it.
 *
 * `-h` / `--help` / `-V` / `--version` print usage and return in milliseconds on
 * both, and were the one false refusal found in the real command corpus.
 *
 * @param {string[]} args
 * @param {string} platform - `process.platform` of the running host.
 * @returns {boolean} whether the invocation ends on its own.
 */
function pingBounded(args, platform) {
    if (hasArg(args, [/^--?h(?:elp)?$/u, /^--version$/u, /^-V$/u, /^-\?$/u])) return true;
    if (pingHasCount(args)) return true;
    return platform === 'win32' && !args.includes('-t');
}

/** Script names that start a long-running dev server. */
const DEV_SCRIPTS = new Set(['start', 'dev', 'serve', 'watch']);

/** `vite` subcommands that build and exit. */
const VITE_ONE_SHOT = new Set(['build', 'optimize']);

/**
 * Whether a command starts a dev server that never returns on its own.
 *
 * @param {string} word - lower-cased command word.
 * @param {string[]} args
 * @returns {string | null} a reason, or null when the command returns.
 */
function devServerReason(word, args) {
    if (word === 'vite') {
        if (hasArg(args, SHORT_CIRCUIT)) return null;
        const sub = args.find(arg => !arg.startsWith('-')) ?? '';
        return VITE_ONE_SHOT.has(sub) ? null : 'a dev server that never returns';
    }
    if (word === 'nodemon') {
        return hasArg(args, SHORT_CIRCUIT) ? null : 'a dev server that never returns';
    }
    if (word === 'webpack') {
        return args.includes('serve') ? 'a dev server that never returns' : null;
    }
    if (PACKAGE_MANAGERS.has(word)) {
        const positional = args.filter(arg => !arg.startsWith('-'));
        const first = positional[0] ?? '';
        const script = first === 'run' || first === 'run-script' ? positional[1] ?? '' : first;
        return DEV_SCRIPTS.has(script) ? 'a dev server that never returns' : null;
    }
    return null;
}

/** `Start-Sleep` anywhere in a command, including inside a PowerShell block. */
const START_SLEEP = /(?:^|[;&|({\n]|\s)Start-Sleep(?=\s|$)([^\n;|&}]*)/giu;

/**
 * A `for`/`while`/`until` loop body that reaches a foreground `sleep N`.
 *
 * `segments()` runs first and splits `do sleep 30; done` at its separators, so
 * the body is already in pieces by the time a per-segment check sees it. What
 * those pieces still share is the loop that encloses them, which is why the loop
 * is matched on the whole text before segmenting.
 *
 * The iteration count is only read when it is written literally: `$(seq 1 40)`
 * or a plain word list. `while true` has no count, so one pass is assumed — the
 * command is still refused, because a loop whose sleep is already over the
 * threshold blocks at least that long per pass.
 */
const LOOP_SLEEP = /\b(?:for|while|until)\b([\s\S]{0,300}?)\bdo\b([\s\S]{0,2000}?)\bdone\b/giu;

/** A foreground `sleep N` inside a loop body: not backgrounded, not in a comment. */
const LOOP_BODY_SLEEP = /(?:^|[;&|(\n]|\bdo\b|\bthen\b|\belse\b)\s*sleep\s+(\d+(?:\.\d+)?)([smhd]?)?\b(?!\s*&)/giu;

/** The iteration count a `for` header states, or 1 when it cannot be read. */
function loopIterations(header) {
    const counted = /\$\(\s*seq\s+1\s+(\d+)\s*\)/iu.exec(header);
    if (counted !== null) return Number(counted[1]);
    const list = /\bin\s+([\s\S]*)$/iu.exec(header);
    if (list === null) return 1;
    const words = list[1].match(/"[^"]*"|'[^']*'|\S+/gu) ?? [];
    return Math.max(1, words.length);
}

/** A `while`/`until` whose condition is a literal that never changes. */
const UNBOUNDED_LOOP = /\bwhile\s+(?:true|:)\s*;?\s*$/iu;

/**
 * The reason a loop holds the turn for at least `minSeconds`, if any.
 *
 * The hold is the whole loop, not one pass: `for i in $(seq 1 30); do sleep 10;
 * done` is five minutes of a frozen turn even though no single sleep crosses the
 * threshold. So the per-pass sleep is multiplied by the iteration count before
 * the comparison.
 *
 * A loop with no sleep in its body is skipped: `for f in *.txt; do wc -l "$f";
 * done` finishes when the glob does, and `while read -r line; do …; done < f`
 * ends at EOF. `while true` has no exit path at all, so it is refused whatever
 * its body sleeps.
 *
 * Only the sleep is counted. Everything else in the body is assumed to cost
 * nothing, which makes the figure a lower bound and keeps the estimate from
 * inventing time it cannot see. A nested loop is matched by the outer one and
 * its body sleeps are summed, which errs toward refusing a genuinely long call.
 *
 * @param {string} text - quote-stripped, heredoc-free command text.
 * @param {number} minSeconds - shortest foreground hold worth refusing.
 * @returns {string | null}
 */
function loopReason(text, minSeconds) {
    for (const match of text.matchAll(LOOP_SLEEP)) {
        const header = match[1] ?? '';
        const body = match[2] ?? '';
        let perPass = null;
        for (const sleep of body.matchAll(LOOP_BODY_SLEEP)) {
            const amount = toSeconds(`${sleep[1]}${sleep[2] ?? ''}`);
            if (amount === null) continue;
            perPass = (perPass ?? 0) + amount;
        }
        if (perPass === null) continue;
        if (UNBOUNDED_LOOP.test(header)) return 'a `while true` loop that never returns';
        const iterations = loopIterations(header);
        const total = perPass * iterations;
        if (total < minSeconds) continue;
        return iterations > 1
            ? `a loop holding ${total}s in the foreground (${iterations} x ${perPass}s)`
            : `a ${total}s foreground sleep in a loop`;
    }
    return null;
}

/**
 * The reason a blocking wait is too long, if any.
 *
 * Both tools accept a `timeout_ms` ceiling and return the moment their condition
 * is met, so the requested ceiling is a budget, not a planned delay. Capping it
 * does not forbid waiting: it forces the wait back into a step boundary, where
 * the agent can look at the job and decide again instead of sitting frozen for
 * the whole ceiling. A malformed or absent `timeout_ms` takes the host default,
 * which fails open.
 *
 * This judge sees only the call, so it cannot know that the waited-on job has
 * already settled and the call would return at once; such a call is refused too.
 * That costs one extra tool call and no lost work, because the retry carries a
 * shorter ceiling and returns the output immediately.
 *
 * @param {string} toolName
 * @param {Record<string, unknown>} args
 * @param {number} maxWaitMs - longest blocking wait worth allowing.
 * @returns {string | null} a reason, or null when the wait is bounded.
 */
function waitReason(toolName, args, maxWaitMs) {
    if (!WAIT_TOOLS.has(toolName)) return null;
    // `job_output` without `wait: true` reads what is already there and returns.
    if (toolName === 'job_output' && args.wait !== true) return null;
    const requested = typeof args.timeout_ms === 'number' && Number.isFinite(args.timeout_ms)
        ? args.timeout_ms
        : DEFAULT_WAIT_MS;
    if (requested <= maxWaitMs) return null;
    return `a ${Math.round(requested / 1000)}s blocking wait`;
}

/**
 * Find the reason a command would block the turn, if any.
 *
 * @param {string} command - the raw shell command.
 * @param {number} [minSeconds] - shortest foreground delay to refuse.
 * @param {string} [platform] - `process.platform` of the running host; the
 *   `ping` bound differs between Windows and MSYS/Linux.
 * @returns {string | null} a human-readable reason, or null when nothing blocks.
 */
export function findBlocking(command, minSeconds = MIN_SECONDS, platform = process.platform) {
    if (typeof command !== 'string' || command === '') return null;
    // Scan the head of an oversized command instead of all of it: the tail is
    // not analyzed, which fails open rather than guessing.
    const scoped = command.length > MAX_SCAN_CHARS ? command.slice(0, MAX_SCAN_CHARS) : command;
    const text = stripQuoted(dropRedirections(dropHeredocs(dropHereStrings(scoped))));

    // PowerShell has its own delay cmdlet, which may sit inside a block.
    for (const match of text.matchAll(START_SLEEP)) {
        const args = (match[1] ?? '').split(/\s+/u).filter(word => word !== '');
        const seconds = sleepSeconds(args);
        if (seconds !== null && seconds >= minSeconds) return `a ${seconds}s foreground sleep`;
    }

    // A loop hides its delay from the per-segment check, so it is matched first.
    const loop = loopReason(text, minSeconds);
    if (loop !== null) return loop;

    for (const { text: body, background } of segments(text)) {
        // `cmd &` returns immediately, so it never holds the turn.
        if (background) continue;
        const parsed = commandOf(body);
        if (parsed === null) continue;
        const { word, args } = parsed;

        // POSIX `sleep` and the PowerShell `Sleep` alias.
        if (word === 'sleep' || word === 'start-sleep') {
            const seconds = sleepSeconds(args);
            if (seconds !== null && seconds >= minSeconds) return `a ${seconds}s foreground sleep`;
            continue;
        }

        // `tail -f` / `-F` / `--follow` never returns on its own.
        if (word === 'tail' && hasArg(args, [/^-f$/u, /^-F$/u, /^--follow(=.*)?$/u])) {
            return 'a following `tail` that never returns';
        }

        // `watch` re-runs its command forever.
        if (word === 'watch') {
            if (hasArg(args, SHORT_CIRCUIT)) continue;
            return 'a `watch` loop that never returns';
        }

        // `ping` without a bound runs until interrupted. What counts as a bound
        // differs per platform, so the rule lives in pingBounded().
        if ((word === 'ping' || word === 'ping6') && !pingBounded(args, platform)) {
            return 'a `ping` without a count that never returns';
        }

        // Follow-mode log readers. `-f` only means follow after a `logs` verb:
        // `docker build -f Dockerfile` and `kubectl apply -f x.yaml` name a file,
        // so the flag alone must not match. Testing for the `logs` token instead
        // of a fixed position keeps `docker compose -f box.yml logs -f` working,
        // because compose's own global options would shift the verb along.
        if (word === 'journalctl' && hasArg(args, FOLLOW)) {
            return 'a follow-mode log reader that never returns';
        }
        // Only flags after the `logs` verb count: `docker compose -f box.yml logs`
        // names a compose file, and that `-f` is not a follow.
        const logsAt = args.indexOf('logs');
        if ((word === 'docker' || word === 'docker-compose' || word === 'kubectl')
            && logsAt >= 0 && hasArg(args.slice(logsAt + 1), FOLLOW)) {
            return 'a follow-mode log reader that never returns';
        }

        // Dev servers are foreground processes by nature.
        const server = devServerReason(word, args);
        if (server !== null) return server;
    }
    return null;
}

/**
 * The direction to try next, keyed by the shape of what was refused.
 *
 * These are directions, not replacement commands. The guard sees one command and
 * no context: a `sleep 300` may be waiting for a process, for a service to come
 * up, or may be padding that does not belong at all, and the three need different
 * fixes. Naming one concrete rewrite would be wrong in the other two cases, and a
 * wrong instruction is worse than a general one because the agent follows it and
 * then fails. What is safe to say is which *kind* of change to consider — that
 * holds whatever the surrounding context turns out to be.
 *
 * The mapping reads the reason this file itself produced, so it stays in step with
 * the detector: a new reason that matches nothing falls back to the generic line.
 *
 * @param {string} reason - the reason `findBlocking` or `waitReason` returned.
 * @returns {string} one sentence naming the next step.
 */
function guidanceFor(reason) {
    // `watch date` says "loop" too, so the watch case is checked before the loop
    // case; the two need different advice, and the word overlap is unavoidable.
    if (reason.includes('watch')) {
        return 'Start it in a background job and collect it with job_output; a command that '
            + 're-runs itself is meant to outlive the step that starts it.';
    }
    // Checked before the sleep branch: a loop's reason also mentions a sleep.
    if (reason.includes('loop')) {
        return 'Decide what the loop is really waiting for. If it polls a condition, lift the '
            + 'check out of the loop and call it once per step instead; if the loop is genuine '
            + 'work, run the whole loop in a background job and collect it later.';
    }
    if (reason.includes('foreground sleep')) {
        return 'Say what the delay is waiting for. If it is an external condition, replace the '
            + 'fixed wait with one bounded check; if it only pads time, drop it; if the pause is '
            + 'genuinely part of the work, run it in a background job.';
    }
    if (reason.includes('follow') || reason.includes('tail')) {
        return 'Read the end of the log once instead of following it, or run the follower in a '
            + 'background job and collect what it has written so far.';
    }
    if (reason.includes('dev server')) {
        return 'Start it in a background job and collect it with job_output; a server is meant '
            + 'to outlive the step that starts it.';
    }
    if (reason.includes('ping')) {
        return 'Bound the run with a packet count, or start it in a background job.';
    }
    return 'Start it in a background job and collect it with job_output, or add a bound so it '
        + 'returns on its own.';
}

/**
 * Mount the guard row.
 *
 * The decision is synchronous and final: `ctx.tools.guard()` runs after the
 * extensible pre-execute policy, and a returned reason cannot be re-granted by
 * a later listener, so registration order does not matter.
 *
 * The row's `config` is read here rather than through a `Config` schema, which
 * keeps the package free of a `@deepseek-ai/schemastery` dependency; cordis
 * passes an unvalidated patch object through untouched. Settings are resolved
 * once per mount, so a malformed patch degrades to the shipped defaults.
 *
 * @param {import('cordis').Context} ctx - the row's cordis context.
 * @param {unknown} [config] - the `config` of the patch row, if any.
 * @returns {() => void} the disposer that removes the guard.
 */
export function apply(ctx, config) {
    const { shellTools, minSeconds, maxWaitMs } = resolveSettings(config);
    // Refusal logging is deliberately bounded: a guard that fires in a loop must
    // not turn the session log into a megabyte of one-line warnings. Two limits
    // apply, both per mount — a total cap and a minimum gap between lines.
    // Logging must never be the reason a tool call fails, so it is also guarded:
    // `checkGuards()` calls the guard without a try/catch of its own.
    let logged = 0;
    let lastLogAt = 0;
    let suppressed = 0;
    const note = (reason) => {
        try {
            const now = Date.now();
            if (logged >= LOG_LIMIT || now - lastLogAt < LOG_GAP_MS) {
                suppressed += 1;
                return;
            }
            logged += 1;
            lastLogAt = now;
            const tail = suppressed === 0 ? '' : ` (${suppressed} more refusal(s) not logged)`;
            suppressed = 0;
            ctx.logger?.warn?.(`[dsh-sleep-guard] refused ${reason}${tail}`);
        } catch {
            // A broken logger is not worth failing a tool call over.
        }
    };
    // An agent that has been refused several times is usually rephrasing the same
    // intent rather than changing the approach. Saying so is cheaper than another
    // round of "a different command that blocks the same way", and it needs no
    // judgement about the command itself.
    let refused = 0;
    const countTail = () => {
        refused += 1;
        return refused >= REPEAT_AT
            ? ` This is refusal #${refused} in this session: rephrasing the same intent will keep `
                + 'failing, so change the approach rather than the wording.'
            : '';
    };
    return ctx.tools.guard((exec) => {
        try {
            const toolName = typeof exec?.name === 'string' ? exec.name : '';
            const args = exec?.arguments;
            if (args === null || typeof args !== 'object') return undefined;
            // A blocking wait costs the turn exactly like a foreground delay, but
            // it carries a ceiling instead of a command, so it is judged first.
            const waiting = waitReason(toolName, args, maxWaitMs);
            if (waiting !== null) {
                note(waiting);
                return `Refusing ${waiting}: it would hold the whole turn. `
                    + `Pass a timeout_ms of ${maxWaitMs} or less, or read the job with `
                    + `job_output({ wait: false }) between steps and decide again.${countTail()}`;
            }
            if (!shellTools.has(toolName)) return undefined;
            // A background job returns at once, so its delay costs nothing.
            if (args.run_in_background === true) return undefined;
            // File contents are not part of this call; do not read or guess them.
            if (typeof args.script_path === 'string' && args.script_path !== '') return undefined;
            const blocking = findBlocking(args.command, minSeconds);
            if (blocking === null) return undefined;
            note(blocking);
            return `Refusing ${blocking}: it would hold the whole turn. `
                + `${guidanceFor(blocking)}${countTail()}`;
        } catch (error) {
            // A detector bug must never block an unrelated command, but it must
            // not vanish either: a silent guard looks like the plugin working.
            note(`a detector error (${error?.message ?? error})`);
            return undefined;
        }
    });
}
