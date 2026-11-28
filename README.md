# dsh-sleep-guard

[![test](https://github.com/guagua159/dsh-sleep-guard/actions/workflows/test.yml/badge.svg)](https://github.com/guagua159/dsh-sleep-guard/actions/workflows/test.yml)

A DeepSeek Harness bundle that refuses shell commands and blocking waits that would hold the whole turn, and points the agent at background jobs instead.

The agent cannot act while a foreground command is running. `sleep 300`, `tail -f`, and `npm run dev` each hold the turn for minutes or forever, so the work they wait for cannot overlap with anything else. This plugin denies those calls with a `ctx.tools.guard()`: the decision is synchronous, it lands after the extensible pre-execute policy, and no later listener can turn the refusal back into permission — so registration order does not matter. The alternative is named in the message.

## What it refuses

| Command | Condition |
| --- | --- |
| `sleep` | 20 seconds or more, including `20s`, `2m`, `1h`, `1d` suffixes and absolute paths such as `/usr/bin/sleep` |
| `Start-Sleep` | 20 seconds or more, in the flag form (`-Seconds 60`, `-Milliseconds:30000`, abbreviable to `-s` / `-m`) and the positional form (`Start-Sleep 60`, `Sleep 60`) |
| `tail` | `-f`, `-F`, `--follow`, `--follow=name` |
| `ping`, `ping6` | runs until interrupted: on MSYS/Linux any call without `-c N`, on Windows only `-t`. A bare Windows `ping host` sends four echoes and returns in about 3 s, so it is allowed; `-h`, `--help`, `-V`, and `--version` print and return everywhere |
| `watch` | always, except `--version` / `--help` |
| `journalctl` | `-f`, `--follow` |
| `docker logs`, `docker compose logs`, `docker-compose logs`, `kubectl logs` | `-f`, `--follow`; compose global options (`-f box.yml`, `-p proj`) do not shift the verb out of view |
| `vite` | except `build` and `optimize`, which exit |
| `nodemon`, `webpack serve` | always, except `--version` / `--help` |
| `npm`/`pnpm`/`yarn`/`bun` `start`, `dev`, `serve`, `watch`, `run <one of those>` | always |
| `job_output` | `wait: true` with `timeout_ms` above the wait bound (5 minutes by default) |
| `wait_agent` | `timeout_ms` above the wait bound (5 minutes by default) |

Commands are split on `&&`, `||`, `;`, `|`, `&`, and line breaks — including a lone carriage return — before each segment is checked. A segment backgrounded with `&` returns immediately, so it is allowed: `sleep 300 &` costs nothing. Leading `VAR=value` assignments, wrappers such as `sudo`, `env`, `nohup`, `time`, `nice`, `stdbuf`, `command`, `exec`, and `busybox`, and command runners (`npx`, `bunx`, `pnpx`, `pnpm dlx`, `yarn exec`) are stepped over together with their own options, so `sudo -u root sleep 300` and `npx vite` are still seen. Heredoc bodies are treated as file contents, not commands; `<<` inside arithmetic (`x=$((1<<n))`) is a bit shift and opens nothing. Quoted text is stripped first, so `echo "sleep 240"` is allowed — but an unpaired quote stays literal text, so `git commit -m don't care; sleep 300` no longer hides the sleep.

A blocking wait spends the turn exactly like a foreground delay, so the two wait tools are bounded the same way. `job_output({ wait: true })` and `wait_agent` return as soon as their condition is met, so their `timeout_ms` is a ceiling rather than a planned delay — the limit is therefore generous (5 minutes) and does not forbid waiting. Exceeding it is refused with an instruction to shorten the ceiling or to read with `wait: false` between steps. `job_output` without `wait: true` returns at once and is never refused. The judge sees only the call, so a wait on a job that has already settled is refused too; the retry with a shorter ceiling then returns the output immediately.

## What it leaves alone

- `run_in_background: true` — the command is meant to outlive the step.
- A non-empty `script_path` — the contents are not part of this call and are not read.
- Tools other than `bash`, `pwsh`, `pwsh_persistent`, `shell`, and `ops_bash`, apart from the two bounded wait tools. `bash` and `pwsh` also cover the persistent variants, which register under the same names and take no `run_in_background`. `ops_bash` comes from the separate [dsh-ops](https://www.npmjs.com/package/dsh-ops) package; `pwsh_persistent` and `shell` are not registered by any shipped package. All three names are kept for profiles that do install a matching tool and never match otherwise.
- Anything the detector throws on. Every path fails open: a guard bug must never block an unrelated command. The failure is logged through `ctx.logger.warn` so a broken detector does not look like a working guard. Refusal logging is bounded: at most 100 lines per mount and at most one line per second, with the count of suppressed lines reported on the next line that is written. A guard firing in a loop cannot flood the session log.

It is hygiene, not a security boundary. Destructive-command analysis stays with a dedicated tool such as cc-safety-net, which parses shell structure far more thoroughly than this package tries to.

## Install

Not on npm yet, so there is no `dsh plugin add dsh-sleep-guard` that resolves. Clone the repository next to your profile and link it instead:

```sh
git clone https://github.com/guagua159/dsh-sleep-guard ~/.dsh/local-plugins/dsh-sleep-guard
```

Then record it as a dependency of the profile:

```json
{ "dependencies": { "dsh-sleep-guard": "link:../../local-plugins/dsh-sleep-guard" } }
```

and add `dsh-sleep-guard` to `dsh.profile.bundles`. The path in `link:` is relative to the profile directory; adjust the number of `..` segments if you cloned elsewhere. Link rather than copy: a `link:` dependency points at the one checkout, so edits and `git pull` are picked up, while `file:` would install a second copy that nothing keeps in sync.

Restart DeepSeek Harness afterwards — an installed package only loads a fresh JavaScript module generation on restart.

## Configure

Three values are adjustable from the patch layer; each keeps its shipped default when omitted, and a malformed value falls back to it rather than disabling the guard.

```yaml
- insert:
    - id: sleep-guard
      name: dsh-sleep-guard
      config:
        minSeconds: 60                                    # default 20
        maxWaitMs: 600000                                 # default 300000
        shellTools: ['bash', 'pwsh', 'shell']             # default: bash, pwsh, pwsh_persistent, shell, ops_bash
```

`minSeconds` is the shortest foreground delay worth refusing. `maxWaitMs` is the longest single blocking wait allowed, in milliseconds, for `job_output({ wait: true })` and `wait_agent`. `shellTools` replaces — not extends — the built-in list, so name every tool that carries a `command` argument in your profile. The settings are read once when the row mounts, so a change takes effect after a restart.

## Limits

Detection is pattern-based, not a shell parser. These forms are **not** refused:

```sh
bash -c "sleep 300"
sh -c "tail -f x"
eval "sleep 300"
xargs sleep 300
find . -exec sleep 300 \;
(sleep 300)
if true; then sleep 300; fi
while true; do sleep 30; done
$(sleep 300)
`sleep 300`
timeout 10 sleep 300
```

Nested quoting, command substitution, subshells, and control-flow blocks all hide the command from a per-segment regex. Closing that gap needs an AST walker over a real shell parser; this package stays dependency-free, so the gap is documented instead of papered over.

Two further bounds apply, both failing open. A command longer than 64 KiB is analyzed only up to that cut, since real calls average a few hundred characters and scanning a megabyte costs milliseconds per tool call. A heredoc with no terminator swallows the lines after it in real shells too, so `echo hi << x` followed by `sleep 300` is allowed: bash treats the sleep as file content.

`tail -f --pid=N` is refused on purpose: it ends only when the watched process exits, which may be never or an hour from now.

## Test

```sh
node test/test.mjs
```

253 cases across detection, guard exemptions, config handling, blocked-wait bounds, logging bounds, and a false-positive watch list; exit code 0 means all pass. `test/ab.mjs` measures the foreground-versus-background wall-clock difference and the guard's own per-call cost.
## License

MIT
