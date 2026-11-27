# dsh-sleep-guard

A DeepSeek Harness bundle that refuses shell commands that would block the whole turn, and points the agent at background jobs instead.

The agent cannot act while a foreground command is running. `sleep 300`, `tail -f`, and `npm run dev` each hold the turn for minutes or forever, so the work they wait for cannot overlap with anything else. This plugin denies those calls at `tools/pre-execute`, where the refusal is immediate and the alternative is named in the message.

## What it refuses

| Command | Condition |
| --- | --- |
| `sleep` | 20 seconds or more, including `20s`, `2m`, `1h`, `1d` suffixes and absolute paths such as `/usr/bin/sleep` |
| `tail` | `-f`, `-F`, `--follow`, `--follow=name` |
| `ping` | no count (`-c N` on MSYS/Linux, `-n N` on Windows); a bare `-t`, `-w`, or `-l` does not bound it |
| `watch` | always |
| `journalctl` | `-f`, `--follow` |
| `docker logs`, `docker compose logs`, `docker-compose logs`, `kubectl logs` | `-f`, `--follow` |
| `vite`, `nodemon`, `webpack serve` | always |
| `npm`/`pnpm`/`yarn` `start`, `run dev`, `run serve`, `run start`, `run watch` | always |

Commands are split on `&&`, `||`, `;`, `|`, and newlines before each segment is checked, and leading `VAR=value` assignments plus wrappers such as `sudo`, `env`, `nohup`, `time`, and `command` are skipped. Quoted text is stripped first, so `echo "sleep 240"` is allowed.

## What it leaves alone

- `run_in_background: true` — the command is meant to outlive the step.
- A non-empty `script_path` — the contents are not part of this call and are not read.
- Tools other than `bash`, `pwsh`, `pwsh_persistent`, `shell`, and `ops_bash`. That last one comes from the separate [dsh-ops](https://www.npmjs.com/package/dsh-ops) package; the name is kept for profiles that install it and never matches otherwise.
- Anything the detector throws on. Every path fails open: a guard bug must never block an unrelated command.

It is hygiene, not a security boundary. Destructive-command analysis stays with a dedicated tool such as cc-safety-net, which parses shell structure far more thoroughly than this package tries to.

## Install

```sh
dsh plugin --profile <name> add dsh-sleep-guard
```

Or point a profile at a local directory:

```json
{ "dependencies": { "dsh-sleep-guard": "link:../../local-plugins/dsh-sleep-guard" } }
```

Then add `dsh-sleep-guard` to `dsh.profile.bundles`.

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

Nested quoting, command substitution, subshells, and control-flow blocks all hide the command from a per-segment regex. Closing that gap needs an AST walker over [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), which this package deliberately avoids to stay dependency-free.

`tail -f --pid=N` is refused on purpose: it ends only when the watched process exits, which may be never or an hour from now.

## Test

```sh
node test/test.mjs
```

118 cases across detection, handler exemptions, and a false-positive watch list; exit code 0 means all pass. `test/ab.mjs` measures the foreground-versus-background wall-clock difference and the guard's own per-call cost.

## License

MIT
