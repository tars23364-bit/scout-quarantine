# Setup

## Prerequisites

| Need | Why | Check |
|---|---|---|
| Docker (daemon running) | fetch + extract containers | `docker info` |
| ollama | the scan model runs on the host | `ollama --version` |
| ~6–8 GB free RAM | qwen3:8b; use `--model llama3.2:3b` on small machines | |
| Python 3.9+ | host helpers | `python3 --version` |
| bash 4+ | orchestrator | macOS ships 3.2 and it works; `brew install bash` is nicer |
| Codex CLI (optional) | strongest auditor tier | `codex --version` |

Linux and macOS. On macOS with Docker Desktop, `scout` starts the app if the daemon is down.

## The one command

```bash
./setup.sh                       # default model qwen3:8b
./setup.sh --model llama3.2:3b   # smaller machine
./setup.sh --no-pull             # you'll pull the model yourself
SCOUT_HOME=/srv/scout ./setup.sh # custom state dir
```

It creates `$SCOUT_HOME` (mode 700), writes `config.json` from the example (or adds missing
keys to an existing one, never overwriting your values), creates an empty trust list and
history, builds `scout/fetch` and `scout/extract`, pulls the scan model if ollama is present,
and links `scout` into `~/.local/bin`. It ends with `scout doctor`.

## Notifications

Scout calls `$SCOUT_NOTIFY_CMD "<title>" "<message>"` on a HOSTILE verdict or a canary failure.
Default is a line on stderr. Point it at whatever pages you:

```bash
export SCOUT_NOTIFY_CMD="$HOME/bin/notify"        # any script taking title, message
export SCOUT_NOTIFY_CMD="ntfy publish my-topic"    # etc.
```

## Choosing the auditor

See `audit/README.md`. Short version: `codex` if you have it, `ollama` with a second model
family if you are offline, `none` only if you accept that every report stays sealed until a
human looks.

## Updating

`git pull && ./setup.sh`. Images rebuild only when missing; force with
`docker rmi scout/fetch scout/extract && ./setup.sh`.

## Uninstall

```bash
rm ~/.local/bin/scout
docker rmi scout/fetch scout/extract
rm -rf "$SCOUT_HOME"          # zones, history, trust list
```
