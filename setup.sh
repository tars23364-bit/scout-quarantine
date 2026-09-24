#!/bin/bash
# Scout setup — builds the two images, pulls the scan model, writes the state dir, links `scout`.
# Usage: ./setup.sh [--model <name>] [--no-pull] [--bin-dir <dir>]
# Env:   SCOUT_HOME (state dir; default ${XDG_STATE_HOME:-~/.local/state}/scout)
set -euo pipefail
SCOUT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOUT_HOME="${SCOUT_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}/scout}"
BIN_DIR="$HOME/.local/bin"
PULL=1; MODEL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --model) MODEL="$2"; shift 2 ;;
        --no-pull) PULL=0; shift ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
export SCOUT_ROOT SCOUT_HOME

echo "Scout setup: code=$SCOUT_ROOT state=$SCOUT_HOME"
mkdir -p "$SCOUT_HOME/zones"
chmod 700 "$SCOUT_HOME"

# --- config: create from the example, or add any keys the example has that the config lacks ---
if [ ! -f "$SCOUT_HOME/config.json" ]; then
    cp "$SCOUT_ROOT/config.example.json" "$SCOUT_HOME/config.json"
    echo "wrote $SCOUT_HOME/config.json"
else
    python3 - "$SCOUT_ROOT/config.example.json" "$SCOUT_HOME/config.json" <<'PY'
import json, sys
ex, cur = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
added = [k for k in ex if k not in cur]
for k in added: cur[k] = ex[k]
if added:
    json.dump(cur, open(sys.argv[2], "w"), indent=2); open(sys.argv[2], "a").write("\n")
    print("config: added missing keys " + ", ".join(added))
else:
    print("config: up to date")
PY
fi
if [ -n "$MODEL" ]; then
    python3 - "$SCOUT_HOME/config.json" "$MODEL" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])); c["default_model"] = sys.argv[2]
json.dump(c, open(sys.argv[1], "w"), indent=2); open(sys.argv[1], "a").write("\n")
PY
fi
[ -f "$SCOUT_HOME/trusted-sources.json" ] || printf '{\n  "sources": [],\n  "registries": ["registry.npmjs.org", "pypi.org"]\n}\n' > "$SCOUT_HOME/trusted-sources.json"
[ -f "$SCOUT_HOME/history.json" ] || echo '[]' > "$SCOUT_HOME/history.json"

# --- docker images ---
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    for img in fetch extract; do
        echo "building scout/$img ..."
        docker build -q -f "$SCOUT_ROOT/docker/Dockerfile.$img" -t "scout/$img:latest" "$SCOUT_ROOT/docker/" >/dev/null
    done
else
    echo "docker: daemon not reachable — images not built (start Docker, re-run setup.sh)"
fi

# --- scan model ---
model=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["default_model"])' "$SCOUT_HOME/config.json")
if command -v ollama >/dev/null 2>&1; then
    if ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qxF "$model"; then
        echo "model $model: present"
    elif [ "$PULL" = 1 ]; then
        echo "pulling $model (several GB) ..."; ollama pull "$model"
    else
        echo "model $model: missing (--no-pull given) — run: ollama pull $model"
    fi
else
    echo "ollama: not installed — https://ollama.com ; then: ollama pull $model"
fi

# --- `scout` on PATH ---
mkdir -p "$BIN_DIR"
ln -sf "$SCOUT_ROOT/scout.sh" "$BIN_DIR/scout"
echo "linked $BIN_DIR/scout -> $SCOUT_ROOT/scout.sh"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "NOTE: $BIN_DIR is not on your PATH" ;; esac

echo
"$SCOUT_ROOT/scout.sh" doctor || true
echo
echo "Auditor: config 'auditor' is '$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("auditor","codex"))' "$SCOUT_HOME/config.json")'. See audit/README.md for the tiers."
echo "Agent hookup: see plugin/ (Claude Code) — the skill calls 'scout' on PATH."
