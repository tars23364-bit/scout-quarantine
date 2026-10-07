#!/bin/sh
# Entrypoint of the codex box image (P2: session boxes).
#
#   idle         keep the box up; the host drives each turn with `docker exec ... codex exec`
#                (and `codex exec resume <thread>` for a host repair turn). This process holds
#                no credential.
#   put-auth     stdin = base64 of the box auth.json, built in HOST memory with the access token
#                and an EMPTY refresh token (deeplib.py codex-box-auth), so nothing in the box can
#                refresh or rotate the host's login. Written to $CODEX_HOME/auth.json (0600) on the
#                tmpfs HOME, with an empty config.toml (no MCP servers, no project trust, no
#                notify hooks). It arrives over stdin, never as an env var, so it is not in
#                `docker inspect`, and it dies with the container.
#   put-schema   stdin = the host-computed output schema -> $HOME/output-schema.json
#   (anything else) exec codex with those arguments, e.g. `--version`.
set -eu
umask 077
case "${1:-}" in
    idle)
        exec sleep infinity ;;
    put-auth)
        mkdir -p "$CODEX_HOME"
        base64 -d > "$CODEX_HOME/auth.json"
        : > "$CODEX_HOME/config.toml"
        exit 0 ;;
    put-schema)
        cat > "$HOME/output-schema.json"
        exit 0 ;;
esac
mkdir -p "$CODEX_HOME"
exec codex "$@"
