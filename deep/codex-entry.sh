#!/bin/sh
# Entrypoint of the codex reviewer box. If the host passed SCOUT_CODEX_AUTH_B64 (by NAME, via
# `docker run -e`), decode it into $CODEX_HOME/auth.json on the tmpfs HOME, drop the variable,
# and exec codex. The host builds that payload WITHOUT the refresh token (deeplib.py
# codex-box-auth), so nothing in the box can refresh, and so nothing in the box can rotate the
# host's login. The file dies with the container.
set -eu
umask 077
mkdir -p "$CODEX_HOME"
if [ -n "${SCOUT_CODEX_AUTH_B64:-}" ]; then
    printf '%s' "$SCOUT_CODEX_AUTH_B64" | base64 -d > "$CODEX_HOME/auth.json"
    unset SCOUT_CODEX_AUTH_B64
fi
# The host-computed output schema (trusted), for `--output-schema "$HOME/output-schema.json"`.
if [ -n "${SCOUT_OUTPUT_SCHEMA_B64:-}" ]; then
    printf '%s' "$SCOUT_OUTPUT_SCHEMA_B64" | base64 -d > "$HOME/output-schema.json"
    unset SCOUT_OUTPUT_SCHEMA_B64
fi
# A config that is empty of house state: no MCP servers, no project trust, no notify hooks.
: > "$CODEX_HOME/config.toml"
exec codex "$@"
