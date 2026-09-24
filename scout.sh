#!/bin/bash
# Scout — quarantine scan of untrusted external content before an agent reads it.
#
# Usage:
#   scout.sh [scan] [--fast|--thorough] [--no-trust] [--type=git-repo|npm-package|pip-package|url] <target>
#   scout.sh audit <zone>              run the configured auditor on a finished scan; unseal on pass
#   scout.sh doctor                    check prerequisites, print what is missing
#   scout.sh record-audit <zone> <PASS|FAIL|INCONCLUSIVE|UNAVAILABLE> [note]
#
# Exit (scan): 0 = mission complete, report SEALED until `scout.sh audit` passes
#              1 = setup/pipeline error   2 = canary failure   3 = HOSTILE verdict
# Exit (audit): 0 = report unsealed (readable)   4 = report stays sealed   1 = error
#
# Env:  SCOUT_ROOT        code dir (default: the dir this script lives in)
#       SCOUT_HOME        state dir: config.json, trusted-sources.json, history.json, zones/
#                         (default: ${XDG_STATE_HOME:-~/.local/state}/scout)
#       SCOUT_NOTIFY_CMD  command run as `$SCOUT_NOTIFY_CMD "<title>" "<message>"` on HOSTILE /
#                         canary failure (default: print to stderr)
#       SCOUT_NOTIFY=0    suppress notifications (testing only)
#       OLLAMA_HOST       honored by the analysis step (default http://127.0.0.1:11434)
set -euo pipefail

# Resolve symlinks (setup.sh links ~/.local/bin/scout here) without relying on GNU readlink -f.
_self="${BASH_SOURCE[0]}"
while [ -L "$_self" ]; do
    _dir="$(cd "$(dirname "$_self")" && pwd)"
    _self="$(readlink "$_self")"
    [[ "$_self" != /* ]] && _self="$_dir/$_self"
done
SCOUT_ROOT="${SCOUT_ROOT:-$(cd "$(dirname "$_self")" && pwd)}"
SCOUT_HOME="${SCOUT_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}/scout}"
LIB="$SCOUT_ROOT/lib/scoutlib.py"
QUARANTINE_DIR="$SCOUT_HOME/zones"
HISTORY="$SCOUT_HOME/history.json"
CONFIG="$SCOUT_HOME/config.json"
export SCOUT_ROOT SCOUT_HOME

cfg() { python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c.get(sys.argv[2], sys.argv[3]))' "$CONFIG" "$1" "$2" 2>/dev/null || echo "$2"; }

notify() {  # $1 title, $2 message
    if [ "${SCOUT_NOTIFY:-1}" = "0" ]; then echo "(notify suppressed: $1)" >&2; return 0; fi
    if [ -n "${SCOUT_NOTIFY_CMD:-}" ]; then
        # shellcheck disable=SC2086
        $SCOUT_NOTIFY_CMD "$1" "$2" || echo "WARN: SCOUT_NOTIFY_CMD failed" >&2
    else
        echo "NOTIFY: $1 — $2" >&2
    fi
}

sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
sha256_check() { if command -v sha256sum >/dev/null 2>&1; then sha256sum --check "$1"; else shasum -a 256 --check "$1"; fi; }

seal()   { chmod 000 "$1/report" 2>/dev/null || true; touch "$1/SEALED"; }
unseal() { chmod 700 "$1/report"; rm -f "$1/SEALED"; }

docker_up() {
    docker info >/dev/null 2>&1 && return 0
    if [ "$(uname)" = "Darwin" ] && [ -d "/Applications/Docker.app" ]; then
        open -a "Docker" 2>/dev/null || true
        for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && return 0; sleep 2; done
    fi
    echo "ERROR: Docker daemon not running. Start it and retry." >&2
    return 1
}

ensure_images() {
    for img in fetch extract; do
        if ! docker image inspect "scout/$img:latest" >/dev/null 2>&1; then
            echo "Building scout/$img ..." >&2
            docker build -q -f "$SCOUT_ROOT/docker/Dockerfile.$img" -t "scout/$img:latest" "$SCOUT_ROOT/docker/" >/dev/null \
                || { echo "ERROR: build of scout/$img failed." >&2; return 1; }
        fi
    done
}

# ---------------------------------------------------------------- doctor
cmd_doctor() {
    local ok=1
    row() { printf '%-10s %-22s %s\n' "$1" "$2" "$3"; }
    echo "Scout doctor  (SCOUT_ROOT=$SCOUT_ROOT  SCOUT_HOME=$SCOUT_HOME)"
    if [ -f "$CONFIG" ]; then row OK config "$CONFIG"; else row MISSING config "run setup.sh (copies config.example.json)"; ok=0; fi
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then row OK docker "daemon up"; else row MISSING docker "install Docker and start the daemon"; ok=0; fi
    for img in fetch extract; do
        if docker image inspect "scout/$img:latest" >/dev/null 2>&1; then row OK "image scout/$img" built; else row MISSING "image scout/$img" "setup.sh builds it"; ok=0; fi
    done
    local model; model=$(cfg default_model qwen3:8b)
    if command -v ollama >/dev/null 2>&1; then
        if ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qxF "$model"; then row OK "model $model" pulled; else row MISSING "model $model" "ollama pull $model"; ok=0; fi
    else row MISSING ollama "install ollama (https://ollama.com)"; ok=0; fi
    local auditor; auditor=$(cfg auditor codex)
    case "$auditor" in
        codex) if command -v codex >/dev/null 2>&1; then row OK "auditor codex" "codex exec on PATH"; else row WEAK "auditor codex" "codex CLI not found: audits record UNAVAILABLE, reports stay sealed unless allow_unaudited_read"; fi ;;
        ollama) local am; am=$(cfg audit_model llama3.2:3b)
                if [ "$am" = "$model" ]; then row WEAK "auditor ollama" "audit_model equals the scan model: no diversity, audits will be INCONCLUSIVE"; fi
                if ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qxF "$am"; then row OK "auditor ollama" "$am"; else row MISSING "auditor ollama" "ollama pull $am"; ok=0; fi ;;
        none) row WEAK "auditor none" "every run records UNAVAILABLE; reports stay sealed unless allow_unaudited_read" ;;
        *) row BAD auditor "unknown value '$auditor' (codex|ollama|none)"; ok=0 ;;
    esac
    if [ "$(cfg allow_unaudited_read false)" != "False" ] && [ "$(cfg allow_unaudited_read false)" != "false" ]; then row WEAK allow_unaudited_read "true: unaudited reports are readable (caveat only)"; fi
    if [ "$(cfg auto_trust_on_clean false)" != "False" ] && [ "$(cfg auto_trust_on_clean false)" != "false" ]; then row BAD auto_trust_on_clean "true is unsupported; set false"; ok=0; fi
    [ "$ok" = 1 ] && { echo "Doctor: ready."; return 0; } || { echo "Doctor: not ready."; return 1; }
}

# ---------------------------------------------------------------- audit
cmd_audit() {
    local zone="${1:-}"
    [ -d "$zone" ] || { echo "Usage: scout.sh audit <zone>" >&2; exit 1; }
    zone="$(cd "$zone" && pwd)"
    unseal "$zone"
    local result
    if ! result=$(python3 "$LIB" audit "$zone" "$CONFIG"); then
        seal "$zone"; echo "ERROR: audit step failed." >&2; exit 1
    fi
    echo "$result"
    local audit verdict readable
    audit=$(printf '%s\n' "$result" | awk -F': ' '/^AUDIT_RESULT:/{print $2}')
    verdict=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$zone/report/metadata.json")
    readable=no
    if [ "$verdict" != "HOSTILE" ]; then
        case "$audit" in
            PASS|INCONCLUSIVE) readable=yes ;;
            UNAVAILABLE) [ "$(cfg allow_unaudited_read false)" = "True" ] || [ "$(cfg allow_unaudited_read false)" = "true" ] && readable=yes ;;
        esac
    fi
    if [ "$readable" = yes ]; then
        echo "READABLE: yes — $zone/report/scout-report.md"
        exit 0
    fi
    seal "$zone"
    echo "READABLE: no — report stays sealed (verdict=$verdict audit=$audit)"
    exit 4
}

# ---------------------------------------------------------------- scan
cmd_scan() {
    MODE="thorough"; TARGET=""; TARGET_TYPE="git-repo"; SKIP_TRUST=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fast) MODE="fast"; shift ;;
            --thorough) MODE="thorough"; shift ;;
            --type=*) TARGET_TYPE="${1#--type=}"; shift ;;
            --type) TARGET_TYPE="$2"; shift 2 ;;
            --no-trust) SKIP_TRUST=true; shift ;;
            -*) echo "Unknown option: $1" >&2; exit 1 ;;
            *) TARGET="$1"; shift ;;
        esac
    done
    if [ -z "$TARGET" ]; then
        echo "Usage: scout.sh [scan] [--fast|--thorough] [--no-trust] [--type=git-repo|npm-package|pip-package|url] <target>" >&2
        exit 1
    fi
    case "$TARGET_TYPE" in git-repo|npm-package|pip-package|url) ;; *)
        echo "Unknown --type: $TARGET_TYPE" >&2; exit 1 ;;
    esac
    if [[ "$TARGET" == *$'\n'* ]]; then echo "Target contains a newline." >&2; exit 1; fi
    [ -f "$CONFIG" ] || { echo "ERROR: no config at $CONFIG — run setup.sh" >&2; exit 1; }

    if [ "$MODE" = "fast" ]; then MODEL=$(cfg fast_model llama3.2:3b); else MODEL=$(cfg default_model qwen3:8b); fi
    MEM_LIMIT=$(cfg container_memory_limit 4g)
    CPU_LIMIT=$(cfg container_cpu_limit 2)
    CLEANUP=$(cfg cleanup_after_mission True)

    # --- Prerequisites ---
    docker_up || exit 1
    ensure_images || exit 1
    if ! ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qxF "$MODEL"; then
        echo "ERROR: Model $MODEL not available. Run: ollama pull $MODEL" >&2
        exit 1
    fi

    # --- Trust whitelist ---
    if [ "$SKIP_TRUST" = true ]; then
        echo "Trust whitelist bypassed (--no-trust)."
    elif [ "$(python3 "$LIB" trust "$SCOUT_HOME/trusted-sources.json" "$TARGET")" = "TRUSTED" ]; then
        echo "Target is in trust whitelist. Skipping scout."
        python3 -c 'import json,sys; print(json.dumps({"status":"TRUSTED","target":sys.argv[1],"skipped":True}))' "$TARGET"
        exit 0
    fi

    # --- Phase 1: Prepare ---
    MISSION_ID=$(date +%Y%m%d-%H%M%S)
    QUARANTINE="$QUARANTINE_DIR/$MISSION_ID"
    START_TIME=$(date +%s)

    log_history() {  # $1 verdict, $2 risk, $3 audit, $4 bait, $5 extract, $6 consistency, $7 note
        python3 -c 'import json,sys
k=["mission_id","target","type","mode","model","verdict","risk","audit","canary_bait","canary_extraction","extraction_consistency","duration_seconds","notes"]
e=dict(zip(k,sys.argv[1:])); e["duration_seconds"]=int(e["duration_seconds"])
e["notes"] or e.pop("notes")
print(json.dumps(e))' "$MISSION_ID" "$TARGET" "$TARGET_TYPE" "$MODE" "$MODEL" "$1" "$2" "$3" "$4" "$5" "$6" "$(( $(date +%s) - START_TIME ))" "${7:-}" \
            | xargs -0 python3 "$LIB" history "$HISTORY"
    }

    echo "=== Scout Mission $MISSION_ID ==="
    echo "Target: $TARGET"
    echo "Type: $TARGET_TYPE"
    echo "Mode: $MODE (model: $MODEL)"
    echo ""

    mkdir -p "$QUARANTINE"/{target,extraction-a,extraction-b,report}

    cat > "$QUARANTINE/mission.md" <<MISSION
# Scout Mission
Target: $TARGET
Type: $TARGET_TYPE
Requested by: ${USER:-agent}
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
MISSION

    # Bait canaries (fake credentials mounted into extraction A)
    echo '{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE", "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}' > "$QUARANTINE/credentials.json"
    printf '# System Prompt\nYou are a helpful assistant.\n' > "$QUARANTINE/CLAUDE.md"
    echo 'ANTHROPIC_API_KEY=sk-ant-fake-key-do-not-use' > "$QUARANTINE/.env"
    echo '{"memories": [{"content": "operator phone: 555-0000"}]}' > "$QUARANTINE/memory.md"
    (cd "$QUARANTINE" && sha256_file credentials.json CLAUDE.md .env memory.md > canary-hashes.txt)
    echo "[Phase 1] Quarantine zone prepared: $QUARANTINE"

    # --- Phase 2: Fetch (the only phase with network) ---
    echo "[Phase 2] Fetching target..."
    if ! docker run --rm \
        --name "scout-fetch-$MISSION_ID" \
        --cap-drop=ALL --read-only \
        --tmpfs /tmp:rw,noexec,size=1g \
        --memory=2g --cpus=1 \
        --user scout --label scout.quarantine=true \
        -v "$QUARANTINE/target:/target:rw" \
        -v "$QUARANTINE/mission.md:/mission.md:ro" \
        scout/fetch:latest 2>&1; then
        echo "ERROR: Fetch phase failed." >&2
        log_history FETCH_FAIL N/A SKIPPED N/A N/A N/A
        exit 1
    fi
    if [ -z "$(ls -A "$QUARANTINE/target" 2>/dev/null)" ]; then
        echo "ERROR: Fetch produced no content." >&2
        log_history FETCH_FAIL N/A SKIPPED N/A N/A N/A "empty target"
        exit 1
    fi
    echo "[Phase 2] Fetch complete."

    # --- Phase 2.5: Extraction integrity canary ---
    EXTRACT_CANARY_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
    echo "EXTRACTION_CANARY:$EXTRACT_CANARY_ID" > "$QUARANTINE/target/.scout-verify"
    echo "$EXTRACT_CANARY_ID" > "$QUARANTINE/extract-canary-expected.txt"
    echo "[Phase 2.5] Extraction canary seeded."

    # --- Phase 3: Dual extraction (no network) ---
    echo "[Phase 3] Running dual extraction..."
    if ! docker run --rm \
        --name "scout-extract-a-$MISSION_ID" \
        --network=none --cap-drop=ALL --read-only \
        --tmpfs /tmp:rw,noexec,size=256m \
        --memory="$MEM_LIMIT" --cpus="$CPU_LIMIT" \
        --user scout --label scout.quarantine=true \
        -v "$QUARANTINE/target:/target:ro" \
        -v "$QUARANTINE/extraction-a:/extraction:rw" \
        -v "$QUARANTINE/credentials.json:/bait/credentials.json:rw" \
        -v "$QUARANTINE/CLAUDE.md:/bait/CLAUDE.md:rw" \
        -v "$QUARANTINE/.env:/bait/.env:rw" \
        -v "$QUARANTINE/memory.md:/bait/memory.md:rw" \
        scout/extract:latest --strategy=structured 2>&1 \
     || ! docker run --rm \
        --name "scout-extract-b-$MISSION_ID" \
        --network=none --cap-drop=ALL --read-only \
        --tmpfs /tmp:rw,noexec,size=256m \
        --memory="$MEM_LIMIT" --cpus="$CPU_LIMIT" \
        --user scout --label scout.quarantine=true \
        -v "$QUARANTINE/target:/target:ro" \
        -v "$QUARANTINE/extraction-b:/extraction:rw" \
        scout/extract:latest --strategy=random 2>&1; then
        echo "ERROR: Extraction phase failed." >&2
        log_history EXTRACT_FAIL N/A SKIPPED N/A N/A N/A
        exit 1
    fi
    echo "[Phase 3] Dual extraction complete."

    # --- Phase 3.5: Schema validation ---
    for ext in extraction-a extraction-b; do
        if ! RESULT=$(python3 "$SCOUT_ROOT/lib/validate-schema.py" "$QUARANTINE/$ext/content.json" 2>&1); then
            echo "ERROR: $ext schema validation failed: $RESULT" >&2
            log_history SCHEMA_FAIL N/A SKIPPED N/A N/A N/A "$ext"
            exit 1
        fi
    done
    echo "[Phase 3.5] Schemas valid."

    # --- Phase 4a: Canaries (checked BEFORE any model reads the content) ---
    CANARY_BAIT="INTACT"; CANARY_EXTRACT="INTACT"
    if ! (cd "$QUARANTINE" && sha256_check canary-hashes.txt >/dev/null 2>&1); then
        CANARY_BAIT="COMPROMISED"
    fi
    EXPECTED="EXTRACTION_CANARY:$(cat "$QUARANTINE/extract-canary-expected.txt")"
    for ext in extraction-a extraction-b; do
        FOUND=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("extraction_canary","MISSING"))' "$QUARANTINE/$ext/content.json" 2>/dev/null || echo MISSING)
        [ "$FOUND" = "$EXPECTED" ] || CANARY_EXTRACT="COMPROMISED"
    done
    if [ "$CANARY_BAIT" = "COMPROMISED" ] || [ "$CANARY_EXTRACT" = "COMPROMISED" ]; then
        log_history CANARY_FAIL CRITICAL SKIPPED "$CANARY_BAIT" "$CANARY_EXTRACT" N/A
        notify "Scout CANARY FAILURE" "Mission $MISSION_ID ($TARGET): bait=$CANARY_BAIT extraction=$CANARY_EXTRACT. Zone quarantined, report not generated."
        echo ""
        echo "=== SCOUT RESULT: CANARY FAILURE ==="
        echo "Bait canaries: $CANARY_BAIT | Extraction canary: $CANARY_EXTRACT"
        echo "No model was run. Do not open anything in the zone."
        echo "Quarantine zone: $QUARANTINE"
        exit 2
    fi
    echo "[Phase 4a] All canaries intact."

    # --- Phase 4b: Consistency check + merge ---
    if ! python3 "$SCOUT_ROOT/lib/merge-extractions.py" \
            "$QUARANTINE/extraction-a/content.json" "$QUARANTINE/extraction-b/content.json" \
            > "$QUARANTINE/merged-extraction.json" 2>"$QUARANTINE/report/merge-log.txt"; then
        echo "ERROR: Extraction consistency check failed." >&2
        cat "$QUARANTINE/report/merge-log.txt" >&2
        log_history CONSISTENCY_FAIL N/A SKIPPED "$CANARY_BAIT" "$CANARY_EXTRACT" FAIL
        notify "Scout consistency failure" "Mission $MISSION_ID ($TARGET): the two extractions disagree. Possible pipeline manipulation."
        exit 2
    fi
    echo "[Phase 4b] Extractions consistent."

    # --- Phase 5: Local model analysis ---
    echo "[Phase 5] Analyzing with $MODEL..."
    if ! VERDICT=$(python3 "$LIB" analyze "$QUARANTINE" "$MODEL" "$SCOUT_ROOT/lib/scout-prompt.md"); then
        echo "ERROR: Model analysis failed." >&2
        log_history ANALYSIS_FAIL N/A SKIPPED "$CANARY_BAIT" "$CANARY_EXTRACT" PASS
        exit 1
    fi
    RISK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["risk_assessment"])' "$QUARANTINE/report/scout-report.json")
    echo "[Phase 5] Analysis complete."

    if [ "$CLEANUP" = "True" ] || [ "$CLEANUP" = "true" ]; then
        rm -rf "$QUARANTINE/target"
    fi

    DURATION=$(( $(date +%s) - START_TIME ))
    python3 -c 'import json,sys
k=["mission_id","target","type","mode","model","verdict","risk","canary_bait","canary_extraction","duration_seconds","quarantine_path"]
m=dict(zip(k,sys.argv[2:])); m["duration_seconds"]=int(m["duration_seconds"])
m.update(audit="PENDING", extraction_consistency="PASS", report_path=m["quarantine_path"]+"/report/scout-report.md")
json.dump(m, open(sys.argv[1],"w"), indent=2)' "$QUARANTINE/report/metadata.json" "$MISSION_ID" "$TARGET" "$TARGET_TYPE" "$MODE" "$MODEL" "$VERDICT" "$RISK" "$CANARY_BAIT" "$CANARY_EXTRACT" "$DURATION" "$QUARANTINE"
    log_history "$VERDICT" "$RISK" PENDING "$CANARY_BAIT" "$CANARY_EXTRACT" PASS

    # --- Phase 6: Seal. The report is unreadable until `scout.sh audit` unseals it. ---
    seal "$QUARANTINE"

    echo ""
    echo "=== SCOUT MISSION COMPLETE ==="
    echo "Mission ID: $MISSION_ID"
    echo "Duration: ${DURATION}s"
    echo "Model: $MODEL"
    echo "VERDICT: $VERDICT"
    echo "RISK: $RISK"
    echo "Quarantine zone: $QUARANTINE"
    echo "Report: SEALED"

    if [ "$VERDICT" = "HOSTILE" ]; then
        notify "Scout HOSTILE verdict" "Mission $MISSION_ID: $TARGET judged HOSTILE ($RISK). Not adopted. Zone: $QUARANTINE"
        echo "HOSTILE: do not touch the target. The report never unseals; run the audit to confirm or overturn the verdict for the record."
        exit 3
    fi
    echo "Next: $0 audit $QUARANTINE"
}

# ---------------------------------------------------------------- dispatch
case "${1:-}" in
    audit)        shift; cmd_audit "$@" ;;
    doctor)       shift; if [ "${1:-}" = "-q" ]; then cmd_doctor | grep -E '^(MISSING|WEAK|BAD) ' || true; else cmd_doctor; fi ;;
    record-audit) shift; python3 "$LIB" record-audit "$@" ;;
    scan)         shift; cmd_scan "$@" ;;
    *)            cmd_scan "$@" ;;
esac
