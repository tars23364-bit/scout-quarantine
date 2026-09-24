#!/bin/bash
# Scout Extract — reads fetched content and produces structured JSON extraction
# Runs inside Docker with NO network. Two strategies: structured and random.
set -euo pipefail

STRATEGY="${1:---strategy=structured}"
STRATEGY="${STRATEGY#--strategy=}"
TARGET="/target"
OUTPUT="/extraction/content.json"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- Utility functions ---

# Safe filename output — escape control chars, limit length
safe_name() {
    echo "$1" | tr -cd '[:print:]' | head -c 255
}

# JSON-quote a string (filenames are attacker-controlled)
jstr() {
    printf '%s' "$1" | jq -Rs .
}

# Check if file is text (not binary)
is_text() {
    file -b --mime-type "$1" 2>/dev/null | grep -q '^text/'
}

# Read file lines safely — no following symlinks outside target
safe_read() {
    local filepath="$1"
    local mode="$2"    # head or tail
    local lines="$3"

    # Resolve and check symlink targets
    local resolved
    resolved=$(readlink -f "$filepath" 2>/dev/null || echo "$filepath")
    case "$resolved" in
        /target/*)
            # OK — within target
            ;;
        *)
            echo "[SYMLINK OUTSIDE TARGET: $filepath -> $resolved]"
            return
            ;;
    esac

    if ! is_text "$filepath"; then
        echo "[BINARY FILE]"
        return
    fi

    local total
    total=$(wc -l < "$filepath" 2>/dev/null || echo "0")

    if [ "$mode" = "head" ]; then
        head -n "$lines" "$filepath" 2>/dev/null
    elif [ "$mode" = "tail" ]; then
        tail -n "$lines" "$filepath" 2>/dev/null
    elif [ "$mode" = "mid" ]; then
        # Read lines 150-350 (overlapping window)
        sed -n '150,350p' "$filepath" 2>/dev/null
    fi
}

# --- Build file tree ---
build_tree() {
    local tree_json="["
    local first=true
    local count=0

    while IFS= read -r -d '' entry; do
        [ $count -ge 200 ] && break

        local relpath="${entry#$TARGET/}"
        local ftype="file"
        local fsize=0
        local symtarget="null"

        if [ -L "$entry" ]; then
            ftype="symlink"
            local target
            target=$(readlink "$entry" 2>/dev/null || echo "unknown")
            symtarget=$(jstr "$(safe_name "$target")")
        elif [ -d "$entry" ]; then
            ftype="dir"
        fi

        if [ -f "$entry" ] && [ ! -L "$entry" ]; then
            fsize=$(stat -c %s "$entry" 2>/dev/null || stat -f %z "$entry" 2>/dev/null || echo 0)
        fi

        local safe_relpath
        safe_relpath=$(safe_name "$relpath")

        if [ "$first" = true ]; then
            first=false
        else
            tree_json+=","
        fi

        tree_json+="{\"path\":$(jstr "$safe_relpath"),\"type\":\"$ftype\",\"size\":$fsize,\"target\":$symtarget}"
        count=$((count + 1))
    done < <(find "$TARGET" -maxdepth 4 -print0 2>/dev/null | sort -z)

    tree_json+="]"
    echo "$tree_json"
}

# --- Suspicious indicators ---
check_suspicious() {
    local symlinks_out="[]"
    local control_chars="[]"
    local hidden_dirs="[]"
    local binary_as_text="[]"
    local oversized="[]"
    local injection_names="[]"

    # Symlinks pointing outside target
    local syms
    syms=$(find "$TARGET" -type l 2>/dev/null | while read -r link; do
        local target
        target=$(readlink -f "$link" 2>/dev/null || echo "")
        case "$target" in
            (/target/*) ;;
            (*) safe_name "$link" ;;
        esac
    done)
    if [ -n "$syms" ]; then
        symlinks_out=$(echo "$syms" | jq -R . | jq -s .)
    fi

    # Filenames with control characters
    local ctrl
    ctrl=$(find "$TARGET" -maxdepth 4 -name '*[[:cntrl:]]*' 2>/dev/null | head -20)
    if [ -n "$ctrl" ]; then
        control_chars=$(echo "$ctrl" | while read -r f; do safe_name "${f#$TARGET/}"; done | jq -R . | jq -s .)
    fi

    # Hidden directories beyond standard
    local hidden
    hidden=$(find "$TARGET" -maxdepth 3 -type d -name '.*' ! -name '.git' ! -name '.github' ! -name '.vscode' ! -name '.gitignore' ! -name '.' 2>/dev/null | head -20)
    if [ -n "$hidden" ]; then
        hidden_dirs=$(echo "$hidden" | while read -r f; do safe_name "${f#$TARGET/}"; done | jq -R . | jq -s .)
    fi

    # Files over 1MB in unexpected locations
    local big
    big=$(find "$TARGET" -type f -size +1M ! -path '*/.git/*' ! -name '*.bin' ! -name '*.dat' ! -name '*.db' 2>/dev/null | head -10)
    if [ -n "$big" ]; then
        oversized=$(echo "$big" | while read -r f; do safe_name "${f#$TARGET/}"; done | jq -R . | jq -s .)
    fi

    # Filenames with injection-like patterns
    local inj
    inj=$(find "$TARGET" -maxdepth 4 2>/dev/null | grep -iE '(IGNORE|INSTRUCTION|PROMPT|SYSTEM|OVERRIDE|INJECT)' | head -20)
    if [ -n "$inj" ]; then
        injection_names=$(echo "$inj" | while read -r f; do safe_name "${f#$TARGET/}"; done | jq -R . | jq -s .)
    fi

    cat <<SUSP
{
  "symlinks_outside_target": $symlinks_out,
  "control_char_filenames": $control_chars,
  "hidden_directories": $hidden_dirs,
  "binary_as_text": $binary_as_text,
  "oversized_files": $oversized,
  "injection_pattern_filenames": $injection_names
}
SUSP
}

# --- Check extraction canary ---
check_extraction_canary() {
    if [ -f "$TARGET/.scout-verify" ]; then
        cat "$TARGET/.scout-verify"
    else
        echo "MISSING"
    fi
}

# --- Strategy: Structured ---
extract_structured() {
    local contents="{}"
    local key_files=""

    # Find key files
    key_files=$(find "$TARGET" -maxdepth 3 \( \
        -iname 'README*' -o -iname 'SKILL.md' -o -iname 'CLAUDE.md' -o \
        -iname 'AGENTS.md' -o -name 'package.json' -o -name 'setup.py' -o \
        -name 'pyproject.toml' -o -name 'Makefile' -o -name 'Dockerfile' -o \
        -name '*.sh' -o -name '.env*' -o -name '.scout-verify' \
    \) -type f 2>/dev/null | head -30)

    # Add random sample of text files under 50KB
    local random_files
    random_files=$(find "$TARGET" -type f -size -50k ! -path '*/.git/*' 2>/dev/null | \
        while read -r f; do is_text "$f" && echo "$f"; done | \
        shuf -n 10 2>/dev/null || true)

    # Combine, deduplicate
    local all_files
    all_files=$(echo -e "$key_files\n$random_files" | sort -u | grep -v '^$')

    # Read each file
    contents="{"
    local first=true
    while IFS= read -r filepath; do
        [ -z "$filepath" ] && continue
        local relpath="${filepath#$TARGET/}"
        local safe_rel
        safe_rel=$(safe_name "$relpath")
        local total
        total=$(wc -l < "$filepath" 2>/dev/null || echo "0")
        local file_content
        file_content=$(safe_read "$filepath" "head" 200)
        local truncated="false"
        [ "$total" -gt 200 ] && truncated="true"

        # Escape content for JSON
        local escaped
        escaped=$(echo "$file_content" | jq -Rs .)

        if [ "$first" = true ]; then
            first=false
        else
            contents+=","
        fi

        contents+="$(jstr "$safe_rel"):{\"lines_read\":\"1-200\",\"content\":$escaped,\"truncated\":$truncated,\"total_lines\":$total}"
    done <<< "$all_files"
    contents+="}"

    echo "$contents"
}

# --- Strategy: Random ---
extract_random() {
    local contents="{}"

    # Pure random sample — 20 text files under 50KB
    local random_files
    random_files=$(find "$TARGET" -type f -size -50k ! -path '*/.git/*' 2>/dev/null | \
        while read -r f; do is_text "$f" && echo "$f"; done | \
        shuf -n 20 2>/dev/null || true)

    # Also check .scout-verify specifically
    if [ -f "$TARGET/.scout-verify" ]; then
        random_files=$(echo -e "$random_files\n$TARGET/.scout-verify")
    fi

    # For files that match known key names, read mid-section (lines 150-350)
    # For everything else, read tail
    contents="{"
    local first=true
    while IFS= read -r filepath; do
        [ -z "$filepath" ] && continue
        local relpath="${filepath#$TARGET/}"
        local safe_rel
        safe_rel=$(safe_name "$relpath")
        local total
        total=$(wc -l < "$filepath" 2>/dev/null || echo "0")
        local file_content
        local lines_desc

        # Check if this is a known key file — use mid-section
        local basename
        basename=$(basename "$filepath")
        case "$basename" in
            README*|SKILL.md|CLAUDE.md|package.json|setup.py|Makefile|Dockerfile)
                file_content=$(safe_read "$filepath" "mid" 200)
                lines_desc="150-350"
                ;;
            *)
                file_content=$(safe_read "$filepath" "tail" 200)
                lines_desc="tail-200"
                ;;
        esac

        local truncated="false"
        [ "$total" -gt 200 ] && truncated="true"

        local escaped
        escaped=$(echo "$file_content" | jq -Rs .)

        if [ "$first" = true ]; then
            first=false
        else
            contents+=","
        fi

        contents+="$(jstr "$safe_rel"):{\"lines_read\":\"$lines_desc\",\"content\":$escaped,\"truncated\":$truncated,\"total_lines\":$total}"
    done <<< "$random_files"
    contents+="}"

    echo "$contents"
}

# --- Main ---

echo "Scout extract ($STRATEGY) starting..." >&2

TREE=$(build_tree)
SUSPICIOUS=$(check_suspicious)
CANARY=$(check_extraction_canary)
FILE_COUNT=$(find "$TARGET" -type f ! -path '*/.git/*' 2>/dev/null | wc -l)
TOTAL_SIZE=$(find "$TARGET" -type f ! -path '*/.git/*' -exec stat -c %s {} + 2>/dev/null | awk '{s+=$1}END{print s+0}' || echo "0")

case "$STRATEGY" in
    structured)
        CONTENTS=$(extract_structured)
        ;;
    random)
        CONTENTS=$(extract_random)
        ;;
    *)
        echo "ERROR: Unknown strategy: $STRATEGY" >&2
        exit 1
        ;;
esac

# Build final JSON
cat > "$OUTPUT" <<ENDJSON
{
  "schema_version": "1.0",
  "strategy": "$STRATEGY",
  "timestamp": "$TIMESTAMP",
  "file_tree": $TREE,
  "file_contents": $CONTENTS,
  "suspicious_indicators": $SUSPICIOUS,
  "extraction_canary": "$CANARY",
  "file_count": $FILE_COUNT,
  "total_size_bytes": $TOTAL_SIZE
}
ENDJSON

# Validate JSON
if jq empty "$OUTPUT" 2>/dev/null; then
    echo "Scout extract ($STRATEGY) complete — valid JSON." >&2
else
    echo "ERROR: Output JSON is invalid!" >&2
    exit 1
fi
