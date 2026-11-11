#!/bin/bash
# Scout Fetch — clones/downloads target into /target/
# Runs inside Docker with network access. Does nothing else.
set -euo pipefail

MISSION="/mission.md"

if [ ! -f "$MISSION" ]; then
    echo "ERROR: No mission.md found" >&2
    exit 1
fi

# Parse target URL from mission file
TARGET=$(grep -oP '(?<=Target: ).*' "$MISSION" | tr -d '[:space:]')
TYPE=$(grep -oP '(?<=Type: ).*' "$MISSION" | tr -d '[:space:]')

if [ -z "$TARGET" ]; then
    echo "ERROR: No target URL in mission.md" >&2
    exit 1
fi

echo "Scout fetch: $TYPE — $TARGET"

case "$TYPE" in
    git-repo)
        # Shallow clone, no checkout hooks
        git clone --depth 1 --no-checkout "$TARGET" /tmp/clone 2>&1
        # Move contents without executing any hooks
        cd /tmp/clone
        git config core.hooksPath /dev/null
        git checkout HEAD -- . 2>&1
        cp -r /tmp/clone/. /target/
        rm -rf /tmp/clone
        ;;
    npm-package)
        cd /tmp
        curl -sL "https://registry.npmjs.org/$TARGET/latest" -o meta.json
        TARBALL=$(cat meta.json | grep -oP '"tarball":\s*"\K[^"]+' | head -1)
        if [ -n "$TARBALL" ]; then
            curl -sL "$TARBALL" -o package.tgz
            tar xzf package.tgz -C /target/ --strip-components=1
        else
            echo "ERROR: Could not find tarball URL" >&2
            exit 1
        fi
        ;;
    pip-package)
        cd /tmp
        # Accepts "name" (latest) or "name==version" (that exact release).
        PKG_NAME="${TARGET%%==*}"
        PKG_VER=""
        case "$TARGET" in *==*) PKG_VER="${TARGET#*==}" ;; esac
        if ! printf '%s' "$PKG_NAME" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]*$' \
           || { [ -n "$PKG_VER" ] && ! printf '%s' "$PKG_VER" | grep -qE '^[A-Za-z0-9][A-Za-z0-9.!+_-]*$'; }; then
            echo "ERROR: pip target must be name or name==version" >&2
            exit 1
        fi
        if [ -n "$PKG_VER" ]; then
            META_URL="https://pypi.org/pypi/$PKG_NAME/$PKG_VER/json"
        else
            META_URL="https://pypi.org/pypi/$PKG_NAME/json"
        fi
        curl -sfL "$META_URL" -o meta.json || { echo "ERROR: PyPI has no such package or release: $TARGET" >&2; exit 1; }
        # Prefer the source archive; fall back to a wheel (pure-python first) when a release ships none.
        PICK=$(python3 -c "
import json
urls = json.load(open('meta.json'))['urls']
s = [u for u in urls if u['packagetype'] == 'sdist']
w = [u for u in urls if u['packagetype'] == 'bdist_wheel']
w.sort(key=lambda u: 0 if u['filename'].endswith('-none-any.whl') else 1)
u = (s or w or [None])[0]
print((u['packagetype'] + ' ' + u['url']) if u else '')
" 2>/dev/null)
        PICK_TYPE="${PICK%% *}"
        PICK_URL="${PICK#* }"
        if [ "$PICK_TYPE" = "sdist" ]; then
            echo "Scout fetch: source archive $PICK_URL"
            curl -sfL "$PICK_URL" -o package.tar.gz
            tar xzf package.tar.gz -C /target/ --strip-components=1
        elif [ "$PICK_TYPE" = "bdist_wheel" ]; then
            echo "Scout fetch: no source archive, using wheel $PICK_URL"
            curl -sfL "$PICK_URL" -o package.whl
            unzip -q -o package.whl -d /target/
        else
            echo "ERROR: release has neither a source archive nor a wheel" >&2
            exit 1
        fi
        ;;
    url)
        curl -sL "$TARGET" -o /target/downloaded-content
        # An archive is unpacked in place (inside this container only) so the extract
        # stage sees files, not one binary blob; anything else stays as downloaded.
        case "$(file -b --mime-type /target/downloaded-content 2>/dev/null)" in
            application/zip)
                mkdir -p /tmp/unpack && unzip -q -o /target/downloaded-content -d /tmp/unpack \
                    && rm -f /target/downloaded-content && cp -r /tmp/unpack/. /target/ && rm -rf /tmp/unpack ;;
            application/gzip|application/x-gzip|application/x-tar)
                mkdir -p /tmp/unpack && tar xf /target/downloaded-content -C /tmp/unpack \
                    && rm -f /target/downloaded-content && cp -r /tmp/unpack/. /target/ && rm -rf /tmp/unpack ;;
        esac
        ;;
    *)
        # Default: try git clone
        git clone --depth 1 --no-checkout "$TARGET" /tmp/clone 2>&1
        cd /tmp/clone
        git config core.hooksPath /dev/null
        git checkout HEAD -- . 2>&1
        cp -r /tmp/clone/. /target/
        rm -rf /tmp/clone
        ;;
esac

echo "Scout fetch complete."
