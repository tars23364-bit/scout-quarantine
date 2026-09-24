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
        curl -sL "https://pypi.org/pypi/$TARGET/json" -o meta.json
        SDIST=$(python3 -c "import json; d=json.load(open('meta.json')); urls=d['urls']; s=[u for u in urls if u['packagetype']=='sdist']; print(s[0]['url'] if s else '')" 2>/dev/null)
        if [ -n "$SDIST" ]; then
            curl -sL "$SDIST" -o package.tar.gz
            tar xzf package.tar.gz -C /target/ --strip-components=1
        else
            echo "ERROR: Could not find sdist URL" >&2
            exit 1
        fi
        ;;
    url)
        curl -sL "$TARGET" -o /target/downloaded-content
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
