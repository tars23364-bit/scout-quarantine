#!/usr/bin/env python3
"""Add coverage metadata inside the existing offline extractor, never on the host.

Sampling is unchanged. The census uses the extractor's text/* MIME definition,
excludes .git and the exact pipeline canary, and never follows symlinks.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def annotate(data, root):
    root = Path(root)
    inventory = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.git' and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink() or not p.is_file() or rel == '.scout-verify':
                continue
            mime = subprocess.run(['file', '-b', '--mime-type', '--', str(p)],
                                  check=True, capture_output=True, text=True).stdout.strip()
            if mime.startswith('text/'):
                inventory[rel] = p.stat().st_size
    data['text_inventory'] = dict(sorted(inventory.items()))
    for path, entry in data['file_contents'].items():
        # Sanitized/colliding names cannot establish identity: fail closed below
        # unless the excerpt exactly matches the bytes at this regular text path.
        if path not in inventory:
            continue
        raw = (root / path).read_bytes()
        lines = raw.split(b'\n')
        if lines[-1] == b'':
            lines.pop()
        lengths = [len(line) + 1 for line in lines]
        if raw and not raw.endswith(b'\n'):
            lengths[-1] -= 1
        mode = entry.get('lines_read')
        if mode == 'tail-200':
            lo, hi = max(0, len(lines) - 200), len(lines)
        elif mode in ('1-200', '150-350'):
            lo, hi = (0, 200) if mode == '1-200' else (149, 350)
            lo, hi = min(lo, len(lines)), min(hi, len(lines))
        else:
            continue
        start, end = sum(lengths[:lo]), sum(lengths[:hi])
        # Shell command substitution drops trailing newlines; echo adds one.
        expected = raw[start:end].rstrip(b'\n') + b'\n'
        if expected != entry.get('content', '').encode('utf-8'):
            continue
        entry.update(source_path=path, byte_start=start, byte_end=end)
    return data


if __name__ == '__main__':
    output = Path(sys.argv[1])
    data = annotate(json.loads(output.read_text()), sys.argv[2])
    output.write_text(json.dumps(data, indent=2) + '\n')
