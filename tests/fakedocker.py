#!/usr/bin/env python3
"""A fake `docker` for the session-driver tests (tests/test_p2.py). It logs every call to
$FAKE_DOCKER_LOG and plays a reviewer CLI on `docker exec`:

  FAKE_MODE=lazy     turn 1 Reads only the first half of every box file; a turn whose stdin is a
                     host repair message Reads exactly the ranges it names
  FAKE_MODE=never    every turn Reads only the first half (repair never completes)
  FAKE_MODE=sleep    the CLI hangs (timeout path)
  FAKE_MODE=crash    the CLI exits 137 with no output (box crash path)

Claude turns emit stream-json with numbered Read results; codex turns emit exec --json events
with `nl -ba ... | sed -n` commands. The report is a minimal object (the driver does not judge it).
"""
import json
import os
import re
import sys
import time
from pathlib import Path

LOG = Path(os.environ["FAKE_DOCKER_LOG"])
PD = Path(os.environ.get("FAKE_PAIR", "/nonexistent"))
MODE = os.environ.get("FAKE_MODE", "lazy")


def log(argv):
    with open(LOG, "a") as f:
        f.write(json.dumps(argv) + "\n")


def lines_of(rel):
    t = (PD / "box" / "repo" / rel).read_text()
    ls = t.split("\n")
    return ls[:-1] if t.endswith("\n") else ls


def want_ranges(prompt: str):
    if "HOST CHECK" not in prompt or MODE == "never":
        files = json.loads((PD / "manifest.json").read_text())["files"]
        return {f: [(1, max(1, len(lines_of(f)) // 2))] for f in files if lines_of(f)}
    out = {}
    for ln in prompt.splitlines():
        m = re.match(r"^(\S+): lines (.+?) \[", ln)
        if m:
            out[m.group(1)] = [tuple(int(x) for x in r.split("-")) for r in m.group(2).split(", ")]
    return out


def claude(prompt):
    ev = [{"type": "system", "subtype": "init", "tools": ["Glob", "Grep", "Read", "StructuredOutput"], "mcp_servers": []}]
    n = 0
    for rel, ranges in want_ranges(prompt).items():
        ls = lines_of(rel)
        for a, b in ranges:
            n += 1
            body = "\n".join(f"{i}\t{ls[i - 1]}" for i in range(a, min(b, len(ls)) + 1))
            ev.append({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": f"t{n}", "name": "Read",
                                                                     "input": {"file_path": f"/repo/{rel}", "offset": a}}]}})
            ev.append({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": f"t{n}",
                                                                "content": body}]}})
    ev.append({"type": "result", "subtype": "success", "is_error": False, "total_cost_usd": 0.01,
               "structured_output": {"schema_version": "deep-report/2"}})
    print("\n".join(json.dumps(e) for e in ev))


def codex(prompt):
    ev = [{"type": "thread.started", "thread_id": "11111111-2222-3333-4444-555555555555"}, {"type": "turn.started"}]
    n = 0
    for rel, ranges in want_ranges(prompt).items():
        ls = lines_of(rel)
        # as instructed: at most 200 lines per command, so no output is cut by codex
        chunks = [(x, min(x + 199, b)) for a, b in ranges for x in range(a, b + 1, 200)]
        for a, b in chunks:
            n += 1
            out = "\n".join(f"{i:6d}\t{ls[i - 1]}" for i in range(a, min(b, len(ls)) + 1))
            ev.append({"type": "item.completed", "item": {"id": f"item_{n}", "type": "command_execution",
                                                          "command": f"/usr/bin/bash -lc \"nl -ba /repo/{rel} | sed -n '{a},{b}p'\"",
                                                          "aggregated_output": out, "exit_code": 0, "status": "completed"}})
    ev.append({"type": "item.completed", "item": {"id": "item_0", "type": "agent_message", "text": "{}"}})
    ev.append({"type": "turn.completed", "usage": {}})
    print("\n".join(json.dumps(e) for e in ev))


def main():
    argv = sys.argv[1:]
    log(argv)
    if argv[:1] == ["exec"]:
        prompt = sys.stdin.read()
        if "put-auth" in argv or "put-schema" in argv:
            return 0
        if MODE == "sleep":
            time.sleep(30)
        if MODE == "crash":
            return 137
        if "claude" in argv:
            claude(prompt)
        else:
            codex(prompt)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
