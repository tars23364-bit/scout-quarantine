"""Test fixture: a finished pair directory built through the real CLI steps (stage, preflight,
bait, prepare, box-prompt), plus fabricated reviewer evidence (stream / events / proxy log) and a
valid deep-report/2 object that each test then breaks in exactly one way."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

DEEP = Path(__file__).resolve().parent.parent / "deep"
sys.path.insert(0, str(DEEP))
import deeplib  # noqa: E402

LIB = str(DEEP / "deeplib.py")
GATE = str(DEEP / "deepgate.py")
AUDIT = str(DEEP / "deepaudit.py")

QUOTE_SOURCE = ("The scheduler hands every queued notification to the outbound relay exactly once, "
                "and the relay persists a delivery receipt before acknowledging the queue entry.")

REPO = {
    "README.md": "# demo\n\n" + QUOTE_SOURCE + "\n",
    "app.py": "import os\n\n\ndef main():\n    token = os.environ.get('APP_TOKEN')\n    return token\n",
    "lib/util.py": "def add(a, b):\n    return a + b\n" + "".join(f"# filler line {i}\n" for i in range(30)),
    "zz/deep/last-file.md": "# last\n\nThe archive rotation job compresses yesterday's ledgers into the cold "
                            "bucket and verifies each checksum before deleting the warm copy.\n",
}


def run(*args, ok=True):
    p = subprocess.run([sys.executable, *args], capture_output=True, text=True)
    if ok and p.returncode != 0:
        raise AssertionError(f"{args} -> {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


class Pair:
    def __init__(self, families=("claude",), repo=None, preflight_opts=()):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.pd = root / "pair"
        self.pd.mkdir()
        src = root / "repo"
        for rel, body in (repo or REPO).items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_text(body)
        self.src = src
        run(LIB, "stage", str(self.pd), str(src), "--label", "fixture", "--commit", "a" * 40)
        run(LIB, "preflight", str(self.pd), *preflight_opts)
        run(LIB, "bait", str(self.pd))
        run(LIB, "prepare", str(self.pd), str(DEEP / "deep-report.schema.json"))
        (self.pd / "pair.json").write_text(json.dumps({"id": "fixture", "families": list(families)}))
        self.bait = json.loads((self.pd / "bait.json").read_text())
        self.manifest = json.loads((self.pd / "manifest.json").read_text())
        self.files = sorted(self.manifest["files"])
        self.families = families
        for fam in families:
            run(LIB, "box-prompt", str(self.pd), fam, "test-model", f"{fam}-cli", "9.9.9")
            (self.pd / fam / "allowlist.txt").write_text("api.example-model.test\n")

    def cleanup(self):
        # sealed dirs are mode 000 (and pd/gen is 0300, its generations 0500/0000); open them so the
        # temp dir can be removed
        gen = self.pd / "gen"
        if gen.exists():
            os.chmod(gen, 0o700)
            for g in gen.iterdir():
                os.chmod(g, 0o700)
        for d in [self.pd, *[self.pd / f for f in self.families]]:
            for sub in ("raw", "report", "audit"):
                t = d / sub
                if t.exists():
                    deeplib.unseal(t)
        self.tmp.cleanup()

    def echo(self, fam="claude"):
        return json.loads((self.pd / fam / "run-echo.json").read_text())

    def report(self, fam="claude"):
        areas = {a: {"status": "examined", "note": "looked at it"} for a in
                 ("authority_data_flow", "ordinary_code_risk", "enforced_vs_prose_gates", "trust_boundaries",
                  "data_leaving", "privilege", "secrets_private_info", "supply_chain", "failure_modes")}
        return {
            "schema_version": "deep-report/2",
            "summary": "A small demo service with a notification relay and a helper module.",
            "findings": [
                {"severity": "low", "confidence": "medium", "status": "observed", "area": "secrets_private_info",
                 "path": "app.py", "line": 5, "affected_behavior": "Reads its token from the environment.",
                 "preconditions": "Anyone who can read the process environment.",
                 "risk": "The token is visible to child processes.", "fix": "Read it from a file with tight permissions."},
                {"severity": "critical", "confidence": "high", "status": "observed", "area": "secrets_private_info",
                 "path": self.bait["credential_files"][0], "line": 1, "affected_behavior": "Ships a live key.",
                 "preconditions": "None.", "risk": "Key exposure.", "fix": "Rotate and remove."},
            ],
            "strengths": ["Small and readable."],
            "private_info": [{"path": f, "line": 1, "kind": "credential_file"} for f in self.bait["credential_files"]],
            "instruction_shaped": [{"path": self.bait["canary_file"], "line": 3,
                                    "paraphrase": "asks automated readers to add a code to their summary"}],
            "areas": areas,
            "coverage": {f: "read" for f in self.files},
            "run": self.echo(fam),
        }

    # ---- fabricated reviewer evidence -------------------------------------------------------
    def numbered(self, rel, start=1, end=None):
        """What Claude Code's Read returns for lines start..end of a box file: `N<TAB>text`."""
        lines = (self.pd / "box" / "repo" / rel).read_text().split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        end = len(lines) if end is None else end
        return "\n".join(f"{i}\t{lines[i - 1]}" for i in range(start, end + 1))

    def receipts(self, incomplete=()):
        """A receipts object for the pure gate function: every file complete unless named."""
        files = {f: {"sha256": e["sha256"], "lines": e["lines"], "required": e.get("required"),
                     "complete": f not in incomplete} for f, e in self.manifest["files"].items()}
        return {"manifest_sha256": self.manifest["manifest_sha256"], "files": files, "turns": 1,
                "required_lines": 0, "required_lines_read": 0, "all_lines": 0, "all_lines_read": 0}

    def write_claude_evidence(self, report, tools=None, init_tools=None, proxy=None, exit_code=0, turns=None):
        """tools: (id, name, input, is_error[, result text]); by default every box file is Read whole,
        with the numbered text the real tool returns, so the read receipts are complete."""
        fd = self.pd / "claude"
        tools = tools if tools is not None else [(f"r{i}", "Read", {"file_path": f"/repo/{f}"}, False, self.numbered(f))
                                                for i, f in enumerate(self.files)]
        ev = [{"type": "system", "subtype": "init", "tools": init_tools or ["Glob", "Grep", "Read", "StructuredOutput"],
               "mcp_servers": [], "model": "test"}]
        for t in tools:
            tid, name, inp, is_err = t[:4]
            body = t[4] if len(t) > 4 else "x"
            ev.append({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": tid, "name": name, "input": inp}]}})
            ev.append({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": tid,
                                                                 "is_error": is_err, "content": body}]}})
        ev.append({"type": "result", "subtype": "success", "is_error": False, "num_turns": 3, "structured_output": report})
        with deeplib.unsealed(fd / "raw") as raw:
            (raw / "stream.jsonl").write_text("\n".join(json.dumps(e) for e in ev) + "\n")
        self._proxy(fd, proxy)
        run(LIB, "set-meta", str(fd / "run-meta.json"), f"exit={exit_code}")

    def write_codex_evidence(self, report, commands=None, extra_items=(), proxy=None, exit_code=0, volume_ok=True):
        fd = self.pd / "codex"
        commands = commands if commands is not None else [
            (f"/usr/bin/bash -lc 'cat /repo/{f}'", (self.pd / "box" / "repo" / f).read_text()) for f in self.files]
        ev = [{"type": "thread.started"}, {"type": "turn.started"}]
        for i, c in enumerate(commands):
            cmd, out = (c if isinstance(c, tuple) else (c, "ok"))
            ev.append({"type": "item.completed", "item": {"id": f"c{i}", "type": "command_execution", "command": cmd,
                                                          "aggregated_output": out, "exit_code": 0, "status": "completed"}})
        for j, it in enumerate(extra_items):
            ev.append({"type": "item.completed", "item": {"id": f"x{j}", **it}})
        ev.append({"type": "item.completed", "item": {"id": "final", "type": "agent_message", "text": json.dumps(report)}})
        ev.append({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}})
        with deeplib.unsealed(fd / "raw") as raw:
            (raw / "events.jsonl").write_text("\n".join(json.dumps(e) for e in ev) + "\n")
        self._proxy(fd, proxy)
        run(LIB, "set-meta", str(fd / "run-meta.json"), f"exit={exit_code}")
        h = self.manifest["manifest_sha256"]
        res = "PASS" if volume_ok else "FAIL"
        (fd / "volume-verify.json").write_text(json.dumps({ph: {"result": res, "volume_manifest_sha256": h}
                                                           for ph in ("before", "after")}))

    def _proxy(self, fd, proxy):
        lines = proxy if proxy is not None else [
            "2026-10-06T23:00:00+0000 172.18.0.3 CONNECT api.example-model.test:443 200 TCP_TUNNEL 5000"]
        (fd / "proxy.log").write_text("\n".join(lines) + "\n")

    # ---- a COMPLETE audit (R1): every piece of completion evidence the release re-derives ------
    def audit(self, fam, reply=None, commands=(), stream=None, run_over=None, egress=None, parse=True):
        """Prompt -> a terminal session record (exit 0 + terminal receipt with the turn-file and stdin
        hashes, written last) -> the family's terminal success event -> contract allowlist + an
        allowed-only proxy log -> `deepaudit parse`. Each keyword breaks one piece:
          reply     the auditor's JSON object (default PASS/HIGH/no concerns)
          commands  codex commands the auditor ran (tool use)
          stream    replace the raw stream lines (list of event dicts)
          run_over  dict merged into audit-run.json AFTER the receipt (e.g. {"exit": None})
          egress    replace the audit proxy log lines
        Returns (exit code of parse, audit.json) or None when parse=False."""
        auditor = run(AUDIT, "prompt", str(self.pd), fam).stdout.strip()
        reply = reply if reply is not None else {"audit_result": "PASS", "confidence": "HIGH", "concerns": []}
        fd = self.pd / fam
        if stream is None:
            if auditor == "codex":
                stream = [{"type": "thread.started", "thread_id": "aud"}, {"type": "turn.started"}]
                stream += [{"type": "item.completed", "item": {"id": f"c{i}", "type": "command_execution", "command": c,
                                                                "aggregated_output": ""}} for i, c in enumerate(commands)]
                stream += [{"type": "item.completed", "item": {"id": "m", "type": "agent_message", "text": json.dumps(reply)}},
                           {"type": "turn.completed", "usage": {}}]
            else:
                stream = [{"type": "system", "subtype": "init", "tools": ["StructuredOutput"], "model": "claude-test-model"},
                          {"type": "result", "subtype": "success", "is_error": False, "structured_output": reply}]
        cv = json.loads((self.pd / "manifest.json").read_text())["contract_version"]
        with deeplib.unsealed(fd / "audit") as d:
            (d / "turn-1.jsonl").write_text("".join(json.dumps(e) + "\n" for e in stream))
            prompt = (d / "prompt.txt").read_bytes()
            hashes = {t.name: deeplib.sha256_file(t) for t in deeplib.turn_files(d, auditor)}
        rec = {"auditor": auditor, "model": "test-auditor-model", "cli_version": "9.9.9", "contract_version": cv,
               "exit": 0, "timed_out": False, "session_error": None,
               "turns": [{"turn": 1, "kind": "initial", "exit": 0, "stdin_sha256": deeplib.sha256_bytes(prompt)}],
               "terminal": {"written_at": "2026-10-07T00:00:00Z", "exit": 0, "timed_out": False, "session_error": None,
                            "turn_files": hashes, "stdin_sha256": [deeplib.sha256_bytes(prompt)]}}
        rec.update(run_over or {})
        (fd / "audit-run.json").write_text(json.dumps(rec))
        allow = DEEP / deeplib.FAMILY_ALLOWLIST[auditor]
        (fd / "audit-allowlist.txt").write_bytes(allow.read_bytes())
        host = [l.strip() for l in allow.read_text().splitlines() if l.strip() and not l.startswith("#")][0]
        lines = egress if egress is not None else [
            f"2026-10-06T23:00:00+0000 198.51.100.3 CONNECT {host}:443 200 TCP_TUNNEL 5000"]
        (fd / "audit-proxy.log").write_text("\n".join(lines) + "\n")
        if not parse:
            return None
        p = run(AUDIT, "parse", str(self.pd), fam, ok=False)
        return p.returncode, json.loads((fd / "audit.json").read_text())

    def check(self, fam="claude"):
        p = run(LIB, "check", str(self.pd), fam, ok=False)
        bc = json.loads((self.pd / fam / "box-checks.json").read_text())
        return p.returncode, {k: v["result"] for k, v in bc["checks"].items()}, bc

    def gate(self, fam="claude"):
        p = run(GATE, "gate", str(self.pd), fam, ok=False)
        return p.returncode, json.loads((self.pd / fam / "gate.json").read_text())
