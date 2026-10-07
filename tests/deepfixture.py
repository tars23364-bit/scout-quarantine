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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deeplib  # noqa: E402
import fakedocker  # noqa: E402  (its docker-shaped inspect synthesis, P4)

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


def run(*args, ok=True, env=None):
    p = subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env)
    if ok and p.returncode != 0:
        raise AssertionError(f"{args} -> {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


# ---- P3: the credential proxy's log shape (credproxy.js), and synthetic host credentials -------
def contract_host(fam: str) -> str:
    allow = DEEP / deeplib.FAMILY_ALLOWLIST[fam]
    return [l.strip() for l in allow.read_text().splitlines() if l.strip() and not l.startswith("#")][0]


def proxy_start(fam: str, allow_bytes: bytes, **over) -> dict:
    return {"event": "start", "code_sha256": deeplib.sha256_file(DEEP / "credproxy.js"),
            "config_sha256": deeplib.sha256_file(DEEP / deeplib.PROXY_CONFIG[fam]),
            "allowlist_sha256": deeplib.sha256_bytes(allow_bytes), "family": fam, "test_ca": False,
            "tls_verify": True, **over}


def fwd(host: str, path="/v1/messages", **over) -> dict:
    return {"event": "request", "decision": "forwarded", "method": "POST", "path": path, "upstream": f"{host}:443",
            "status": 200, "scrubbed": 0, "tls": {"authorized": True, "servername": host}, **over}


def denied(reason="route_not_allowlisted", path="/x", **over) -> dict:
    return {"event": "request", "decision": "denied", "reason": reason, "method": "GET", "path": path, "status": 403, **over}


def proxy_log(fam: str, allow_bytes: bytes, lines=None, start=True) -> str:
    lines = lines if lines is not None else [fwd(contract_host(fam))]
    lines = ([proxy_start(fam, allow_bytes)] if start else []) + list(lines)
    return "".join((l if isinstance(l, str) else json.dumps(l)) + "\n" for l in lines)


LOCK = json.loads((DEEP / "images.lock.json").read_text())
HARD = ["--network", "scout-deep-int-fixture", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "10001:10001"]


def fake_inspect(ref):
    key = "credproxy" if "credproxy" in ref else ("codex" if "codex" in ref else "reviewer")
    return {"ref": ref, "id": LOCK[key], "repo_digests": []}


def proxy_run_args(fam, role, allow_file):
    """The credential proxy's launch vector as net_up() builds it (hardened, its own egress net)."""
    tag = f"fixture-{role[:3]}-{fam}"
    return ["--name", f"scout-deep-proxy-{tag}", "--network", f"scout-deep-eg-{tag}", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m",
            "--tmpfs", "/run/credproxy:rw,size=1m", "--tmpfs", "/tmp:rw,size=16m",
            "-v", f"{DEEP / deeplib.PROXY_CONFIG[fam]}:/etc/credproxy/config.json:ro",
            "-v", f"{allow_file}:/etc/credproxy/allowlist.txt:ro", "--label", "scout.quarantine=true",
            "scout/deep-credproxy:latest"]


def evidence_for(desc: dict, box_name: str, box_image: str) -> dict:
    """The inspect evidence the session driver records for this declared launch (P4, F2): docker's
    JSON as fakedocker synthesizes it from the run vectors, normalized by the driver's own code."""
    import deepsession
    box = fakedocker.container_json(box_name, desc["box_run_args"], box_image)
    po = fakedocker.run_opts(desc["proxy_run_args"])
    pname = po["--name"][-1]
    box_net = fakedocker.run_opts(desc["box_run_args"])["--network"][-1]
    px = fakedocker.proxy_json(pname, box_net, LOCK["credproxy"], args=desc["proxy_run_args"])
    nets = sorted(set(box["NetworkSettings"]["Networks"]) | set(px["NetworkSettings"]["Networks"]))
    return {"evidence_version": "inspect/1", "taken_at": "2026-10-07T00:00:00Z", "box_name": box_name,
            "proxy_name": pname, "box": deepsession._norm_container(box), "proxy": deepsession._norm_container(px),
            "networks": {n: deepsession._norm_network(fakedocker.network_json(n, [box, px])) for n in nets}}


def session_record(*, exit_code=0, stdin=(), turn_files=None, evidence=None, image=None) -> dict:
    """What deepsession.run_session writes in its finally: the outer status, the turns, the
    container's image and inspect evidence, and the terminal receipt (complete schema, F1)."""
    stdin = list(stdin)
    rec = {"exit": exit_code, "timed_out": False, "session_error": None,
           "session_started": "2026-10-06T23:59:00Z", "session_ended": "2026-10-07T00:00:00Z",
           "turns": [{"turn": i + 1, "kind": "initial" if i == 0 else "repair", "exit": exit_code,
                      "stdin_sha256": h} for i, h in enumerate(stdin)],
           "container_image_id": image, "runtime_evidence": evidence,
           "terminal": {"written_at": "2026-10-07T00:00:00Z", "exit": exit_code, "timed_out": False,
                        "session_error": None, "turn_files": turn_files or {}, "stdin_sha256": stdin,
                        "runtime_evidence_sha256": deeplib.canon_sha(evidence) if evidence else None}}
    return rec


def write_runtime(pd, fam, role, prompt: bytes, out_name, allow_file, task_append=None):
    """A runtime descriptor exactly as deep-review.sh records one (R4), with the image ids of
    images.lock.json; returns (the container image id the box 'ran', the inspect evidence)."""
    box_img = "scout/deep-codex:latest" if fam == "codex" else "scout/deep-reviewer:latest"
    run_args = HARD + ([] if role == "auditor" else ["-v", f"{pd}/box/repo:/repo:ro"]) + [box_img]
    if fam == "claude":
        sysp = ((DEEP / "reviewer-system.md").read_text().rstrip("\n") if role == "reviewer"
                else __import__("deepaudit").AUDIT_SYSTEM)
        spec = {"run_args": run_args, "cli": ["claude", "-p", "--system-prompt", sysp],
                "exec_env": {"CLAUDE_CODE_OAUTH_TOKEN": DUMMY_MARK}}
    else:
        spec = {"run_args": run_args, "cli": ["codex", "exec", "-s", "read-only", "-"]}
    proxy_run = proxy_run_args(fam, role, allow_file)
    desc = deeplib.runtime_descriptor(role=role, family=fam, spec=spec, proxy_run=proxy_run, prompt=prompt,
                                      task_append_sha256=task_append, box_image=box_img,
                                      proxy_image="scout/deep-credproxy:latest", proxy_container=proxy_run[1],
                                      inspect=fake_inspect, container_image=lambda n: LOCK["credproxy"])
    (pd / (out_name if "/" in out_name else f"{out_name}")).write_text(json.dumps(desc))
    img = LOCK["codex" if fam == "codex" else "reviewer"]
    return img, evidence_for(desc, f"scout-deep-{role[:3]}-{fam}-fixture", img)


# synthetic values of the admitted shapes, assembled at runtime (no literal shape in the source)
DUMMY_MARK = deeplib.BOX_MARKER + "-fixture"
SYNTH_CLAUDE = "-".join(["sk", "ant", "oat01", "SYNTHETICcomparator" + "x" * 60 + "AA"])


def _synth_jwt(sub_claim: str, tail: str) -> str:
    import base64
    seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return ".".join([seg({"alg": "RS256"}), seg({"sub": sub_claim}), "SYNTHETICcomparator" + tail * 40])


SYNTH_TOKENS = {"access": _synth_jwt("synthetic", "y"), "id": _synth_jwt("synthetic-id", "z"),
                "refresh": "_".join(["rt", "SYNTHETICcomparator" + "w" * 30])}
DUMP_OK = {"bytes": 4096, "comparator": True, "real_values_compared": 1, "real_windows_hit": 0, "dummy_seen": True,
           "docker_diff_entries": 0, "sources": ["fixture"]}


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
            (self.pd / fam / "allowlist.txt").write_bytes((DEEP / deeplib.FAMILY_ALLOWLIST[fam]).read_bytes())
        # synthetic host credentials: the comparator the box checks REQUIRE (P3, probe 07)
        auth = root / "codex-auth.json"
        auth.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {
            **{f"{k}_token": v for k, v in SYNTH_TOKENS.items()}, "account_id": "synthetic-account"}}))
        self.cred_env = {"CLAUDE_CODE_OAUTH_TOKEN": SYNTH_CLAUDE, "SCOUT_CODEX_AUTH_FILE": str(auth)}

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
        self._runtime(fd, exit_code)

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
        self._runtime(fd, exit_code)
        h = self.manifest["manifest_sha256"]
        res = "PASS" if volume_ok else "FAIL"
        (fd / "volume-verify.json").write_text(json.dumps({ph: {"result": res, "volume_manifest_sha256": h}
                                                           for ph in ("before", "after")}))

    def _runtime(self, fd, exit_code=0):
        """R4: the reviewer box's descriptor + the session's own record as the driver finishes it
        (status, turns, container image, inspect evidence, complete terminal receipt: P4 F1/F2)."""
        prompt = (fd / "prompt.txt").read_bytes()
        img, ev = write_runtime(self.pd, fd.name, "reviewer", prompt, f"{fd.name}/runtime.json", fd / "allowlist.txt")
        with deeplib.unsealed(fd / "raw") as raw:
            tf = {t.name: deeplib.sha256_file(t) for t in deeplib.turn_files(raw, fd.name)}
        rec = session_record(exit_code=exit_code, stdin=[deeplib.sha256_bytes(prompt)], turn_files=tf, evidence=ev,
                             image=img)
        run(LIB, "set-meta", str(fd / "run-meta.json"), *[f"{k}={json.dumps(v)}" for k, v in rec.items()],
            f"box_dump={json.dumps(DUMP_OK)}")

    def _proxy(self, fd, proxy):
        (fd / "proxy.log").write_text(proxy_log(fd.name, (fd / "allowlist.txt").read_bytes(), proxy))

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
        allow = (DEEP / deeplib.FAMILY_ALLOWLIST[auditor]).read_bytes()
        (fd / "audit-allowlist.txt").write_bytes(allow)
        img, ev = write_runtime(self.pd, auditor, "auditor", prompt, f"{fam}/audit-runtime.json",
                                fd / "audit-allowlist.txt")
        rec = {"auditor": auditor, "model": "test-auditor-model", "cli_version": "9.9.9", "contract_version": cv,
               **session_record(stdin=[deeplib.sha256_bytes(prompt)], turn_files=hashes, evidence=ev, image=img)}
        rec.update(run_over or {})
        (fd / "audit-run.json").write_text(json.dumps(rec))
        (fd / "audit-proxy.log").write_text(proxy_log(auditor, allow, egress))
        if not parse:
            return None
        p = run(AUDIT, "parse", str(self.pd), fam, ok=False)
        return p.returncode, json.loads((fd / "audit.json").read_text())

    def check(self, fam="claude", env=None):
        p = run(LIB, "check", str(self.pd), fam, ok=False, env={**os.environ, **self.cred_env, **(env or {})})
        bc = json.loads((self.pd / fam / "box-checks.json").read_text())
        return p.returncode, {k: v["result"] for k, v in bc["checks"].items()}, bc

    def gate(self, fam="claude"):
        p = run(GATE, "gate", str(self.pd), fam, ok=False)
        return p.returncode, json.loads((self.pd / fam / "gate.json").read_text())
