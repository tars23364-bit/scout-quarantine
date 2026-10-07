#!/usr/bin/env python3
"""scout deep review, P2: the host-driven session driver. Stdlib only.

  run <spec.json>     run one box session; exit = the final turn's exit (124 on timeout)
  validate <spec.json>

Every model-running box (reviewer, auditor, the codexcheck/toolcheck probes) goes through here,
so the box that is probed is the box that reviews. A session is:

  1. `docker run -d` the box IDLE (sleep), with the spec's hardened flags. The idle process holds
     no credential: Claude's token is passed by NAME to each `docker exec` of the CLI only, and
     Codex's non-refreshable auth file is written into the box's tmpfs CODEX_HOME over stdin
     (never an env var, so never in `docker inspect`).
  2. Turn 1: `docker exec -i` the CLI with the task on stdin. Raw output goes to the sealed raw
     dir as turn-1.jsonl (the dir is unsealed only for the duration of the session).
  3. Reviewer only: the host computes read receipts from the trusted tool log (deepdepth). If a
     REQUIRED file is incomplete and repair turns remain, the host resumes the SAME session with
     a message built from host data only (paths and line ranges): Claude `--resume <uuid>`,
     Codex `exec resume <thread id>`. At most max_repair turns, then the gate decides.
  4. `docker rm -f` in every case: success, failure, timeout, crash.

The spec is validated before anything starts: an auditor box may not mount a repo; a reviewer
box mounts exactly one /repo read-only and nothing else; no privileged, host-namespace, socket or
cap-add flags; no credential in the container's own environment.
"""
from __future__ import annotations


import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

DEEP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DEEP_DIR))
import deeplib  # noqa: E402
from deeplib import jdump, jload, now, unsealed  # noqa: E402

ROLES = ("reviewer", "auditor", "probe")
CRED_ENV_NAMES = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "SCOUT_CODEX_AUTH_B64", "OPENAI_API_KEY",
                  "CODEX_API_KEY")
REQUIRED_RUN_FLAGS = ("--read-only", "--cap-drop", "--security-opt", "--user", "--network")
FORBIDDEN_RUN = ("--privileged", "--cap-add", "--pid", "--ipc", "--userns", "--uts", "--device",
                 "--group-add", "--volumes-from")
BANNED_CLI = ("-i", "--image", "--file", "--mcp-config", "--plugin-dir", "--dangerously-skip-permissions",
              "--allow-dangerously-skip-permissions", "--dangerously-bypass-approvals-and-sandbox",
              "--dangerously-bypass-hook-trust", "--full-auto", "--yolo", "--search", "--add-file")


def _mounts(run: list[str]) -> list[str]:
    out = []
    for i, a in enumerate(run):
        if a in ("-v", "--volume", "--mount") and i + 1 < len(run):
            out.append(run[i + 1])
        elif a.startswith(("-v=", "--volume=", "--mount=")):
            out.append(a.split("=", 1)[1])
    return out


def validate_spec(spec: dict) -> list[str]:
    errs = []
    fam, role = spec.get("family"), spec.get("role")
    if fam not in ("claude", "codex"):
        errs.append("family must be claude or codex")
    if role not in ROLES:
        errs.append(f"role must be one of {ROLES}")
    run = list(spec.get("run_args") or [])
    if not run or not spec.get("cli"):
        errs.append("run_args and cli are required")
    mounts = _mounts(run)
    repo = [m for m in mounts if ":/repo" in m or "dst=/repo" in m or "target=/repo" in m]
    other = [m for m in mounts if m not in repo]
    if other:
        errs.append("nothing but /repo may be mounted into a box")
    if role == "auditor" and repo:
        errs.append("an auditor box must not mount the repo: it judges the gated report only")
    if role == "reviewer" and len(repo) != 1:
        errs.append("a reviewer box mounts exactly one /repo")
    if any(not m.endswith(":ro") for m in repo):
        errs.append("/repo must be mounted read-only")
    for a in run:
        if a.split("=", 1)[0] in FORBIDDEN_RUN:
            errs.append(f"forbidden docker run flag {a.split('=', 1)[0]}")
        if "docker.sock" in a or "seccomp=unconfined" in a or "apparmor=unconfined" in a:
            errs.append("unconfined profile or docker socket in run args")
    for i, a in enumerate(run):
        if a == "--network" and i + 1 < len(run) and run[i + 1] in ("host", "bridge", "default"):
            errs.append("a box runs only on its internal network")
        if a in ("-e", "--env") and i + 1 < len(run) and run[i + 1].split("=", 1)[0] in CRED_ENV_NAMES:
            errs.append("a credential may not be in the container's own environment")
    for f in REQUIRED_RUN_FLAGS:
        if f not in run:
            errs.append(f"missing hardening flag {f}")
    if "ALL" not in run or "no-new-privileges" not in run:
        errs.append("cap-drop ALL and no-new-privileges are required")
    # The CLI argv: no attachments (a second way for a file to reach a model), no extra readable
    # dirs, no MCP/plugins, and no sandbox or permission bypass, on the first turn and on resume.
    for key in ("cli", "cli_resume"):
        argv = list(spec.get(key) or [])
        for i, a in enumerate(argv):
            flag = a.split("=", 1)[0]
            if flag in BANNED_CLI:
                errs.append(f"{key}: forbidden CLI flag {flag}")
            if flag == "--add-dir" and (i + 1 >= len(argv) or argv[i + 1] != "/repo"):
                errs.append(f"{key}: --add-dir may only name /repo")
            if flag in ("-s", "--sandbox") and i + 1 < len(argv) and argv[i + 1] != "read-only":
                errs.append(f"{key}: the codex sandbox must be read-only")
            if flag == "--permission-mode" and i + 1 < len(argv) and argv[i + 1] not in ("dontAsk", "default"):
                errs.append(f"{key}: permission mode {argv[i + 1]} is not allowed")
            if "sandbox_mode=" in a and 'sandbox_mode="read-only"' not in a:
                errs.append(f"{key}: sandbox_mode override must be read-only")
    for n in spec.get("exec_env") or []:
        if n not in CRED_ENV_NAMES:
            errs.append(f"exec_env may only name a model credential, not {n}")
    if fam == "codex" and spec.get("exec_env"):
        errs.append("the codex box gets its credential as a tmpfs file over stdin, not as exec env")
    return errs


def _exec(argv: list[str], stdin: bytes, out: Path, err: Path, timeout: float) -> tuple[int, bool]:
    with open(out, "wb") as fo, open(err, "wb") as fe:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=fo, stderr=fe)
        try:
            p.communicate(stdin, timeout=max(1.0, timeout))
            return p.returncode, False
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            return 124, True


def _claude_cost(path: Path) -> float:
    st = deeplib.parse_stream(path)
    return sum(float(r.get("total_cost_usd") or 0) for r in st["results"])


def run_session(spec: dict, environ=None) -> int:
    environ = dict(os.environ if environ is None else environ)
    errs = validate_spec(spec)
    meta_file = Path(spec["meta_file"])
    meta = jload(meta_file) if meta_file.exists() else {}
    if errs:
        meta.update({"exit": 2, "session_error": "spec_invalid", "spec_errors": errs})
        jdump(meta_file, meta)
        print("session: spec refused: " + "; ".join(errs), file=sys.stderr)
        return 2
    fam, role, name = spec["family"], spec["role"], spec["name"]
    raw = Path(spec["raw_dir"])
    timeout = float(spec.get("timeout", 3600))
    max_repair = int(spec.get("max_repair", 0)) if role == "reviewer" else 0
    followups = list(spec.get("followups") or []) if role == "probe" else []
    multi = max_repair > 0 or bool(followups)
    deadline = time.monotonic() + timeout
    turns, receipts_log, rc, timed_out, err = [], [], 1, False, None
    cost = 0.0
    sid = str(uuid.uuid4())
    session = None
    started = now()
    import deepdepth  # noqa: E402
    policy = deepdepth.load_policy()
    with unsealed(raw):
        try:
            up = subprocess.run(["docker", "run", "-d", "--name", name, *spec["run_args"]],
                                capture_output=True, text=True)
            if up.returncode != 0:
                err = "container_start_failed"
                (raw / "session.stderr").write_text(up.stderr[-4000:])
                return 1
            if fam == "codex":
                put = spec.get("codex_put") or {}
                b64 = environ.get(put.get("auth_env", "SCOUT_CODEX_AUTH_B64"), "")
                if not b64:
                    err = "codex_auth_missing"
                    return 1
                p = subprocess.run(["docker", "exec", "-i", name, "scout-codex-entry", "put-auth"],
                                   input=b64.encode(), capture_output=True)
                if p.returncode != 0:
                    err = "codex_auth_put_failed"
                    return 1
                if put.get("schema_file"):
                    p = subprocess.run(["docker", "exec", "-i", name, "scout-codex-entry", "put-schema"],
                                       input=Path(put["schema_file"]).read_bytes(), capture_output=True)
                    if p.returncode != 0:
                        err = "codex_schema_put_failed"
                        return 1
            if "prompt_sealed" in spec:
                prompt = (raw / spec["prompt_sealed"]).read_bytes()
            else:
                prompt = Path(spec["prompt_file"]).read_bytes()
            exec_env = []
            for n in spec.get("exec_env") or []:
                exec_env += ["-e", n]
            turn, kind = 1, "initial"
            while True:
                if fam == "claude":
                    cli = list(spec["cli"]) + (["--session-id", sid] if turn == 1 and multi else [])
                    if turn > 1:
                        cli = list(spec["cli"]) + ["--resume", sid]
                else:
                    cli = list(spec["cli"]) if turn == 1 else [a.replace("{SESSION}", session or "")
                                                               for a in spec["cli_resume"]]
                argv = ["docker", "exec", "-i", "-w", spec.get("workdir", "/work"), *exec_env, name, *cli]
                t0 = time.monotonic()
                left = deadline - t0
                if left <= 0:
                    rc, timed_out = 124, True
                    break
                out = raw / f"turn-{turn}.jsonl"
                rc, to = _exec(argv, prompt, out, raw / f"turn-{turn}.stderr", left)
                rec = {"turn": turn, "kind": kind, "exit": rc, "seconds": round(time.monotonic() - t0, 1)}
                if fam == "claude":
                    c = _claude_cost(out)
                    cost += c
                    rec["cost_usd"] = round(c, 4)
                    session = sid
                else:
                    session = session or deeplib.parse_codex_events(out).get("thread_id")
                turns.append(rec)
                if to:
                    timed_out = True
                    break
                if rc != 0:
                    break
                if role == "probe":
                    if not followups:
                        break
                    prompt, kind = followups.pop(0).encode(), "followup"
                    turn += 1
                    continue
                if role != "reviewer":
                    break
                pd = Path(spec["pair_dir"])
                manifest = jload(pd / "manifest.json")
                r = deepdepth.compute(raw, pd / "box" / "repo", manifest, fam,
                                      manifest.get("contract_version", "unknown"), policy)
                receipts_log.append({"after_turn": turn, "required_complete": r["required_complete"],
                                     "required_files": r["required_files"],
                                     "required_lines_read": r["required_lines_read"],
                                     "required_lines": r["required_lines"]})
                if not r["required_incomplete"] or len(turns) - 1 >= max_repair:
                    break
                if fam == "codex" and not session:
                    err = "codex_thread_id_missing"
                    break
                msg = deepdepth.repair_message(r, fam, policy.get("repair_message_max_entries", 120))
                (Path(spec["fd"]) / f"repair-{turn}.txt").write_text(msg)  # host data only: public
                prompt, kind = msg.encode(), "repair"
                turn += 1
        except Exception as e:  # noqa: BLE001  - any driver fault ends the session closed
            err = f"driver_exception:{type(e).__name__}"
            rc = 1
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            meta = jload(meta_file) if meta_file.exists() else {}
            meta.update({"exit": rc, "timed_out": timed_out, "session_error": err, "session_started": started,
                         "session_ended": now(), "turns": turns,
                         "repair_turns_used": sum(1 for t in turns if t["kind"] == "repair"),
                         "max_repair": max_repair, "receipts_by_turn": receipts_log,
                         "contract_version": meta.get("contract_version") or deeplib.contract_version()})
            if fam == "claude":
                meta["cost_usd"] = round(cost, 4)
            jdump(meta_file, meta)
    return rc if err is None else (rc if rc != 0 else 1)


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    spec = jload(Path(sys.argv[2]))
    if sys.argv[1] == "validate":
        errs = validate_spec(spec)
        print("OK" if not errs else "\n".join(errs))
        sys.exit(0 if not errs else 1)
    sys.exit(run_session(spec))


if __name__ == "__main__":
    main()
