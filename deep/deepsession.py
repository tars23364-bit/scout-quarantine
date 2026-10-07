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
cap-add flags; no credential in the container's own environment. Since P4 (F2) the docker and CLI
vectors are parsed as docker and the CLIs parse them and judged on their EFFECTIVE values against
an option allowlist, and after `docker run` the driver records `docker inspect` of the box and its
credential proxy plus `docker network inspect` of their networks, refuses to start a turn if that
evidence differs from the declaration, and binds it in the terminal receipt (F1: closed schema).
"""
from __future__ import annotations


import contextlib
import json
import os
import re
import signal
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
                  "CODEX_API_KEY", "ANTHROPIC_AUTH_TOKEN")
FORBIDDEN_RUN = ("--privileged", "--cap-add", "--pid", "--ipc", "--userns", "--uts", "--device",
                 "--group-add", "--volumes-from", "--mount", "--env-file", "--cgroupns", "--sysctl",
                 "--runtime", "--network-alias")
BANNED_CLI = ("-i", "--image", "--file", "--mcp-config", "--plugin-dir", "--dangerously-skip-permissions",
              "--allow-dangerously-skip-permissions", "--dangerously-bypass-approvals-and-sandbox",
              "--dangerously-bypass-hook-trust", "--full-auto", "--yolo", "--search", "--add-file")

# --------------------------------------------------------------------------- launch policy (P4, F2)
#
# Serafina's P3 review (F2): the launch declarations were hashed and bound, but the checks read
# them token by token, so a weakened declaration made BEFORE binding was admissible: the reviewer
# `--user 0:0`, `--network <any name>`, `codex exec --sandbox=danger-full-access` (equals form at
# the end of argv), and `--privileged` in the proxy's vector (never validated at all). Now:
#   * a docker run vector is parsed the way docker parses it (aliases -u/--net/-v/-e/..., `--opt=v`
#     and `--opt v`, booleans with `=true|false`, options end at the image) and judged on its
#     EFFECTIVE values (the last occurrence, which is what docker applies); single-valued
#     security options (--user, --network, --read-only, --name, --entrypoint) may appear once;
#   * the option set is an ALLOWLIST: an option outside it is refused, so an unknown or new
#     weakening flag cannot pass by not being on a deny list;
#   * the box must run as BOX_UID on its own scout-deep-int-<id> network, read-only, cap-drop ALL,
#     no-new-privileges; the proxy (same hardening, never root) on its scout-deep-eg-<id> network,
#     mounting only its policy files read-only;
#   * CLI argv options are normalized the same way (`--opt=v`, `--opt v`, `-sV`), and every
#     occurrence of the codex sandbox / sandbox_mode and the Claude permission mode is checked;
#   * after `docker run`, the driver records `docker inspect` of the box and the proxy and
#     `docker network inspect` of their networks, refuses to start a turn if that evidence differs
#     from the declaration, and binds the evidence into its terminal receipt; release compares it
#     again with the descriptor (deeplib.runtime_check).

BOX_UID = "10001:10001"
RUN_ALIASES = {"-v": "--volume", "-e": "--env", "-u": "--user", "-l": "--label", "-m": "--memory",
               "--net": "--network", "-w": "--workdir", "-h": "--hostname", "-d": "--detach",
               "-i": "--interactive", "-t": "--tty", "-p": "--publish", "-P": "--publish-all"}
RUN_VALUE_OPTS = {"--network", "--cap-drop", "--security-opt", "--user", "--memory", "--memory-swap", "--cpus",
                  "--pids-limit", "--tmpfs", "--env", "--label", "--volume", "--entrypoint", "--name"}
RUN_BOOL_OPTS = {"--read-only"}
RUN_SINGLE = ("--network", "--user", "--read-only", "--entrypoint", "--name")
NNP_FORMS = {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
NET_INT_RE = re.compile(r"^scout-deep-int-[A-Za-z0-9][A-Za-z0-9_.-]*$")
NET_EG_RE = re.compile(r"^scout-deep-eg-[A-Za-z0-9][A-Za-z0-9_.-]*$")
PROXY_NAME_RE = re.compile(r"^scout-deep-proxy-[A-Za-z0-9][A-Za-z0-9_.-]*$")
PROXY_MOUNT_DIR = "/etc/credproxy/"
SAFE_IPC = ("private", "none", "")


def _is_root(user: str | None) -> bool:
    u = (user or "").strip()
    return u in ("", "0", "root") or u.split(":", 1)[0] in ("0", "root")


def parse_run(argv) -> dict:
    """A `docker run` option vector as docker reads it. Returns {"opts": {canonical name: [values in
    order]}, "image", "command", "errors"}. Booleans are recorded as "true"/"false"."""
    opts: dict[str, list[str]] = {}
    errs: list[str] = []
    argv = list(argv or [])
    i = 0
    while i < len(argv):
        a = argv[i]
        if not isinstance(a, str):
            errs.append("a docker run argument is not a string")
            i += 1
            continue
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break                                   # the image: options end here
        if a.startswith("--"):
            name, eq, val = a.partition("=")
        elif len(a) > 2:                            # -uVALUE, -u=VALUE
            name, eq, val = a[:2], "=", a[2:].removeprefix("=")
        else:
            name, eq, val = a, "", ""
        name = RUN_ALIASES.get(name, name)
        if name in RUN_BOOL_OPTS:
            v = val.lower() if eq else "true"
            if v not in ("true", "false"):
                errs.append(f"{name} takes true or false (got {val!r})")
            opts.setdefault(name, []).append(v)
        elif name in RUN_VALUE_OPTS:
            if not eq:
                if i + 1 >= len(argv):
                    errs.append(f"{name} has no value")
                    break
                i += 1
                val = argv[i]
            opts.setdefault(name, []).append(val)
        elif name in FORBIDDEN_RUN:
            errs.append(f"forbidden docker run flag {name}")
        else:
            errs.append(f"a docker run option is not in the launch policy ({name})")
        i += 1
    return {"opts": opts, "image": argv[i] if i < len(argv) else None, "command": argv[i + 1:], "errors": errs}


def eff(opts: dict, name: str) -> str | None:
    """The effective (last) value of an option, as docker applies it."""
    v = opts.get(name) or []
    return v[-1] if v else None


def _volume(v: str) -> dict:
    parts = v.split(":")
    return {"source": parts[0], "destination": parts[1] if len(parts) > 1 else "",
            "ro": len(parts) > 2 and "ro" in parts[2].split(",")}


def declared_volumes(opts: dict) -> list[dict]:
    return [_volume(v) for v in opts.get("--volume") or []]


def _common_hardening(o: dict, who: str) -> list[str]:
    errs = []
    for n in RUN_SINGLE:
        if len(o.get(n) or []) > 1:
            errs.append(f"{who}: {n} is declared more than once (docker applies the last: {eff(o, n)})")
    if eff(o, "--read-only") != "true":
        errs.append(f"{who}: the root filesystem must be read-only (effective --read-only {eff(o, '--read-only')})")
    caps = {c.strip().upper() for v in o.get("--cap-drop") or [] for c in v.split(",")}
    if "ALL" not in caps:
        errs.append(f"{who}: cap-drop ALL is required")
    sec = o.get("--security-opt") or []
    if not sec:
        errs.append(f"{who}: no-new-privileges is required")
    for v in sec:
        if v.strip() not in NNP_FORMS:
            errs.append(f"{who}: a security option is not in the launch policy (no-new-privileges only; got {v!r})")
    for v in o.get("--env") or []:
        n = v.split("=", 1)[0]
        if n in CRED_ENV_NAMES:
            errs.append("a credential may not be in the container's own environment")
        if n in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY") and not v.endswith("="):
            errs.append("a box has no forward proxy: its only egress is the credential proxy's base URL")
    return errs


def validate_box_run(argv) -> tuple[list[str], dict]:
    """The box's `docker run` vector, on its effective values. Returns (errors, parsed)."""
    p = parse_run(argv)
    o, errs = p["opts"], list(p["errors"])
    errs += _common_hardening(o, "box")
    net = eff(o, "--network")
    if net in ("host", "bridge", "default", "none") or (net or "").startswith("container:"):
        errs.append("a box runs only on its internal network")
    elif not (net and NET_INT_RE.match(net)):
        errs.append(f"box: the network must be the pair's own internal scout-deep-int-<id> network (effective --network {net})")
    user = eff(o, "--user")
    if user != BOX_UID:
        errs.append(f"box: the box runs as {BOX_UID} only (effective --user {user})")
    if not p["image"]:
        errs.append("box: no image")
    return errs, p


def validate_proxy_run(argv) -> list[str]:
    """The credential proxy's `docker run` vector (never validated before P4)."""
    p = parse_run(argv)
    o, errs = p["opts"], list(p["errors"])
    errs += _common_hardening(o, "proxy")
    net = eff(o, "--network")
    if not (net and NET_EG_RE.match(net)):
        errs.append(f"proxy: the network must be the pair's scout-deep-eg-<id> network (effective --network {net})")
    name = eff(o, "--name")
    if not (name and PROXY_NAME_RE.match(name)):
        errs.append(f"proxy: the container name must be scout-deep-proxy-<id> (effective --name {name})")
    if "--user" in o and _is_root(eff(o, "--user")):
        errs.append(f"proxy: the proxy never runs as root (effective --user {eff(o, '--user')})")
    for m in declared_volumes(o):
        if not (m["destination"].startswith(PROXY_MOUNT_DIR) and m["ro"]):
            errs.append(f"proxy: only read-only policy files under {PROXY_MOUNT_DIR} may be mounted")
    if not p["image"]:
        errs.append("proxy: no image")
    return errs


def cli_values(argv: list, names: tuple[str, ...]) -> list[str | None]:
    """Every value given to one of `names`, in every syntax: `--opt v`, `--opt=v`, `-o v`, `-ov`,
    `-o=v`. A flag with no value yields None."""
    out: list[str | None] = []
    for i, a in enumerate(argv):
        if not isinstance(a, str):
            continue
        for n in names:
            if a == n:
                out.append(argv[i + 1] if i + 1 < len(argv) and isinstance(argv[i + 1], str) else None)
            elif n.startswith("--") and a.startswith(n + "="):
                out.append(a[len(n) + 1:])
            elif not n.startswith("--") and not a.startswith("--") and a.startswith(n) and len(a) > len(n):
                out.append(a[len(n):].removeprefix("="))
    return out


def _codex_sandbox_errs(key: str, argv: list) -> list[str]:
    errs = []
    flags = cli_values(argv, ("-s", "--sandbox"))
    for v in flags:
        if v != "read-only":
            errs.append(f"{key}: the codex sandbox must be read-only (got {v})")
    conf = []
    for v in cli_values(argv, ("-c", "--config")):
        k, _, val = (v or "").partition("=")
        if k.strip() == "sandbox_mode":
            conf.append(val.strip().strip("\"'"))
    for a in argv:
        if isinstance(a, str) and "sandbox_mode" in a and not any(
                a.endswith(f"sandbox_mode={q}read-only{q}") for q in ('"', "'", "")):
            errs.append(f"{key}: sandbox_mode override must be read-only")
    for v in conf:
        if v != "read-only":
            errs.append(f"{key}: sandbox_mode override must be read-only")
    # the effective mode: -s/--sandbox wins over -c sandbox_mode; one of them must say read-only
    effective = flags[-1] if flags else (conf[-1] if conf else None)
    if effective != "read-only":
        errs.append(f"{key}: the codex sandbox must be declared read-only (effective {effective})")
    return errs


def validate_cli(fam: str, key: str, argv: list) -> list[str]:
    errs = []
    for a in argv:
        if not isinstance(a, str):
            errs.append(f"{key}: a CLI argument is not a string")
            continue
        if a.split("=", 1)[0] in BANNED_CLI:
            errs.append(f"{key}: forbidden CLI flag {a.split('=', 1)[0]}")
    # --add-dir is variadic in Claude Code: every value up to the next option must be /repo
    for i, a in enumerate(argv):
        if a == "--add-dir":
            vals = []
            for b in argv[i + 1:]:
                if not isinstance(b, str) or b.startswith("-"):
                    break
                vals.append(b)
            if not vals or any(v != "/repo" for v in vals):
                errs.append(f"{key}: --add-dir may only name /repo")
        elif isinstance(a, str) and a.startswith("--add-dir="):
            if any(v != "/repo" for v in a.split("=", 1)[1].split(",")):
                errs.append(f"{key}: --add-dir may only name /repo")
    for v in cli_values(argv, ("--permission-mode",)):
        if v not in ("dontAsk", "default"):
            errs.append(f"{key}: the permission mode is not allowed (got {v})")
    if fam == "codex":
        errs += _codex_sandbox_errs(key, argv)
    else:
        for a in argv:
            if isinstance(a, str) and "sandbox_mode" in a:
                errs.append(f"{key}: sandbox_mode override must be read-only")
    return errs


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
    run_errs, parsed = validate_box_run(run)
    errs += run_errs
    mounts = declared_volumes(parsed["opts"])
    repo = [m for m in mounts if m["destination"] == "/repo"]
    other = [m for m in mounts if m["destination"] != "/repo"]
    if other:
        errs.append("nothing but /repo may be mounted into a box")
    if role == "auditor" and repo:
        errs.append("an auditor box must not mount the repo: it judges the gated report only")
    if role == "reviewer" and len(repo) != 1:
        errs.append("a reviewer box mounts exactly one /repo")
    if any(not m["ro"] for m in repo):
        errs.append("/repo must be mounted read-only")
    for a in run:
        if isinstance(a, str) and ("docker.sock" in a or "seccomp=unconfined" in a or "apparmor=unconfined" in a):
            errs.append("unconfined profile or docker socket in run args")
    # The CLI argv: no attachments (a second way for a file to reach a model), no extra readable
    # dirs, no MCP/plugins, and no sandbox or permission bypass, on the first turn and on resume.
    for key in ("cli", "cli_resume"):
        if key == "cli_resume" and not spec.get(key):
            continue
        errs += validate_cli(fam, key, list(spec.get(key) or []))
    # P3 (R3): a box only ever holds a DUMMY credential. exec_env maps a credential variable to the
    # box's dummy VALUE; passing a host variable by name (P2) would hand the box the real one.
    ee = spec.get("exec_env") or {}
    if not isinstance(ee, dict):
        errs.append("exec_env must map a credential variable to the box's dummy value (no host variable by name)")
        ee = {}
    real = _real_values(fam)
    for n, v in ee.items():
        if n not in CRED_ENV_NAMES:
            errs.append(f"exec_env may only set a model credential variable, not {n}")
        if not deeplib.is_box_dummy(v) or v in real:
            errs.append(f"exec_env {n} is not a box dummy: the real credential stays in the proxy")
    if fam == "codex" and ee:
        errs.append("the codex box gets its dummy auth as a tmpfs file over stdin, not as exec env")
    if spec.get("comparator_file") and role != "probe":
        errs.append("only a probe may name its own comparator file (canarycheck); real boxes use the host's")
    put = spec.get("codex_put") or {}
    if "auth_env" in put:
        errs.append("codex_put.auth_env is retired: the box's dummy auth comes from codex_put.auth_file")
    return errs


def validate_launch(spec: dict) -> list[str]:
    """validate_spec plus what only a real launch has: the box container's name and the credential
    proxy container it must share its internal network with (the inspect evidence names both)."""
    errs = validate_spec(spec)
    if not (isinstance(spec.get("name"), str) and spec["name"]):
        errs.append("the box needs a container name")
    if not (isinstance(spec.get("proxy_name"), str) and PROXY_NAME_RE.match(spec["proxy_name"])):
        errs.append("proxy_name must name the box's scout-deep-proxy-<id> container (runtime evidence)")
    return errs
    return errs


# ---- runtime evidence: what docker says the containers and networks ARE (P4, F2) ----------------

def _norm_container(c: dict) -> dict:
    hc, cfg = c.get("HostConfig") or {}, c.get("Config") or {}
    mounts = [{"type": m.get("Type"), "destination": m.get("Destination"), "rw": m.get("RW") is True,
               "source": m.get("Name") if m.get("Type") == "volume" else m.get("Source")}
              for m in c.get("Mounts") or []]
    return {"name": (c.get("Name") or "").lstrip("/"), "id": c.get("Id"), "image": c.get("Image"),
            "running": (c.get("State") or {}).get("Running") is True, "user": cfg.get("User") or "",
            "privileged": hc.get("Privileged") is True, "readonly_rootfs": hc.get("ReadonlyRootfs") is True,
            "cap_add": sorted(hc.get("CapAdd") or []), "cap_drop": sorted(hc.get("CapDrop") or []),
            "security_opt": sorted(hc.get("SecurityOpt") or []), "network_mode": hc.get("NetworkMode"),
            "networks": sorted(((c.get("NetworkSettings") or {}).get("Networks") or {}).keys()),
            "pid_mode": hc.get("PidMode") or "", "ipc_mode": hc.get("IpcMode") or "",
            "uts_mode": hc.get("UTSMode") or "", "userns_mode": hc.get("UsernsMode") or "",
            "devices": len(hc.get("Devices") or []), "device_requests": len(hc.get("DeviceRequests") or []),
            "mounts": sorted(mounts, key=lambda m: (m["destination"] or "", m["source"] or "")),
            "tmpfs": sorted((hc.get("Tmpfs") or {}).keys())}


def _norm_network(n: dict) -> dict:
    return {"id": n.get("Id"), "internal": n.get("Internal") is True, "driver": n.get("Driver"),
            "members": sorted((v or {}).get("Name") or "" for v in (n.get("Containers") or {}).values())}


def collect_runtime_evidence(box: str, proxy: str | None) -> dict:
    """`docker inspect` of the box and its credential proxy, and `docker network inspect` of every
    network either is on, normalized to the fields the launch policy speaks about."""
    q = {"capture_output": True, "text": True, "stdin": subprocess.DEVNULL, "timeout": 60}
    ev = {"evidence_version": "inspect/1", "taken_at": now(), "box_name": box, "proxy_name": proxy,
          "box": None, "proxy": None, "networks": {}}
    try:
        p = subprocess.run(["docker", "inspect", box, *([proxy] if proxy else [])], **q)
        if p.returncode != 0:
            return {**ev, "error": "container_inspect_failed"}
        cs = {x["name"]: x for x in (_norm_container(c) for c in json.loads(p.stdout))}
        ev["box"], ev["proxy"] = cs.get(box), cs.get(proxy) if proxy else None
        nets = sorted({n for c in cs.values() for n in c["networks"]})
        if nets:
            p = subprocess.run(["docker", "network", "inspect", *nets], **q)
            if p.returncode != 0:
                return {**ev, "error": "network_inspect_failed"}
            ev["networks"] = {n.get("Name"): _norm_network(n) for n in json.loads(p.stdout)}
    except (subprocess.TimeoutExpired, ValueError, TypeError, KeyError, AttributeError):
        return {**ev, "error": "inspect_unreadable"}
    return ev


def _hardened(c: dict, who: str) -> list[str]:
    r = []
    if c.get("privileged") is not False:
        r.append(f"inspect_{who}_privileged")
    if c.get("readonly_rootfs") is not True:
        r.append(f"inspect_{who}_rootfs_writable")
    if "ALL" not in (c.get("cap_drop") or []) or c.get("cap_add"):
        r.append(f"inspect_{who}_capabilities")
    so = c.get("security_opt") or []
    if not so or any(x not in NNP_FORMS for x in so):
        r.append(f"inspect_{who}_security_options")
    if c.get("pid_mode") or c.get("uts_mode") or c.get("userns_mode") or c.get("ipc_mode") not in SAFE_IPC:
        r.append(f"inspect_{who}_shares_a_host_namespace")
    if c.get("devices") or c.get("device_requests"):
        r.append(f"inspect_{who}_has_devices")
    if c.get("running") is not True:
        r.append(f"inspect_{who}_not_running")
    return r


def _mounts_match(c: dict, declared: list[dict]) -> bool:
    want = sorted((m["destination"], not m["ro"], m["source"]) for m in declared)
    have = sorted((m.get("destination"), m.get("rw"), m.get("source")) for m in c.get("mounts") or [])
    return want == have


FAKE_UPSTREAM_RE = re.compile(r"^scout-deep-fake-[A-Za-z0-9][A-Za-z0-9_.-]*$")


def evidence_problems(ev, *, box_args, box_name: str | None, proxy_args=None, proxy_name: str | None = None,
                      role: str | None = None) -> list[str]:
    """Compare the inspect evidence with the DECLARED launch: the box's run vector always; the
    proxy's run vector when it is known (release: the runtime descriptor), else the proxy is judged
    against the launch policy alone (launch time). Reason codes; empty = the evidence agrees.
    Only a probe box (netcheck/canarycheck) may share its proxy's EGRESS network with the
    launcher's fake upstream (scout-deep-fake-<id>); a reviewer's or auditor's never."""
    if not isinstance(ev, dict):
        return ["runtime_evidence_missing"]
    if ev.get("error"):
        return [f"runtime_evidence_{ev['error']}"]
    r: list[str] = []
    bo = parse_run(box_args)["opts"]
    box, px, nets = ev.get("box") or {}, ev.get("proxy") or {}, ev.get("networks") or {}
    if not box or not box_name or ev.get("box_name") != box_name or box.get("name") != box_name:
        r.append("inspect_box_missing")
    if not px or not proxy_name or ev.get("proxy_name") != proxy_name or px.get("name") != proxy_name:
        r.append("inspect_proxy_missing")
    if r:
        return r
    # the box: hardening, the declared uid, network, mounts and tmpfs
    r += _hardened(box, "box")
    if box.get("user") != BOX_UID or box.get("user") != eff(bo, "--user"):
        r.append("inspect_box_user_not_the_declared_uid")
    net = eff(bo, "--network")
    if box.get("network_mode") != net or box.get("networks") != [net]:
        r.append("inspect_box_network_not_declared")
    n = nets.get(net)
    if not n:
        r.append("inspect_box_network_missing")
    else:
        if n.get("internal") is not True:
            r.append("inspect_box_network_not_internal")
        if n.get("members") != sorted([box_name, proxy_name]):
            r.append("inspect_box_network_members_not_box_and_proxy")
    if not _mounts_match(box, declared_volumes(bo)):
        r.append("inspect_box_mounts_not_declared")
    if box.get("tmpfs") != sorted(v.split(":", 1)[0] for v in bo.get("--tmpfs") or []):
        r.append("inspect_box_tmpfs_not_declared")
    # the proxy: hardening, never root, its two networks, and (when declared) mounts and tmpfs
    r += _hardened(px, "proxy")
    if _is_root(px.get("user")):
        r.append("inspect_proxy_runs_as_root")
    others = [x for x in px.get("networks") or [] if x != net]
    if net not in (px.get("networks") or []) or len(others) != 1 or not NET_EG_RE.match(others[0]):
        r.append("inspect_proxy_networks_not_box_and_egress")
    else:
        eg_members = [m for m in (nets.get(others[0]) or {}).get("members") or []
                      if not (role == "probe" and FAKE_UPSTREAM_RE.match(m))]
        if eg_members != [proxy_name]:
            r.append("inspect_egress_network_members_not_proxy_only")
    if proxy_args is not None:
        po = parse_run(proxy_args)["opts"]
        if eff(po, "--name") != proxy_name:
            r.append("inspect_proxy_not_the_declared_container")
        eg = eff(po, "--network")
        if px.get("network_mode") != eg or sorted(px.get("networks") or []) != sorted([eg, net]):
            r.append("inspect_proxy_network_not_declared")
        if "--user" in po and px.get("user") != eff(po, "--user"):
            r.append("inspect_proxy_user_not_declared")
        if not _mounts_match(px, declared_volumes(po)):
            r.append("inspect_proxy_mounts_not_declared")
        if px.get("tmpfs") != sorted(v.split(":", 1)[0] for v in po.get("--tmpfs") or []):
            r.append("inspect_proxy_tmpfs_not_declared")
    return r


def _real_values(fam) -> list[str]:
    try:
        return deeplib.admitted_credentials(fam) if fam in ("claude", "codex") else []
    except deeplib.ComparatorMissing:
        return []


DUMP_SCRIPT = ('for d in /home/reviewer /tmp /work /out; do [ -d "$d" ] && tar -cf - "$d" 2>/dev/null; done; '
               'for p in /proc/[0-9]*; do cat "$p/environ" "$p/cmdline" 2>/dev/null; printf "\\n"; done')


def box_dump_scan(name: str, fam: str, dummy_values: list[str], compare: list[str] | None = None) -> dict:
    """R3 test (a), on every box: before the box is removed, dump its writable filesystem (every
    tmpfs: HOME, /tmp, /work, /out) and every process's environment and argv, plus `docker diff`
    and `docker inspect`, and scan the bytes on the host BY VALUE for the real credential. The dump
    is held in memory only (it holds repo text): the record is counts."""
    try:
        real, comp = (compare, True) if compare else (deeplib.admitted_credentials(fam), True)
    except deeplib.ComparatorMissing:
        real, comp = [], False
    try:
        q = {"capture_output": True, "stdin": subprocess.DEVNULL}
        d = subprocess.run(["docker", "exec", name, "sh", "-c", DUMP_SCRIPT], timeout=120, **q)
        diff = subprocess.run(["docker", "diff", name], timeout=60, **q)
        insp = subprocess.run(["docker", "inspect", name], timeout=60, **q)
    except subprocess.TimeoutExpired:
        return {"bytes": 0, "comparator": comp, "real_windows_hit": None, "error": "dump_timeout"}
    blob = d.stdout + diff.stdout + insp.stdout
    excl = deeplib.structural_windows(real, dummy_values)
    return {"bytes": len(d.stdout), "comparator": comp, "real_values_compared": len(real),
            "real_windows_hit": deeplib.scan_by_value(blob, real, excl),
            "structural_windows_excluded": len(excl),
            "dummy_seen": deeplib.scan_by_value(blob, dummy_values) > 0,
            "docker_diff_entries": len([l for l in diff.stdout.splitlines() if l.strip()]),
            "sources": ["tmpfs /home/reviewer /tmp /work /out", "/proc/*/environ+cmdline", "docker diff",
                        "docker inspect"]}


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
    errs = validate_launch(spec)
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
    started_box = False
    container_image = None
    evidence, meta_problems = None, []
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
            started_box = True
            # R4: the image this container ACTUALLY runs (its own view), compared at release with the
            # descriptor and images.lock.json
            ci = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", name], capture_output=True, text=True,
                                stdin=subprocess.DEVNULL)
            container_image = ci.stdout.strip() if ci.returncode == 0 else None
            # P4 (F2): what docker says the box, its proxy and their networks ARE, before any turn.
            # A box whose effective containment differs from its declaration never gets a prompt.
            evidence = collect_runtime_evidence(name, spec["proxy_name"])
            problems = evidence_problems(evidence, box_args=spec["run_args"], box_name=name,
                                         proxy_name=spec["proxy_name"], role=role)
            if problems:
                meta_problems = problems
                err = "runtime_evidence_rejected"
                (raw / "session.stderr").write_text("runtime evidence: " + "; ".join(problems) + "\n")
                print("session: runtime evidence rejected: " + "; ".join(problems), file=sys.stderr)
                return 1
            if fam == "codex":
                put = spec.get("codex_put") or {}
                try:
                    b64 = jload(Path(put["auth_file"]))["auth_b64"]
                except (KeyError, OSError, ValueError):
                    b64 = ""
                if not b64 or deeplib.BOX_MARKER not in __import__("base64").b64decode(b64).decode("utf-8", "replace"):
                    err = "codex_dummy_auth_missing"
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
            for n, v in (spec.get("exec_env") or {}).items():
                exec_env += ["-e", f"{n}={v}"]    # a dummy value (validated), never a host variable
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
                # stdin_sha256: the exact bytes this turn was given (the input binding, R1/R4)
                rec = {"turn": turn, "kind": kind, "exit": rc, "seconds": round(time.monotonic() - t0, 1),
                       "stdin_sha256": deeplib.sha256_bytes(prompt)}
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
        except _Stopped:
            err, rc = "stopped_by_signal", 143
        finally:
            dump = None
            if started_box:
                dvals = []
                if spec.get("dummy_file"):
                    with contextlib.suppress(OSError, ValueError, KeyError):
                        dvals = jload(Path(spec["dummy_file"]))["values"]
                comp_vals = None
                if role == "probe" and spec.get("comparator_file"):     # canarycheck: the canary
                    comp_vals = jload(Path(spec["comparator_file"]))["values"]
                dump = box_dump_scan(name, fam, dvals, comp_vals)
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            meta = jload(meta_file) if meta_file.exists() else {}
            meta.update({"exit": rc, "timed_out": timed_out, "session_error": err, "session_started": started,
                         "session_ended": now(), "turns": turns,
                         "repair_turns_used": sum(1 for t in turns if t["kind"] == "repair"),
                         "max_repair": max_repair, "receipts_by_turn": receipts_log,
                         "contract_version": meta.get("contract_version") or deeplib.contract_version()})
            if fam == "claude":
                meta["cost_usd"] = round(cost, 4)
            meta["box_dump"] = dump
            meta["container_image_id"] = container_image
            meta["runtime_evidence"] = evidence
            if err == "runtime_evidence_rejected":
                meta["runtime_evidence_problems"] = meta_problems
            # R1: the terminal receipt. Written only here, at the very end of the session and in one
            # atomic write together with the exit, so a driver killed before this point leaves the
            # prelaunch record with no exit and no receipt, which every consumer rejects. It binds
            # the session's output: the sha256 of every raw turn file as the session ended.
            meta["terminal"] = {"written_at": now(), "exit": rc, "timed_out": timed_out, "session_error": err,
                                "turn_files": {t.name: deeplib.sha256_file(t)
                                               for t in deeplib.turn_files(raw, fam)},
                                "stdin_sha256": [t["stdin_sha256"] for t in turns],
                                # P4 (F2): the inspect evidence is bound by the receipt
                                "runtime_evidence_sha256": deeplib.canon_sha(evidence) if evidence else None}
            jdump(meta_file, meta)
    return rc if err is None else (rc if rc != 0 else 1)


class _Stopped(BaseException):
    """SIGTERM/SIGHUP/SIGINT: unwind through run_session's finally (box removed, raw resealed)."""


def _on_signal(signum, _frame):
    raise _Stopped(signum)


def main() -> None:
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, _on_signal)
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    spec = jload(Path(sys.argv[2]))
    if sys.argv[1] == "validate":
        errs = validate_launch(spec)
        print("OK" if not errs else "\n".join(errs))
        sys.exit(0 if not errs else 1)
    sys.exit(run_session(spec))


if __name__ == "__main__":
    main()
