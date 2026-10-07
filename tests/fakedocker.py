#!/usr/bin/env python3
"""A fake `docker` for the session-driver tests (tests/test_p2.py). It logs every call to
$FAKE_DOCKER_LOG and plays a reviewer CLI on `docker exec`:

  FAKE_MODE=lazy     turn 1 Reads only the first half of every box file; a turn whose stdin is a
                     host repair message Reads exactly the ranges it names
  FAKE_MODE=never    every turn Reads only the first half (repair never completes)
  FAKE_MODE=sleep    the CLI hangs (timeout path)
  FAKE_MODE=crash    the CLI exits 137 with no output (box crash path)

P4 (F2): `docker run -d --name X <args>` is remembered, and `docker inspect` / `docker network
inspect` answer in docker's own JSON shape, synthesized from those args by a parser written here
(independent of deepsession's, so the evidence is not the code under test agreeing with itself).
The box's credential proxy (any name scout-deep-proxy-*) is a hardened proxy on the box's network
and its own egress network. FAKE_INSPECT (comma list) injects what docker would then report:
  box_root box_privileged box_writable box_caps box_other_network box_extra_mount
  net_external net_extra_member proxy_privileged proxy_root proxy_extra_network

Claude turns emit stream-json with numbered Read results; codex turns emit exec --json events
with `nl -ba ... | sed -n` commands. The report is a minimal object (the driver does not judge it).
"""
import json
import os
import re
import sys
import time
from pathlib import Path

LOG = Path(os.environ.get("FAKE_DOCKER_LOG", "/nonexistent/calls.jsonl"))
PD = Path(os.environ.get("FAKE_PAIR", "/nonexistent"))
MODE = os.environ.get("FAKE_MODE", "lazy")
STATE = LOG.with_name(LOG.name + ".containers.json")
ALIAS = {"-v": "--volume", "-e": "--env", "-u": "--user", "--net": "--network", "-l": "--label", "-m": "--memory"}
BOOL = {"--read-only", "--privileged", "-d", "--detach", "--rm", "-i", "-t"}


def run_opts(args):
    """docker run's own reading of an option vector: {option: [values]}, ends at the image."""
    o, i = {}, 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-"):
            break
        if a.startswith("--"):
            k, eq, v = a.partition("=")
        elif len(a) > 2:
            k, eq, v = a[:2], "=", a[2:].lstrip("=")
        else:
            k, eq, v = a, "", ""
        k = ALIAS.get(k, k)
        if k in BOOL:
            o.setdefault(k, []).append(v.lower() if eq else "true")
        else:
            if not eq:
                i += 1
                v = args[i] if i < len(args) else ""
            o.setdefault(k, []).append(v)
        i += 1
    return o


def _last(o, k, default=None):
    return (o.get(k) or [default])[-1]


def container_json(name, args, image_id="sha256:" + "0" * 64, faults=()):
    """One `docker inspect` entry for a container started with these run args."""
    o = run_opts(args)
    caps = sorted({c.strip().upper() for v in o.get("--cap-drop", []) for c in v.split(",")})
    mounts = []
    for v in o.get("--volume", []):
        src, dst, *rest = v.split(":")
        vol = not src.startswith("/")
        mounts.append({"Type": "volume" if vol else "bind", "Source": f"/var/lib/docker/volumes/{src}/_data" if vol else src,
                       **({"Name": src} if vol else {}), "Destination": dst, "RW": not (rest and "ro" in rest[0].split(","))})
    net = _last(o, "--network", "default")
    c = {"Id": "c" * 64, "Name": "/" + name, "Image": image_id, "State": {"Running": True},
         "Config": {"User": _last(o, "--user", "")},
         "HostConfig": {"Privileged": _last(o, "--privileged", "false") == "true",
                        "ReadonlyRootfs": _last(o, "--read-only", "false") == "true",
                        "CapAdd": None, "CapDrop": caps or None, "SecurityOpt": o.get("--security-opt") or None,
                        "NetworkMode": net, "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "",
                        "Devices": [], "Tmpfs": {v.split(":", 1)[0]: (v.split(":", 1) + [""])[1] for v in o.get("--tmpfs", [])}},
         "Mounts": mounts, "NetworkSettings": {"Networks": {net: {}}}}
    hc = c["HostConfig"]
    if "box_root" in faults:
        c["Config"]["User"] = "0:0"
    if "box_privileged" in faults:
        hc["Privileged"] = True
    if "box_writable" in faults:
        hc["ReadonlyRootfs"] = False
    if "box_caps" in faults:
        hc["CapDrop"], hc["CapAdd"] = None, ["SYS_ADMIN"]
    if "box_other_network" in faults:
        c["NetworkSettings"]["Networks"]["bridge"] = {}
    if "box_extra_mount" in faults:
        c["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": True})
    return c


def proxy_json(name, box_net, image_id="sha256:" + "1" * 64, faults=(), args=None):
    """The box's credential proxy: from its run args when known, else the launcher's hardened shape."""
    eg = "scout-deep-eg-" + name.removeprefix("scout-deep-proxy-")
    args = args or ["--name", name, "--network", eg, "--read-only", "--cap-drop", "ALL", "--security-opt",
                    "no-new-privileges", "--tmpfs", "/run/credproxy:rw,size=1m", "--tmpfs", "/tmp:rw,size=16m",
                    "-v", "/fixture/config.json:/etc/credproxy/config.json:ro",
                    "-v", "/fixture/allowlist.txt:/etc/credproxy/allowlist.txt:ro", "scout/deep-credproxy:latest"]
    c = container_json(name, args, image_id)
    c["Config"]["User"] = c["Config"]["User"] or "credproxy"          # the image's own USER
    c["NetworkSettings"]["Networks"][box_net] = {}
    if "proxy_privileged" in faults:
        c["HostConfig"]["Privileged"] = True
    if "proxy_root" in faults:
        c["Config"]["User"] = "root"
    if "proxy_extra_network" in faults:
        c["NetworkSettings"]["Networks"]["bridge"] = {}
    return c


def network_json(name, containers, faults=()):
    members = {c["Id"][:12] + str(i): {"Name": c["Name"].lstrip("/")} for i, c in enumerate(containers)
               if name in c["NetworkSettings"]["Networks"]}
    internal = name.startswith("scout-deep-int-") and "net_external" not in faults
    if name.startswith("scout-deep-int-") and "net_extra_member" in faults:
        members["intruder"] = {"Name": "someone-else"}
    return {"Name": name, "Id": "n" * 64, "Driver": "bridge", "Internal": internal, "Containers": members}


def _faults():
    return tuple(x for x in os.environ.get("FAKE_INSPECT", "").split(",") if x)


def _state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def _inspect(names):
    st, out = _state(), []
    boxes = st.get("boxes", {})
    box = next(iter(boxes), None)
    for n in names:
        if n in boxes:
            out.append(container_json(n, boxes[n], faults=_faults()))
        elif n.startswith("scout-deep-proxy-") and box:
            out.append(proxy_json(n, _last(run_opts(boxes[box]), "--network", "default"), faults=_faults()))
            if n not in st.setdefault("proxies", []):
                st["proxies"].append(n)
                STATE.write_text(json.dumps(st))
        else:
            return None
    return out


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
    if argv[:1] == ["run"] and "--name" in argv:
        args = argv[1:]
        args = [a for a in args if a not in ("-d", "--detach")]
        i = args.index("--name")
        name, rest = args[i + 1], args[:i] + args[i + 2:]
        st = _state()
        st.setdefault("boxes", {})[name] = rest
        STATE.write_text(json.dumps(st))
        print("c" * 64)
        return 0
    if argv[:1] == ["inspect"] and "-f" not in argv:
        got = _inspect(argv[1:])
        if got is None:
            print("Error: No such object", file=sys.stderr)
            return 1
        print(json.dumps(got))
        return 0
    if argv[:2] == ["network", "inspect"]:
        st = _state()
        cs = _inspect(list(st.get("boxes", {})) + list(st.get("proxies", []))) or []
        print(json.dumps([network_json(n, cs, _faults()) for n in argv[2:]]))
        return 0
    if argv[:1] == ["exec"] and "sh" in argv[1:4]:
        # the session driver's box dump (P3): a tar of the tmpfs dirs + process environments
        sys.stdout.write("fake-box-dump\n")
        return 0
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
