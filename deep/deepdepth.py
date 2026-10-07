#!/usr/bin/env python3
"""scout deep review, P2: reading depth. Stdlib only.

Three things, all host-side and deterministic:

1. CLASSIFY (before any run). Every admitted manifest file gets a path/extension class and a
   `required` flag (code, config and agent prose are required). This is written into the
   manifest next to the file's frozen sha256, so the core-file set exists before a reviewer
   starts and cannot be argued with afterwards.

2. PLAN. Each family gets a per-file reading budget: the chunks (line ranges) in which each
   required file should be read so every chunk stays under that family's tool-output caps.

3. RECEIPTS. What the reviewer actually received, computed from the TRUSTED tool log (the
   harness's own record of tool calls and their results), never from the reviewer's coverage
   label. A line counts as read only when the text the tool returned for it equals that line of
   the frozen file. So truncation (a capped Read, a long line cut short, codex's middle
   truncation of big outputs) is accounted for by construction: what was not returned intact
   is not credited, and every required file lists its missing ranges.

The limit that stays: bytes supplied to a model are not comprehension. A complete receipt
proves the reviewer was handed every line of every required file, not that it understood them.

  receipts <pair_dir> <family>   (re)compute <family>/read-receipts.json from the sealed raw log
"""
from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

DEEP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DEEP_DIR))
import deeplib  # noqa: E402
from deeplib import jdump, jload, now, unsealed  # noqa: E402

LIMIT_NOTE = ("bytes supplied are not comprehension: a complete receipt proves every line of every "
              "required file was returned to the reviewer by its tool layer, not that it understood them")


def load_policy() -> dict:
    return jload(DEEP_DIR / "depth-policy.json")


# --------------------------------------------------------------------------- 1. classify

CODE_EXT = {
    "py", "pyi", "pyw", "sh", "bash", "zsh", "fish", "ksh", "js", "mjs", "cjs", "ts", "mts", "cts", "tsx",
    "jsx", "go", "rs", "rb", "php", "java", "kt", "kts", "swift", "m", "mm", "c", "h", "cc", "cpp", "cxx",
    "hpp", "hh", "hxx", "cs", "fs", "scala", "clj", "cljs", "ex", "exs", "erl", "hrl", "hs", "lua", "pl",
    "pm", "r", "jl", "dart", "vue", "svelte", "sql", "ps1", "psm1", "psd1", "bat", "cmd", "nix", "el",
    "vim", "applescript", "groovy", "gradle", "tf", "hcl", "awk", "sed", "html", "htm", "css", "scss",
    "sass", "less", "zig", "nim", "v", "sol", "wasm", "wat", "ipynb", "mk", "cmake", "bzl", "star",
}
CONFIG_EXT = {
    "json", "jsonc", "json5", "yaml", "yml", "toml", "ini", "cfg", "conf", "config", "service", "timer",
    "socket", "path", "mount", "target", "plist", "xml", "properties", "env", "npmrc", "editorconfig",
    "gitattributes", "gitignore", "dockerignore", "nvmrc", "tool-versions", "desktop",
}
CODE_NAMES = {"dockerfile", "containerfile", "makefile", "gnumakefile", "rakefile", "gemfile", "justfile",
              "vagrantfile", "procfile", "brewfile", "cmakelists.txt", "build", "workspace", "jenkinsfile",
              "crontab", "pkgbuild", "configure"}
CONFIG_NAMES = {"requirements.txt", "constraints.txt", "pipfile", "setup.cfg", ".npmrc", ".yarnrc",
                ".gitignore", ".gitattributes", ".dockerignore", ".editorconfig", ".env", "codeowners",
                ".tool-versions", ".python-version", ".nvmrc", ".pre-commit-config.yaml"}
LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "cargo.lock", "gemfile.lock", "go.sum", "composer.lock", "uv.lock", "pipfile.lock",
              "flake.lock", "bun.lockb", "mix.lock", "pubspec.lock", "podfile.lock"}
AGENT_NAMES = {"claude.md", "agents.md", "gemini.md", "codex.md", "copilot-instructions.md", ".cursorrules",
               ".windsurfrules", ".clinerules", "skill.md", "memory.md", "system-prompt.md", "system_prompt.md",
               "instructions.md", "conventions.md"}
AGENT_DIRS = {".claude", ".codex", ".cursor", ".windsurf", ".clinerules", ".gemini", ".agents", "skills",
              "agents", "prompts", "rules", "commands", "memory", ".github/instructions"}
PROSE_EXT = {"md", "mdx", "markdown", "rst", "txt", "adoc", "org", "tex"}
AGENT_EXT = {"mdc", "prompt"}
DATA_EXT = {"csv", "tsv", "svg", "log", "lock", "sum", "pem", "pub"}


def file_class(rel: str, text: str = "") -> str:
    """code | config | agent_prose | lockfile | doc | data | other. Decided by path and extension,
    plus one content rule: a `#!` first line makes an extension-less file code."""
    low = rel.lower()
    base = low.rsplit("/", 1)[-1]
    parts = low.split("/")[:-1]
    ext = base.rsplit(".", 1)[-1] if "." in base.lstrip(".") else ""
    if base in LOCK_NAMES or base.endswith(".lock"):
        return "lockfile"
    if base in AGENT_NAMES or ext in AGENT_EXT or base.endswith(".prompt.md"):
        return "agent_prose"
    joined = "/".join(parts)
    if ext in PROSE_EXT and (any(p in AGENT_DIRS for p in parts) or any(d in joined for d in AGENT_DIRS if "/" in d)):
        return "agent_prose"
    if base in CODE_NAMES or base.startswith("dockerfile") or ext in CODE_EXT:
        return "code"
    if base in CONFIG_NAMES or base.startswith(".env") or ext in CONFIG_EXT:
        return "config"
    if ".github/workflows" in joined or (parts and parts[0] in {"hooks", "bin", "scripts"} and not ext):
        return "code" if not ext else ("config" if ext in {"yml", "yaml"} else "code")
    if text.startswith("#!"):
        return "code"
    if ext in PROSE_EXT or base in {"license", "licence", "copying", "notice", "authors", "changelog", "readme"}:
        return "doc"
    if ext in DATA_EXT:
        return "data"
    return "other"


def classify_manifest(files: dict, box: Path, policy: dict | None = None) -> dict:
    """Adds class + required to each manifest entry in place; returns the summary block."""
    policy = policy or load_policy()
    req = set(policy["required_classes"])
    n_req, req_lines, req_bytes = 0, 0, 0
    for rel, ent in files.items():
        head = (box / rel).read_text(encoding="utf-8")[:64]
        ent["class"] = file_class(rel, head)
        ent["required"] = ent["class"] in req
        if ent["required"]:
            n_req += 1
            req_lines += ent["lines"]
            req_bytes += ent["bytes"]
    return {"policy_version": policy["policy_version"], "required_classes": sorted(req),
            "required_files": n_req, "required_lines": req_lines, "required_bytes": req_bytes,
            "rule": "required = class in required_classes; class from path/extension (plus a #! first line), "
                    "fixed before the run"}


# --------------------------------------------------------------------------- 2. plan

def file_lines(text: str) -> list[str]:
    if text == "":
        return []
    ls = text.split("\n")
    if text.endswith("\n"):
        ls = ls[:-1]
    return ls


def chunks_for(lines: list[str], chunk_lines: int, chunk_bytes: int) -> list[tuple[int, int]]:
    """1-based inclusive line ranges, each <= chunk_lines lines and (unless one line is bigger)
    <= chunk_bytes bytes."""
    out, start, size = [], 1, 0
    for i, ln in enumerate(lines, 1):
        b = len(ln.encode()) + 1
        if i > start and (i - start >= chunk_lines or size + b > chunk_bytes):
            out.append((start, i - 1))
            start, size = i, 0
        size += b
    if lines:
        out.append((start, len(lines)))
    return out


def reading_plan(manifest: dict, box: Path, family: str, policy: dict | None = None) -> list[dict]:
    policy = policy or load_policy()
    fam = policy[family]
    plan = []
    for rel in sorted(manifest["files"]):
        ent = manifest["files"][rel]
        if not ent.get("required"):
            continue
        lines = file_lines((box / rel).read_text(encoding="utf-8"))
        plan.append({"path": rel, "lines": len(lines), "chunks": chunks_for(lines, fam["chunk_lines"], fam["chunk_bytes"])})
    return plan


def render_plan(plan: list[dict], family: str) -> str:
    rows = []
    for p in plan:
        if not p["chunks"]:
            rows.append(f"{p['path']} (empty)")
            continue
        rng = ", ".join(f"{a}-{b}" for a, b in p["chunks"])
        rows.append(f"{p['path']} ({p['lines']} lines): {rng}")
    return "\n".join(rows)


# --------------------------------------------------------------------------- 3. receipts

CLAUDE_NUM_RE = re.compile(r"^\s*(\d+)(?:\t|→)(.*)$")       # Read: "12\tcode" (or "  12→code")
NUM_RE = re.compile(r"^\s*(\d+)(?:\t|:|-| {2,})(.*)$")              # nl -ba / cat -n / grep -n
SED_RANGE_RE = re.compile(r"\bsed\s+-n\s+['\"]?(\d+)\s*,\s*(\d+)\s*p")
HEAD_RE = re.compile(r"\bhead\s+(?:-n\s*|-)(\d+)")
TAIL_PLUS_RE = re.compile(r"\btail\s+-n\s*\+(\d+)")
TRUNC_MARKER_RE = re.compile(r"tokens truncated|chars truncated|truncated output|bytes omitted|lines omitted", re.I)


class Ledger:
    """Per-file set of credited line numbers, built across every turn of one family's run."""

    def __init__(self, manifest: dict, box: Path):
        self.manifest = manifest
        self.files = manifest["files"]
        self.lines: dict[str, list[str]] = {}
        for rel, ent in self.files.items():
            data = (box / rel).read_bytes()
            if deeplib.sha256_bytes(data) != ent["sha256"]:
                raise ValueError(f"box file no longer matches its frozen manifest hash: {rel}")
            self.lines[rel] = [l.rstrip("\r") for l in file_lines(data.decode("utf-8"))]
        self.read: dict[str, set[int]] = {rel: set() for rel in self.files}
        self.sources: dict[str, dict[str, int]] = {rel: {} for rel in self.files}
        self.calls = 0
        self.unparsed = 0
        self.truncation_seen = 0

    def credit(self, rel: str, n: int, text: str, source: str) -> bool:
        fl = self.lines.get(rel)
        if fl is None or not (1 <= n <= len(fl)) or text.rstrip("\r") != fl[n - 1]:
            return False
        self.read[rel].add(n)
        self.sources[rel][source] = self.sources[rel].get(source, 0) + 1
        return True

    # -- alignment of an unnumbered block of output lines against one file ------------------
    def align(self, rel: str, block: list[str], source: str, hint_start: int | None, policy: dict) -> int:
        fl = self.lines.get(rel)
        if not fl or not block:
            return 0
        got = 0
        i = 0
        if hint_start and 1 <= hint_start <= len(fl) and block[0].rstrip("\r") == fl[hint_start - 1]:
            j = hint_start - 1
            while i < len(block) and j < len(fl) and block[i].rstrip("\r") == fl[j]:
                got += self.credit(rel, j + 1, block[i], source)
                i += 1
                j += 1
        index: dict[str, list[int]] = {}
        for k, t in enumerate(fl):
            index.setdefault(t, []).append(k)
        min_run = policy.get("anchored_run_min_lines", 3)
        min_chars = policy.get("anchored_single_line_min_chars", 30)
        while i < len(block):
            t = block[i].rstrip("\r")
            pos = index.get(t, [])
            if len(t.strip()) >= 6 and len(pos) == 1:
                j = pos[0]
                run = 0
                while i + run < len(block) and j + run < len(fl) and block[i + run].rstrip("\r") == fl[j + run]:
                    run += 1
                if run >= min_run or (run >= 1 and len(t.strip()) >= min_chars):
                    for k in range(run):
                        got += self.credit(rel, j + k + 1, block[i + k], source)
                    i += run
                    continue
            i += 1
        return got

    # -- path-prefixed / numbered lines ------------------------------------------------------
    def path_prefixed(self, line: str) -> tuple[str, int, str] | None:
        """`/repo/a/b.py:12:text` or `a/b.py:12-text` (grep/rg with file names)."""
        body = line[len("/repo/"):] if line.startswith("/repo/") else line
        for m in re.finditer(r":(\d+)[:-]", body):
            rel = body[:m.start()]
            if rel in self.files:
                return rel, int(m.group(1)), body[m.end():]
        return None

    def report(self, family: str, contract_version: str, turns: int, policy: dict) -> dict:
        files_out = {}
        req = [r for r, e in self.files.items() if e.get("required")]
        req_lines = sum(len(self.lines[r]) for r in req)
        req_read = 0
        all_lines = sum(len(v) for v in self.lines.values())
        all_read = 0
        for rel in sorted(self.files):
            ent = self.files[rel]
            n = len(self.lines[rel])
            got = self.read[rel]
            ranges = _ranges(sorted(got))
            missing = _ranges([k for k in range(1, n + 1) if k not in got])
            bytes_read = sum(len(self.lines[rel][k - 1].encode()) + 1 for k in got)
            complete = len(got) == n
            all_read += len(got)
            if ent.get("required"):
                req_read += len(got)
            files_out[rel] = {"sha256": ent["sha256"], "lines": n, "bytes": ent["bytes"],
                              "class": ent.get("class"), "required": bool(ent.get("required")),
                              "lines_read": len(got), "bytes_read": min(bytes_read, ent["bytes"]),
                              "complete": complete, "read_ranges": ranges[:200], "read_range_count": len(ranges),
                              "missing_ranges": missing[:200], "missing_range_count": len(missing),
                              "credited_by": self.sources[rel]}
        incomplete = sorted(r for r in req if not files_out[r]["complete"])
        return {
            "family": family, "computed_at": now(), "contract_version": contract_version,
            "manifest_sha256": self.manifest["manifest_sha256"], "turns": turns,
            "tool_calls_examined": self.calls, "commands_unparsed": self.unparsed,
            "truncation_markers_seen": self.truncation_seen,
            "required_files": len(req), "required_complete": len(req) - len(incomplete),
            "required_incomplete": incomplete,
            "required_lines": req_lines, "required_lines_read": req_read,
            "all_files": len(self.files), "all_lines": all_lines, "all_lines_read": all_read,
            "credit_rule": "a line is credited only if the text the tool returned for it equals that "
                           "line of the frozen file; codex output above "
                           f"{policy['codex']['credit_whole_output_bytes']} bytes is credited only in its first "
                           f"and last {policy['codex']['credit_head_tail_bytes']} bytes (middle truncation)",
            "limit": LIMIT_NOTE,
            "files": files_out,
        }


def _ranges(nums: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for n in nums:
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return out


def _repo_rel(p: str, files: dict) -> str | None:
    if not isinstance(p, str):
        return None
    import os
    norm = os.path.normpath(p)
    if norm.startswith("/repo/"):
        rel = norm[len("/repo/"):]
        return rel if rel in files else None
    return None


# ---- claude: Read / Grep tool calls and their results -------------------------------------

def _result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text")
    return ""


def claude_turn_events(path: Path) -> list[dict]:
    ev = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                ev.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return ev


def credit_claude(ledger: Ledger, events: list[dict], policy: dict) -> None:
    uses: dict[str, dict] = {}
    for e in events:
        msg = e.get("message") if isinstance(e.get("message"), dict) else {}
        content = msg.get("content") if isinstance(msg.get("content"), list) else []
        if e.get("type") == "assistant":
            for c in content:
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    uses[c.get("id")] = c
        elif e.get("type") == "user":
            for c in content:
                if not (isinstance(c, dict) and c.get("type") == "tool_result"):
                    continue
                use = uses.get(c.get("tool_use_id"))
                if not use or c.get("is_error"):
                    continue
                name, inp = use.get("name"), use.get("input") or {}
                text = _result_text(c.get("content"))
                ledger.calls += 1
                if TRUNC_MARKER_RE.search(text):
                    ledger.truncation_seen += 1
                if name == "Read":
                    rel = _repo_rel(inp.get("file_path"), ledger.files)
                    if not rel:
                        continue
                    for ln in text.split("\n"):
                        m = CLAUDE_NUM_RE.match(ln)
                        if m:
                            ledger.credit(rel, int(m.group(1)), m.group(2), "Read")
                elif name == "Grep":
                    single = _repo_rel(inp.get("path"), ledger.files)
                    for ln in text.split("\n"):
                        pp = ledger.path_prefixed(ln)
                        if pp:
                            ledger.credit(pp[0], pp[1], pp[2], "Grep")
                            continue
                        m = NUM_RE.match(ln)
                        if m and single:
                            ledger.credit(single, int(m.group(1)), m.group(2), "Grep")


# ---- codex: shell commands and their aggregated output -------------------------------------

def _inner_command(cmd: str) -> str:
    """codex wraps every command as `/usr/bin/bash -lc '<script>'`; unwrap one level."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return cmd
    if len(argv) >= 3 and argv[0].endswith(("bash", "sh", "zsh")) and argv[1] in ("-lc", "-c"):
        return argv[2]
    return cmd


def _candidates(inner: str, files: dict) -> list[str]:
    found = []
    for tok in re.findall(r"(?:/repo/)[^\s'\"|;&<>)(]+", inner):
        rel = tok[len("/repo/"):].rstrip("/")
        if rel in files:
            found.append(rel)
    if re.search(r"\bcd\s+/repo\b", inner) or re.search(r"-C\s+/repo\b", inner):
        for tok in re.findall(r"[^\s'\"|;&<>)(]+", inner):
            t = tok[2:] if tok.startswith("./") else tok
            if t in files:
                found.append(t)
    return list(dict.fromkeys(found))


def _credit_window(output: str, policy: dict) -> list[list[str]]:
    """Blocks of output lines the model is credited with having received. Above the whole-output
    threshold only the head and tail byte windows count (codex truncates the middle)."""
    c = policy["codex"]
    data = output.encode()
    if len(data) <= c["credit_whole_output_bytes"]:
        return [output.split("\n")]
    head = data[: c["credit_head_tail_bytes"]].decode("utf-8", "ignore").split("\n")[:-1]
    tail = data[-c["credit_head_tail_bytes"]:].decode("utf-8", "ignore").split("\n")[1:]
    return [head, tail]


def credit_codex(ledger: Ledger, commands: list[dict], policy: dict) -> None:
    for c in commands:
        out = c.get("output") or ""
        if c.get("exit_code") not in (0, None) and not out:
            continue
        ledger.calls += 1
        inner = _inner_command(c.get("command") or "")
        cands = _candidates(inner, ledger.files)
        if TRUNC_MARKER_RE.search(out):
            ledger.truncation_seen += 1
        m = SED_RANGE_RE.search(inner)
        hint = int(m.group(1)) if m else None
        if hint is None and (re.search(r"\bcat\b", inner) or HEAD_RE.search(inner)):
            hint = 1
        mt = TAIL_PLUS_RE.search(inner)
        if hint is None and mt:
            hint = int(mt.group(1))
        any_credit = 0
        for block in _credit_window(out, policy):
            plain: list[str] = []
            for ln in block:
                pp = ledger.path_prefixed(ln)
                if pp:
                    any_credit += ledger.credit(pp[0], pp[1], pp[2], "command")
                    continue
                mn = NUM_RE.match(ln)
                if mn and len(cands) == 1 and ledger.credit(cands[0], int(mn.group(1)), mn.group(2), "command"):
                    any_credit += 1
                    continue
                plain.append(ln)
            for rel in cands:
                any_credit += ledger.align(rel, plain, "command", hint if len(cands) == 1 else None, policy)
        if not any_credit and cands:
            ledger.unparsed += 1


# ---- per family, across turns --------------------------------------------------------------

turn_files = deeplib.turn_files


def compute(raw: Path, box: Path, manifest: dict, family: str, contract_version: str,
            policy: dict | None = None) -> dict:
    policy = policy or load_policy()
    ledger = Ledger(manifest, box)
    tf = turn_files(raw, family)
    for p in tf:
        if family == "claude":
            credit_claude(ledger, claude_turn_events(p), policy)
        else:
            credit_codex(ledger, deeplib.parse_codex_events(p)["commands"], policy)
    return ledger.report(family, contract_version, len(tf), policy)


def repair_message(rec: dict, family: str, max_entries: int) -> str:
    """The host-driven repair turn. Host data only: manifest paths and line ranges."""
    rows = []
    for rel in rec["required_incomplete"]:
        f = rec["files"][rel]
        rng = ", ".join(f"{a}-{b}" for a, b in f["missing_ranges"][:12])
        more = f["missing_range_count"] - min(12, f["missing_range_count"])
        rows.append(f"{rel}: lines {rng}" + (f" (+{more} more ranges)" if more > 0 else "")
                    + f" [{f['lines_read']}/{f['lines']} lines received]")
    extra = len(rows) - max_entries
    rows = rows[:max_entries]
    how = ("Use Read with offset and limit, in chunks small enough that nothing is cut off."
           if family == "claude" else
           "Print them with `nl -ba /repo/PATH | sed -n 'A,Bp'`, at most 250 lines per command, "
           "so nothing is truncated.")
    return ("HOST CHECK (from your tool log, not your coverage labels): these REQUIRED files or line "
            "ranges have not yet been returned to you in full.\n\n" + "\n".join(rows)
            + (f"\n(+{extra} more files)" if extra > 0 else "")
            + f"\n\nRead exactly these ranges now. {how} Then return your complete review again as the "
              "JSON object the output schema requires, with every field, updated for what you read. "
              "The ground rules from the start of this session still apply.")


def cmd_receipts(pair_dir: str, family: str) -> None:
    pd = Path(pair_dir)
    fd = pd / family
    manifest = jload(pd / "manifest.json")
    with unsealed(fd / "raw") as raw:
        rec = compute(raw, pd / "box" / "repo", manifest, family, manifest.get("contract_version", "unknown"))
    jdump(fd / "read-receipts.json", rec)
    print(f"receipts {family}: required {rec['required_complete']}/{rec['required_files']} complete, "
          f"lines {rec['required_lines_read']}/{rec['required_lines']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    {"receipts": cmd_receipts}[sys.argv[1]](*sys.argv[2:])
