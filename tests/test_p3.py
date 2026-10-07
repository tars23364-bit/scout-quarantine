"""P3: Serafina's EDIT/HOLD (2026-10-06, R1-R4) as tests. Stdlib only; no model, no network.

SeraProbesInverted  her eight probes (assessment/probes.py on the C2 control copies) turned into
                    regression tests. Her probes ASSERT that a defect reproduces; these assert the
                    opposite, so each one FAILS on C2 (ca774fbf) and must PASS on C3. Her fixture
                    shape is reproduced here (invented records only), and each unsafe case must be
                    rejected for the SPECIFIC missing evidence, not for an incidental reason.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
DEEP = HERE.parent / "deep"
sys.path.insert(0, str(DEEP))
import deepaudit  # noqa: E402
import deepdepth  # noqa: E402
import deepgate  # noqa: E402
import deeplib  # noqa: E402

C2 = "ca774fbfa682eba729e5641374d8dddce17ac6660ec4bd39fdad567b1fe6adfd"
PASS = {"audit_result": "PASS", "confidence": "HIGH", "concerns": []}


def put(p, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj))


def sera_fixture(pd):
    """Her fixture (probes.py `fixture`), with the current contract version: a synthetic pair whose
    every record is present and PASS-shaped, so a release decision turns only on what each probe
    removes or adds."""
    cv = deeplib.contract_version()
    put(pd / "pair.json", {"id": "synthetic-pair", "families": ["claude", "codex"]})
    put(pd / "manifest.json", {"contract_version": cv, "manifest_sha256": "a" * 64, "files": {}})
    put(pd / "source-pin.json", {"tarball_sha256": "b" * 64, "commit": "c" * 40})
    for fam, other in (("claude", "codex"), ("codex", "claude")):
        fd = pd / fam
        put(fd / "run-meta.json", {"family": fam, "model": "fixture-model", "reviewer_cli_version": "fixture-v1",
                                   "exit": 0, "timed_out": False})
        body = b'{"synthetic":true}\n'
        (fd / "report").mkdir()
        (fd / "report/report.json").write_bytes(body)
        put(fd / "gate.json", {"verdict": "PASS", "contract_version": cv, "report_sha256": deeplib.sha256_bytes(body),
                               "gated_raw_sha256": "d" * 64, "receipts_sha256": "e" * 64,
                               "rules": {"9_read_depth": {"result": "PASS"}}})
        put(fd / "box-checks.json", {"verdict": "PASS"})
        put(fd / "audit-run.json", {"auditor": other, "model": "fixture-auditor", "cli_version": "v1",
                                    "contract_version": cv, "exit": 0})
        b = deepgate.binding(pd, fam)
        put(fd / "audit.json", dict(PASS, auditor_family=other, binding=b, binding_sha256=deepgate.binding_sha256(b)))
        deeplib.seal(fd / "report")


def sera_make_audit(pd, failed=False):
    """Her `make_audit`: the host's PRE-LAUNCH audit-run shape (no exit, no terminal receipt) and a
    PASS agent message with no turn.completed (or with turn.failed)."""
    cv = deeplib.contract_version()
    fd = pd / "claude"
    put(fd / "audit-meta.json", {"reviewer_family": "claude", "auditor_family": "codex"})
    put(fd / "audit-run.json", {"auditor": "codex", "model": "fixture-auditor", "cli_version": "v1", "contract_version": cv})
    ad = fd / "audit"
    ad.mkdir()
    events = [{"type": "item.completed", "item": {"id": "1", "type": "agent_message", "text": json.dumps(PASS)}}]
    if failed:
        events.append({"type": "turn.failed", "error": {"message": "synthetic failure"}})
    (ad / "turn-1.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    (fd / "audit-allowlist.txt").write_text("chatgpt.com\n")
    (fd / "audit-proxy.log").write_text("2026-10-07T00:00:00+0000 client CONNECT chatgpt.com:443 200 TCP_TUNNEL 10\n")
    deeplib.seal(ad)


def open_all(pd):
    gen = Path(pd) / "gen"
    if gen.exists():
        os.chmod(gen, 0o700)
        for g in gen.iterdir():
            os.chmod(g, 0o700)
    for p in sorted(Path(pd).rglob("*"), key=lambda x: len(x.parts)):
        with contextlib.suppress(OSError):
            if p.is_dir() and not p.is_symlink():
                os.chmod(p, 0o700)
    with contextlib.suppress(OSError):
        os.chmod(pd, 0o700)


def readable_report_files(pd):
    """Every report body a same-uid reader can open WITHOUT changing any mode: the R2 invariant is
    that this is empty before the commit, and holds both reports (or none) after it."""
    out = []
    for root, dirs, files in os.walk(pd):
        if "raw" in Path(root).parts:
            continue
        for f in files:
            if f.endswith(".json") and ("report" in f or Path(root).name == "report"):
                p = Path(root) / f
                try:
                    with open(p, "rb") as fh:
                        body = fh.read()
                except OSError:
                    continue
                if b"synthetic" in body or b"deep-report" in body:
                    out.append(p)
    return out


class SeraProbesInverted(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.pd = Path(self.t.name)

    def tearDown(self):
        open_all(self.pd)
        self.t.cleanup()

    def parse(self, fam="claude"):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as e:
                deepaudit.cmd_parse(str(self.pd), fam)
        return e.exception.code, deeplib.jload(self.pd / fam / "audit.json")

    # probe 01 asserted the contract hash IS C2. C3 is a new, logged version.
    def test_p01_contract_moved_off_C2_and_is_logged_as_C3(self):
        v = deeplib.contract_version()
        self.assertNotEqual(v, C2)
        self.assertEqual(deeplib.contract_entry(v), "C3")

    # probe 02: prelaunch audit-run (no exit) + PASS message without turn.completed -> parse said
    # PASS (exit 0) and release_state admitted the pair. Now: not PASS, and release names why.
    def test_p02_audit_without_terminal_receipt_is_rejected(self):
        sera_fixture(self.pd)
        sera_make_audit(self.pd)
        code, a = self.parse()
        self.assertNotEqual(code, 0)
        self.assertNotEqual(a["audit_result"], "PASS")
        ok, _, reasons = deepgate.release_state(self.pd)
        self.assertFalse(ok)
        self.assertTrue(any(r.startswith("claude: audit completion:") and "auditor_exit" in r for r in reasons), reasons)
        self.assertTrue(any(r.startswith("claude: audit completion:") and "terminal" in r for r in reasons), reasons)

    # probe 03: turn.failed was parsed (turn_failed True) but the audit parser still said PASS.
    def test_p03_failed_auditor_turn_is_not_PASS(self):
        ad = self.pd
        events = [{"type": "item.completed", "item": {"id": "1", "type": "agent_message", "text": json.dumps(PASS)}},
                  {"type": "turn.failed", "error": {"message": "invented"}}]
        (ad / "turn-1.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
        self.assertTrue(deeplib.parse_codex_events(ad / "turn-1.jsonl")["turn_failed"])
        self.assertNotEqual(deepaudit.parse_reply("codex", ad)["audit_result"], "PASS")
        # same with a completed turn followed by nothing else is still not enough for codex: the
        # terminal event must be turn.completed with no turn.failed
        (ad / "turn-1.jsonl").write_text(json.dumps(events[0]) + "\n")
        self.assertNotEqual(deepaudit.parse_reply("codex", ad)["audit_result"], "PASS")
        # and the Claude family: a result event that is an error is not a terminal success
        (ad / "turn-1.jsonl").write_text(json.dumps({"type": "result", "subtype": "error_during_execution",
                                                     "is_error": True, "structured_output": PASS}) + "\n")
        self.assertNotEqual(deepaudit.parse_reply("claude", ad)["audit_result"], "PASS")

    # probe 04: no audit-run, no audit allowlist, no audit proxy log -> parse PASS and release ok.
    def test_p04_missing_audit_run_and_egress_records_are_rejected(self):
        sera_fixture(self.pd)
        sera_make_audit(self.pd)
        for n in ("audit-run.json", "audit-allowlist.txt", "audit-proxy.log"):
            (self.pd / "claude" / n).unlink()
        code, a = self.parse()
        self.assertNotEqual(code, 0)
        self.assertNotEqual(a["audit_result"], "PASS")
        ok, _, reasons = deepgate.release_state(self.pd)
        self.assertFalse(ok)
        joined = " | ".join(reasons)
        self.assertIn("audit_run_missing", joined)
        self.assertIn("audit_egress", joined)

    # probe 05: a hard exit right after the first unseal published one report (0700) with the other
    # 000 and no release.json. Her exact hook (unseal wrapped, os._exit after its first call) must
    # no longer be able to leave exactly one readable report.
    def test_p05_hard_exit_inside_release_never_publishes_one_report(self):
        sera_fixture(self.pd)
        code = '''import os,sys
sys.path.insert(0,sys.argv[1])
import deepgate
real=deepgate.unseal
def crash_after_first(p):
    real(p)
    os._exit(73)
deepgate.unseal=crash_after_first
deepgate.cmd_release(sys.argv[2])
'''
        subprocess.run([sys.executable, "-B", "-c", code, str(DEEP), str(self.pd)], capture_output=True, timeout=30)
        readable = readable_report_files(self.pd)
        self.assertNotEqual(len(readable), 1, f"exactly one report readable: {readable}")
        self.assertEqual(readable, [], "her synthetic fixture lacks C3 evidence, so nothing may be readable")

    # probe 06 was a positive probe (incomplete read FAILs rule 9, a complete numbered read PASSes);
    # it must keep passing.
    def test_p06_depth_credit_positive_and_negative_still_hold(self):
        root = self.pd
        body = "alpha = 1\nbeta = 2\n"
        (root / "core.py").write_text(body)
        m = {"manifest_sha256": "f" * 64, "files": {"core.py": {"sha256": deeplib.sha256_bytes(body.encode()), "bytes": len(body),
                                                               "lines": 2, "class": "code", "required": True}}}
        led = deepdepth.Ledger(m, root)
        pol = deepdepth.load_policy()
        deepdepth.credit_codex(led, [{"command": "cat /repo/core.py", "output": "alpha = 1\n", "exit_code": 0}], pol)
        self.assertEqual(deepgate.depth_rule(led.report("codex", "cv", 1, pol), m)["result"], "FAIL")
        deepdepth.credit_codex(led, [{"command": "nl -ba /repo/core.py", "output": "1\talpha = 1\n2\tbeta = 2\n", "exit_code": 0}], pol)
        self.assertEqual(deepgate.depth_rule(led.report("codex", "cv", 1, pol), m)["result"], "PASS")

    # probe 07: an absent admitted-credential input gave an EMPTY comparison set (zero comparisons
    # read as "no disclosure"). Now the comparator must exist: absent input is an error.
    def test_p07_missing_credential_comparator_is_an_error_not_an_empty_set(self):
        missing = getattr(deeplib, "ComparatorMissing", None)
        self.assertIsNotNone(missing, "no ComparatorMissing error type: an absent comparator is not an error")
        for fam in ("claude", "codex"):
            with patch.dict(os.environ, {}, clear=True):
                try:
                    got = deeplib.admitted_credentials(fam)
                except missing:
                    continue
                self.fail(f"{fam}: absent credential input returned a comparison set {got!r}")

    # probe 08: changing the effective allowlist after the audit left the binding and the release
    # decision unchanged. Now the allowlist as mounted is bound.
    def test_p08_effective_allowlist_is_bound(self):
        sera_fixture(self.pd)
        fd = self.pd / "claude"
        (fd / "allowlist.txt").write_text("api.anthropic.com\n")
        before = deepgate.binding_sha256(deepgate.binding(self.pd, "claude"))
        (fd / "allowlist.txt").write_text("different.invalid\n")
        after = deepgate.binding_sha256(deepgate.binding(self.pd, "claude"))
        self.assertNotEqual(before, after)
        self.assertFalse(deepgate.release_state(self.pd)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)


# =========================================================================== R1: audit completion
sys.path.insert(0, str(HERE))
from deepfixture import AUDIT, GATE, LIB, Pair, run  # noqa: E402


class AuditCompletionR1(unittest.TestCase):
    """Release requires, per family, a re-derived successful terminal audit: identity, terminal
    receipt + terminal event, input and output binding, egress proof. Both families audited."""

    def setUp(self):
        self.p = Pair(("claude", "codex"))
        self.p.write_claude_evidence(self.p.report("claude"))
        self.p.write_codex_evidence(self.p.report("codex"))
        for fam in ("claude", "codex"):
            self.p.check(fam)
            self.assertEqual(self.p.gate(fam)[0], 0)

    def tearDown(self):
        self.p.cleanup()

    def release(self):
        q = run(GATE, "release", str(self.p.pd), ok=False)
        return q.returncode, json.loads((self.p.pd / "release.json").read_text())

    def both_complete(self):
        for fam in ("claude", "codex"):
            rc, a = self.p.audit(fam)
            self.assertEqual((rc, a["audit_result"], a["completion"]["ok"]), (0, "PASS", True), a.get("completion"))

    def assertSealedFor(self, fam, code):
        rc, rel = self.release()
        self.assertEqual((rc, rel["status"]), (4, "SEALED"))
        self.assertTrue(any(r.startswith(f"{fam}: audit completion:") and code in r for r in rel["reasons"]), rel["reasons"])

    def test_complete_audits_of_both_families_release(self):
        self.both_complete()
        rc, rel = self.release()
        self.assertEqual((rc, rel["status"]), (0, "RELEASED"), rel.get("reasons"))
        for fam in ("claude", "codex"):
            self.assertEqual(rel["families"][fam]["audit_completion"], "OK")

    def test_sera_case_prelaunch_audit_run_without_exit(self):
        self.both_complete()
        fd = self.p.pd / "claude"
        a = json.loads((fd / "audit-run.json").read_text())
        prelaunch = {k: a[k] for k in ("auditor", "model", "cli_version", "contract_version")}
        (fd / "audit-run.json").write_text(json.dumps(prelaunch))
        self.assertSealedFor("claude", "auditor_exit_missing")
        self.assertSealedFor("claude", "auditor_terminal_receipt_missing")
        rc, a = run(AUDIT, "parse", str(self.p.pd), "claude", ok=False).returncode, None
        self.assertNotEqual(rc, 0)

    def test_sera_case_missing_audit_run_and_egress_records(self):
        self.both_complete()
        for n in ("audit-run.json", "audit-allowlist.txt", "audit-proxy.log"):
            (self.p.pd / "codex" / n).unlink()
        rc, rel = self.release()
        self.assertEqual(rel["status"], "SEALED")
        j = " | ".join(rel["reasons"])
        for code in ("codex: audit completion: audit_run_missing", "audit_egress_allowlist_missing", "audit_egress_log_missing"):
            self.assertIn(code, j)

    def test_sera_case_codex_turn_failed(self):
        # the claude report is audited by codex: PASS message, then turn.failed
        rc, a = self.p.audit("claude", stream=[
            {"type": "thread.started", "thread_id": "aud"}, {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "m", "type": "agent_message", "text": json.dumps(PASS)}},
            {"type": "turn.failed", "error": {"message": "synthetic"}}])
        self.assertEqual((rc, a["audit_result"]), (1, "INCONCLUSIVE"))
        self.p.audit("codex")
        self.assertSealedFor("claude", "auditor_terminal_event_missing_or_failed")

    def test_claude_auditor_error_result_or_missing_result(self):
        self.p.audit("claude")
        for stream in ([{"type": "system", "subtype": "init", "model": "m"},
                        {"type": "result", "subtype": "error_max_turns", "is_error": True, "structured_output": PASS}],
                       [{"type": "system", "subtype": "init", "model": "m"},
                        {"type": "assistant", "message": {"content": [{"type": "text", "text": json.dumps(PASS)}]}}]):
            rc, a = self.p.audit("codex", stream=stream)
            self.assertEqual(a["audit_result"], "INCONCLUSIVE")
            self.assertSealedFor("codex", "auditor_terminal_event_missing_or_failed")

    def test_nonzero_exit_timeout_or_session_error_in_the_receipt(self):
        for over, code in (({"exit": 1}, "auditor_exit_not_zero"), ({"exit": True}, "auditor_exit_not_zero"),
                           ({"timed_out": True}, "auditor_timed_out"), ({"session_error": "driver_exception:X"},
                                                                         "auditor_session_error")):
            self.p.audit("claude")
            self.p.audit("codex", run_over=over)
            self.assertSealedFor("codex", code)

    def test_stream_or_prompt_changed_after_the_terminal_receipt(self):
        self.both_complete()
        with deeplib.unsealed(self.p.pd / "claude" / "audit") as d:
            with open(d / "turn-1.jsonl", "a") as f:
                f.write("\n")
        self.assertSealedFor("claude", "auditor_stream_changed_since_terminal_receipt")
        self.both_complete()
        with deeplib.unsealed(self.p.pd / "codex" / "audit") as d:
            (d / "prompt.txt").write_text((d / "prompt.txt").read_text() + "x")
        self.assertSealedFor("codex", "auditor_input")

    def test_audit_json_result_alone_is_never_trusted(self):
        rc, a = self.p.audit("claude", stream=[{"type": "thread.started"}, {"type": "turn.started"},
                                               {"type": "turn.failed", "error": {"message": "x"}}])
        self.p.audit("codex")
        a["audit_result"], a["completion"] = "PASS", {"ok": True, "reasons": []}
        (self.p.pd / "claude" / "audit.json").write_text(json.dumps(a))
        rc, rel = self.release()
        self.assertEqual(rel["status"], "SEALED")
        self.assertTrue(any("claude: audit completion:" in r for r in rel["reasons"]), rel["reasons"])

    def test_auditor_identity_and_egress_policy(self):
        self.both_complete()
        self.p.audit("codex", run_over={"auditor": "codex"})  # a codex report audited by codex
        self.assertSealedFor("codex", "auditor_identity_missing_or_wrong")
        self.p.audit("codex", run_over={"model": ""})
        self.assertSealedFor("codex", "auditor_model_missing")
        self.p.audit("codex")
        (self.p.pd / "codex" / "audit-allowlist.txt").write_text("api.anthropic.com\nexample.org\n")
        self.assertSealedFor("codex", "audit_egress_allowlist_not_contract")


class AuditHardInterruptR1(unittest.TestCase):
    """A real SIGKILL of the auditor's session driver mid-turn: no terminal receipt is written, so
    parse cannot say PASS and release refuses, for both auditor families."""

    def test_sigkill_before_terminal_persistence(self):
        import shutil
        import signal
        import time
        for fam, auditor in (("claude", "codex"), ("codex", "claude")):
            p = Pair(("claude", "codex"))
            b = Path(tempfile.mkdtemp())
            try:
                p.write_claude_evidence(p.report("claude"))
                p.write_codex_evidence(p.report("codex"))
                for f in ("claude", "codex"):
                    p.check(f)
                    p.gate(f)
                p.audit(fam, parse=False)  # complete evidence first ...
                fd = p.pd / fam
                cv = json.loads((p.pd / "manifest.json").read_text())["contract_version"]
                # ... then the real launcher's prelaunch record, and a real driver run that is killed
                (fd / "audit-run.json").write_text(json.dumps({"auditor": auditor, "model": "m", "cli_version": "1",
                                                               "contract_version": cv}))
                shutil.copy(HERE / "fakedocker.py", b / "docker")
                os.chmod(b / "docker", 0o755)
                log = b / "calls.jsonl"
                spec = {"family": auditor, "role": "auditor", "name": f"fake-aud-{fam}", "raw_dir": str(fd / "audit"),
                        "fd": str(fd), "meta_file": str(fd / "audit-run.json"), "timeout": 60, "max_repair": 0,
                        "prompt_sealed": "prompt.txt",
                        "run_args": ["--network", "scout-deep-int-x", "--read-only", "--cap-drop", "ALL", "--security-opt",
                                     "no-new-privileges", "--user", "10001:10001", "img", "idle"],
                        "cli": [auditor, "-p"] if auditor == "claude" else ["codex", "exec", "--json", "-"]}
                if auditor == "codex":
                    spec["codex_put"] = {"auth_env": "SCOUT_CODEX_AUTH_B64"}
                else:
                    spec["exec_env"] = ["CLAUDE_CODE_OAUTH_TOKEN"]
                (b / "spec.json").write_text(json.dumps(spec))
                env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "FAKE_DOCKER_LOG": str(log), "FAKE_PAIR": str(p.pd),
                       "FAKE_MODE": "sleep", "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-not-real",
                       "SCOUT_CODEX_AUTH_B64": "e30="}
                proc = subprocess.Popen([sys.executable, str(DEEP / "deepsession.py"), "run", str(b / "spec.json")], env=env)
                for _ in range(200):
                    if log.exists() and auditor in log.read_text() and '"exec"' in log.read_text():
                        break
                    time.sleep(0.05)
                os.kill(proc.pid, signal.SIGKILL)
                proc.wait(timeout=20)
                rec = json.loads((fd / "audit-run.json").read_text())
                self.assertNotIn("exit", rec)
                self.assertNotIn("terminal", rec)
                q = run(AUDIT, "parse", str(p.pd), fam, ok=False)
                a = json.loads((fd / "audit.json").read_text())
                self.assertEqual((q.returncode, a["audit_result"]), (1, "INCONCLUSIVE"))
                self.assertIn("auditor_terminal_receipt_missing", a["completion"]["reasons"])
                other = "codex" if fam == "claude" else "claude"
                p.audit(other)
                q = run(GATE, "release", str(p.pd), ok=False)
                rel = json.loads((p.pd / "release.json").read_text())
                self.assertEqual((q.returncode, rel["status"]), (4, "SEALED"))
                self.assertTrue(any(f"{fam}: audit completion: auditor_exit_missing" in r for r in rel["reasons"]))
            finally:
                shutil.rmtree(b)
                p.cleanup()


# =========================================================================== R2: crash-atomic release
def discoverable_reports(pd):
    """Report bodies a reader can open by LISTING and following paths (current symlink included),
    without changing any mode."""
    found = {}
    cands = []
    for root, dirs, files in os.walk(pd, followlinks=True):
        if "raw" not in Path(root).parts:
            cands += [Path(root) / f for f in files if f.endswith("report.json")]
    cands += [Path(pd) / "current" / f for f in ("claude.report.json", "codex.report.json")]
    for c in cands:
        try:
            with open(c, "rb") as fh:
                if b"deep-report" in fh.read():
                    st = os.fstat(fh.fileno())
                    found[(st.st_dev, st.st_ino)] = str(c)
        except OSError:
            pass
    return sorted(found.values())


class CrashAtomicReleaseR2(unittest.TestCase):
    """A REAL SIGKILL of the release process at each publication boundary. Invariant: before the
    commit nothing is admitted and nothing is discoverable-readable; after it both are admitted (or
    neither), never one."""

    def setUp(self):
        self.p = Pair(("claude", "codex"))
        self.p.write_claude_evidence(self.p.report("claude"))
        self.p.write_codex_evidence(self.p.report("codex"))
        for fam in ("claude", "codex"):
            self.p.check(fam)
            self.assertEqual(self.p.gate(fam)[0], 0)
            self.assertEqual(self.p.audit(fam)[0], 0)

    def tearDown(self):
        self.p.cleanup()

    def kill_at(self, point):
        env = {**os.environ, "DEEP_TEST_CRASHPOINT": point}
        q = subprocess.run([sys.executable, str(DEEP / "deepgate.py"), "release", str(self.p.pd)],
                           env=env, capture_output=True, timeout=60)
        self.assertEqual(q.returncode, -9, f"{point}: the release process was not hard-killed")

    def gens(self):
        g = self.p.pd / "gen"
        os.chmod(g, 0o700)
        try:
            return {x.name: os.stat(x).st_mode & 0o777 for x in g.iterdir()}
        finally:
            os.chmod(g, 0o300)

    def test_kill_before_the_commit_admits_and_exposes_nothing(self):
        for point in ("after_first_report", "after_second_report", "before_rename"):
            seen = set(self.gens()) if (self.p.pd / "gen").exists() else set()
            self.kill_at(point)
            new = {g: m for g, m in self.gens().items() if g not in seen}
            self.assertEqual(len(new), 1, point)
            self.assertFalse((self.p.pd / "current").exists(), point)
            with self.assertRaises(deepgate.NotCommitted):
                deepgate.admit(self.p.pd)
            self.assertEqual(discoverable_reports(self.p.pd), [], point)
            self.assertEqual(os.stat(self.p.pd / "gen").st_mode & 0o777, 0o300, "the staging root is unlistable")
            for fam in ("claude", "codex"):
                self.assertEqual(os.stat(self.p.pd / fam / "report").st_mode & 0o777, 0, f"{point}: {fam} gate output")
            if point == "before_rename":
                self.assertEqual(list(new.values()), [0], "at the commit point the generation is 0000")
            else:
                # disclosed residual: a kill mid-build leaves that build 0700 (its links 0400) under the
                # unlistable 0300 root with an unguessable name; never admitted, sealed by the next release
                self.assertEqual(list(new.values()), [0o700])
        # recovery: a fresh release commits both, and the orphans of the killed attempts are sealed
        q = run(GATE, "release", str(self.p.pd), ok=False)
        self.assertEqual(q.returncode, 0, q.stdout + q.stderr)
        rel, reports = deepgate.admit(self.p.pd)
        self.assertEqual((rel["status"], sorted(reports)), ("RELEASED", ["claude", "codex"]))
        cur = os.readlink(self.p.pd / "current").split("/")[1]
        self.assertTrue(all(m == 0 for g, m in self.gens().items() if g != cur))

    def test_kill_after_the_commit_admits_both(self):
        self.kill_at("after_rename")
        self.assertTrue((self.p.pd / "current").is_symlink())
        self.assertEqual(discoverable_reports(self.p.pd), [], "committed but still 0000: neither readable")
        rel, reports = deepgate.admit(self.p.pd)          # completes the interrupted reveal
        self.assertEqual((rel["status"], sorted(reports)), ("RELEASED", ["claude", "codex"]))
        self.assertEqual(len(discoverable_reports(self.p.pd)), 2, "after the commit: both")
        for fam in ("claude", "codex"):
            self.assertEqual(rel["reports"][fam]["sha256"], deeplib.sha256_bytes(reports[fam]))
            self.assertEqual(rel["reports"][fam]["sha256"], rel["families"][fam]["report_sha256"])
            self.assertIn("binding_sha256", rel["families"][fam])

    def test_normal_release_exposes_both_together_and_records_both_hashes(self):
        q = run(GATE, "release", str(self.p.pd), ok=False)
        self.assertEqual(q.returncode, 0)
        self.assertEqual(len(discoverable_reports(self.p.pd)), 2)
        rel = json.loads((self.p.pd / "release.json").read_text())
        self.assertEqual(sorted(rel["reports"]), ["claude", "codex"])
        self.assertTrue((self.p.pd / "release.json").is_symlink())

    def test_reader_refuses_a_generation_whose_report_changed(self):
        run(GATE, "release", str(self.p.pd))
        gd = self.p.pd / "gen" / os.readlink(self.p.pd / "current").split("/")[1]
        os.chmod(gd, 0o700)
        f = gd / "codex.report.json"
        os.chmod(f, 0o600)
        f.write_text('{"schema_version": "deep-report/2", "tampered": true}')
        with self.assertRaises(deepgate.NotCommitted):
            deepgate.admit(self.p.pd)
        q = run(GATE, "deliver", str(self.p.pd), ok=False)
        self.assertNotEqual(q.returncode, 0)
        q = run(GATE, "read", str(self.p.pd), "claude", ok=False)
        self.assertNotEqual(q.returncode, 0, "all or nothing: an intact claude report is not admitted either")

    def test_sealed_outcome_commits_a_record_and_no_report(self):
        (self.p.pd / "codex" / "audit-proxy.log").unlink()
        q = run(GATE, "release", str(self.p.pd), ok=False)
        self.assertEqual(q.returncode, 4)
        rel, reports = deepgate.admit(self.p.pd)
        self.assertEqual((rel["status"], reports, rel["reports"]), ("SEALED", {}, {}))
        self.assertEqual(discoverable_reports(self.p.pd), [])
