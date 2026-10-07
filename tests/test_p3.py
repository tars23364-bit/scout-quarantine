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
