"""P4: the peer reviewer's review of the P3/C4 package (2026-10-06, REVISE): F1, F2, F3.

  F1  the session record and its terminal receipt are read strictly (closed schema, every status a
      success, no contradiction with the outer record, empty/non-object/malformed rejected at parse),
      the complete receipt is bound, and release re-derives it itself for BOTH sessions.
  F2  launch declarations are judged on their EFFECTIVE values (docker/CLI option syntax normalized,
      option allowlist), the proxy vector is validated too, and `docker inspect` / `docker network
      inspect` evidence is recorded at launch, refused there on any difference, bound, and compared
      again at release.
  F3  the owner-facing route disclosure lists every route the contract forwards.

Her two malformed-terminal fixtures and four weakened declarations are reproduced here verbatim in
intent (tests named `test_sera_*`); each must end SEALED (or FAIL at parse) with a specific reason.
Run: python3 -m unittest discover -s tests
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
DEEP = HERE.parent / "deep"
sys.path.insert(0, str(DEEP))
sys.path.insert(0, str(HERE))
import deepaudit  # noqa: E402
import deepgate  # noqa: E402
import deeplib  # noqa: E402
import deepsession  # noqa: E402
from deepfixture import AUDIT, GATE, LIB, Pair, run  # noqa: E402

PASS = {"audit_result": "PASS", "confidence": "HIGH", "concerns": []}


def _edit_json(path: Path, fn):
    d = json.loads(path.read_text())
    d = fn(d) or d
    path.write_text(json.dumps(d))


class PairCase(unittest.TestCase):
    """A two-family pair with complete reviewer evidence, checked and gated, audits not yet run."""

    def setUp(self):
        self.p = Pair(("claude", "codex"))
        self.p.write_claude_evidence(self.p.report("claude"))
        self.p.write_codex_evidence(self.p.report("codex"))
        for fam in ("claude", "codex"):
            self.assertEqual(self.p.check(fam)[0], 0)
            self.assertEqual(self.p.gate(fam)[0], 0)

    def tearDown(self):
        self.p.cleanup()

    def fresh(self):
        """A new pair for the next sub-case; the previous one is removed first (no leaked temp dir)."""
        self.p.cleanup()
        self.setUp()

    def release(self):
        q = run(GATE, "release", str(self.p.pd), ok=False)
        return q.returncode, json.loads((self.p.pd / "release.json").read_text())

    def parse(self, fam):
        q = run(AUDIT, "parse", str(self.p.pd), fam, ok=False)
        return q.returncode, json.loads((self.p.pd / fam / "audit.json").read_text())

    def assertSealed(self, *needles):
        rc, rel = self.release()
        self.assertEqual((rc, rel["status"]), (4, "SEALED"), rel.get("reasons"))
        self.assertEqual(rel.get("reports", {}), {})
        joined = " | ".join(rel["reasons"])
        for n in needles:
            self.assertIn(n, joined)
        return rel


# =========================================================================== F1
class TerminalReceiptF1(PairCase):

    def audits_then(self, fam, mutate):
        """Both audits' session evidence written (no parse), then `mutate(audit-run dict)` on fam's
        record, then both parsed: her probe's order."""
        for f in ("claude", "codex"):
            self.p.audit(f, parse=False)
        _edit_json(self.p.pd / fam / "audit-run.json", mutate)
        return {f: self.parse(f) for f in ("claude", "codex")}

    def test_positive_control_complete_receipts_release(self):
        out = self.audits_then("claude", lambda a: a)
        for f in ("claude", "codex"):
            self.assertEqual((out[f][0], out[f][1]["audit_result"]), (0, "PASS"), out[f][1]["completion"])
        rc, rel = self.release()
        self.assertEqual((rc, rel["status"]), (0, "RELEASED"), rel.get("reasons"))
        for f in ("claude", "codex"):
            self.assertEqual((rel["families"][f]["reviewer_session"], rel["families"][f]["audit_session"]), ("OK", "OK"))

    def test_sera_terminal_failure_under_an_outer_success(self):
        def bad(a):
            a["terminal"].update(exit=1, timed_out=True, session_error="synthetic_failed_session")
        out = self.audits_then("claude", bad)
        rc, a = out["claude"]
        self.assertEqual((rc, a["audit_result"], a["completion"]["ok"]), (1, "INCONCLUSIVE", False))
        for code in ("auditor_terminal_exit_not_zero", "auditor_terminal_timed_out", "auditor_terminal_session_error",
                     "auditor_terminal_contradicts_record:exit", "auditor_terminal_contradicts_record:timed_out",
                     "auditor_terminal_contradicts_record:session_error"):
            self.assertIn(code, a["completion"]["reasons"])
        self.assertSealed("claude: audit session: auditor_terminal_exit_not_zero",
                          "claude: audit session: auditor_terminal_contradicts_record:exit",
                          "claude: audit completion: auditor_terminal_timed_out")

    def test_sera_terminal_status_fields_deleted_each_and_all(self):
        fields = ("exit", "timed_out", "session_error", "written_at")
        for drop in [(k,) for k in fields] + [fields]:
            with self.subTest(drop=drop):
                self.fresh()
                out = self.audits_then("claude", lambda a: [a["terminal"].pop(k) for k in drop] and None)
                rc, a = out["claude"]
                self.assertEqual((rc, a["audit_result"]), (1, "INCONCLUSIVE"))
                for k in drop:
                    self.assertIn(f"auditor_terminal_{k}_missing", a["completion"]["reasons"])
                self.assertSealed(*[f"claude: audit session: auditor_terminal_{k}_missing" for k in drop])

    def test_sera_empty_record_fails_at_parse_by_name(self):
        for body, code in (("{}", "audit_run_empty"), ("[]", "audit_run_not_an_object"),
                           ('"PASS"', "audit_run_not_an_object"), ("{", "audit_run_malformed"),
                           ("", "audit_run_malformed")):
            with self.subTest(body=body):
                self.fresh()
                for f in ("claude", "codex"):
                    self.p.audit(f, parse=False)
                (self.p.pd / "claude" / "audit-run.json").write_text(body)
                rc, a = self.parse("claude")
                self.assertEqual((rc, a["audit_result"], a["completion"]["ok"]), (1, "INCONCLUSIVE", False))
                self.assertIn(code, a["completion"]["reasons"])
                self.parse("codex")
                self.assertSealed(f"claude: audit session: {code}", f"claude: audit completion: {code}")

    def test_receipt_schema_is_closed_and_typed(self):
        cases = [
            (lambda a: a["terminal"].update(extra="x"), "auditor_terminal_unknown_field"),
            (lambda a: a["terminal"].update(written_at="yesterday"), "auditor_terminal_written_at_invalid"),
            (lambda a: a["terminal"].update(written_at="2026-13-40T00:00:00Z"), "auditor_terminal_written_at_invalid"),
            (lambda a: a["terminal"].update(exit=True), "auditor_terminal_exit_not_zero"),
            (lambda a: a["terminal"].update(exit="0"), "auditor_terminal_exit_not_zero"),
            (lambda a: a["terminal"].update(timed_out=None), "auditor_terminal_timed_out"),
            (lambda a: a["terminal"].update(session_error=""), "auditor_terminal_session_error"),
            (lambda a: a["terminal"].update(turn_files={}), "auditor_terminal_turn_files_invalid"),
            (lambda a: a["terminal"].update(stdin_sha256=[]), "auditor_terminal_stdin_invalid"),
            (lambda a: a["terminal"].pop("runtime_evidence_sha256"), "auditor_terminal_runtime_evidence_sha256_missing"),
            (lambda a: a.update(turns=[]), "auditor_turns_missing"),
            (lambda a: a["turns"][0].update(exit=1), "auditor_turn_exit_not_zero"),
            (lambda a: a["turns"].append(dict(a["turns"][0])), "auditor_terminal_contradicts_record:turns"),
            (lambda a: a.update(session_ended="2026-10-08T00:00:00Z"), "auditor_terminal_contradicts_record:session_ended"),
            (lambda a: a.pop("session_error"), "auditor_session_error_unrecorded"),
            (lambda a: a.update(terminal="ok"), "auditor_terminal_receipt_missing"),
            (lambda a: a.update(runtime_evidence={**a["runtime_evidence"], "taken_at": "x"}),
             "auditor_terminal_contradicts_record:runtime_evidence"),
        ]
        for mutate, code in cases:
            with self.subTest(code=code):
                self.fresh()
                out = self.audits_then("claude", lambda a: mutate(a) and None)
                self.assertIn(code, out["claude"][1]["completion"]["reasons"])
                self.assertSealed(f"claude: audit session: {code}")

    def test_the_complete_receipt_is_bound(self):
        for f in ("claude", "codex"):
            self.p.audit(f)
        a = json.loads((self.p.pd / "codex" / "audit.json").read_text())
        term = json.loads((self.p.pd / "codex" / "audit-run.json").read_text())["terminal"]
        self.assertEqual(a["audit_receipt"]["terminal"], term)
        self.assertEqual(a["audit_receipt"]["terminal_sha256"], deeplib.canon_sha(term))
        # a receipt edit that stays VALID (another valid timestamp) still breaks the binding
        _edit_json(self.p.pd / "codex" / "audit-run.json",
                   lambda r: r["terminal"].update(written_at="2026-10-07T00:00:01Z"))
        self.assertSealed("codex: audit record does not match its re-derived evidence")

    def test_release_rederives_independently_of_completion(self):
        """Release must not take completion()'s word: with completion() forced to say OK and to
        match audit.json, a failed terminal receipt still seals, from release's own check."""
        for f in ("claude", "codex"):
            self.p.audit(f)
        _edit_json(self.p.pd / "claude" / "audit-run.json", lambda r: r["terminal"].update(exit=1))
        stored = json.loads((self.p.pd / "claude" / "audit.json").read_text())
        real = deepaudit.completion

        def lying(pd, fam, index=None):
            c = real(pd, fam, index)
            if fam == "claude":
                c = {**c, "ok": True, "reasons": [], "verdict": PASS, "verdict_sha256": stored["verdict_sha256"],
                     "receipt_sha256": stored["audit_receipt_sha256"]}
            return c
        with mock.patch.object(deepaudit, "completion", lying):
            ok, fams, reasons = deepgate.release_state(self.p.pd)
        self.assertFalse(ok)
        self.assertIn("claude: audit session: auditor_terminal_exit_not_zero", reasons)
        self.assertEqual(fams["claude"]["audit_session"], "REJECTED")
        self.assertFalse(any(r.startswith("claude: audit completion:") for r in reasons), "the lie held")

    def test_reviewer_session_record_is_checked_and_bound_too(self):
        for f in ("claude", "codex"):
            self.p.audit(f)
        rc, rel = self.release()
        self.assertEqual(rel["status"], "RELEASED", rel.get("reasons"))
        # after binding: any change to the reviewer's receipt moves the binding
        _edit_json(self.p.pd / "codex" / "run-meta.json",
                   lambda r: r["terminal"].update(written_at="2026-10-07T00:00:01Z"))
        self.assertSealed("codex: audit binding does not match the host records (reviewer_terminal_sha256)")

    def test_reviewer_terminal_failure_before_binding_seals(self):
        _edit_json(self.p.pd / "claude" / "run-meta.json",
                   lambda r: r["terminal"].update(exit=137, session_error="driver_exception:X"))
        for f in ("claude", "codex"):
            self.p.audit(f)
        self.assertSealed("claude: reviewer session: reviewer_terminal_exit_not_zero",
                          "claude: reviewer session: reviewer_terminal_contradicts_record:exit",
                          "claude: reviewer session: reviewer_terminal_session_error")
        self.fresh()
        for f in ("claude", "codex"):
            self.p.audit(f)
        for body, code in (("{}", "run_meta_empty"), ("[1]", "run_meta_not_an_object"), ("{", "run_meta_malformed")):
            (self.p.pd / "codex" / "run-meta.json").write_text(body)
            self.assertSealed(f"codex: reviewer session: {code}")


# =========================================================================== F2: launch policy
BOX = ["--network", "scout-deep-int-p", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
       "--user", "10001:10001", "--tmpfs", "/tmp:rw,size=64m", "-e", "HOME=/home/reviewer"]
REPO = ["-v", "/b:/repo:ro"]
PROXY = ["--name", "scout-deep-proxy-p", "--network", "scout-deep-eg-p", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", "--memory", "256m", "--tmpfs", "/run/credproxy:rw,size=1m",
         "-v", "/c.json:/etc/credproxy/config.json:ro", "-v", "/a.txt:/etc/credproxy/allowlist.txt:ro",
         "--label", "scout.quarantine=true", "scout/deep-credproxy:latest"]
CODEX_T1 = ["codex", "exec", "-s", "read-only", "-C", "/work", "--json", "-c", 'sandbox_mode="read-only"', "-"]


class LaunchPolicyF2(unittest.TestCase):
    def spec(self, fam="claude", role="reviewer", run_args=None, cli=None, **kw):
        sp = {"family": fam, "role": role,
              "run_args": run_args if run_args is not None else BOX + (REPO if role == "reviewer" else []) + ["img", "idle"],
              "cli": cli or (["claude", "-p", "--permission-mode", "dontAsk", "--add-dir", "/repo"] if fam == "claude"
                             else CODEX_T1)}
        if fam == "claude":
            sp["exec_env"] = {"CLAUDE_CODE_OAUTH_TOKEN": deeplib.box_dummy("claude")["values"][0]}
        sp.update(kw)
        return sp

    def test_controls_pass(self):
        for fam in ("claude", "codex"):
            for role in ("reviewer", "auditor"):
                self.assertEqual(deepsession.validate_spec(self.spec(fam, role)), [], (fam, role))
        self.assertEqual(deepsession.validate_proxy_run(PROXY), [])
        self.assertEqual(deepsession.validate_spec(self.spec("codex", cli_resume=[
            "codex", "exec", "resume", "{SESSION}", "--json", "-c", 'sandbox_mode="read-only"', "-"])), [])

    def bad_box(self, *run_args, fam="claude", needle=None):
        errs = deepsession.validate_spec(self.spec(fam, run_args=list(run_args)))
        self.assertNotEqual(errs, [], run_args)
        if needle:
            self.assertTrue(any(needle in e for e in errs), (run_args, errs))
        return errs

    def test_sera_root_user_and_every_spelling_of_it(self):
        swap = lambda flag: [x for x in BOX if x not in ("--user", "10001:10001")] + flag + REPO + ["img"]
        for flag in (["--user", "0:0"], ["--user=0:0"], ["-u", "0:0"], ["-u0:0"], ["-u=0"], ["--user", "root"]):
            self.bad_box(*swap(flag), needle="the box runs as 10001:10001 only")
        # repeated: docker applies the LAST value; both the repeat and the effective root are named
        errs = self.bad_box(*(BOX + ["--user=0:0"] + REPO + ["img"]))
        self.assertTrue(any("--user is declared more than once" in e for e in errs), errs)
        self.assertTrue(any("effective --user 0:0" in e for e in errs), errs)
        # a repeat that ends on the right uid is still a refused repeat
        self.bad_box(*(["--user", "0:0"] + BOX + REPO + ["img"]), needle="--user is declared more than once")

    def test_sera_arbitrary_network_and_every_spelling_of_it(self):
        base = [x for x in BOX if x not in ("--network", "scout-deep-int-p")]
        for flag in (["--network", "arbitrary-egress-network"], ["--network=arbitrary-egress-network"],
                     ["--net", "arbitrary-egress-network"], ["--net=bridge"], ["--network", "host"],
                     ["--network", "container:other"], ["--network", "scout-deep-eg-p"]):
            self.bad_box(*(base + flag + REPO + ["img"]), needle="network")
        self.bad_box(*(BOX + ["--network", "bridge"] + REPO + ["img"]), needle="--network is declared more than once")
        self.bad_box(*(base + REPO + ["img"]), needle="network")      # none declared at all

    def test_other_weakened_hardening_on_effective_values(self):
        for extra, needle in (
                (["--read-only=false"], "read-only"), (["--read-only", "false"], None),
                (["--security-opt", "seccomp=unconfined"], "security option"),
                (["--security-opt=no-new-privileges:false"], "security option"),
                (["--security-opt", "apparmor=unconfined"], None), (["--cap-add=SYS_ADMIN"], "forbidden docker run flag --cap-add"),
                (["--privileged"], "forbidden docker run flag --privileged"), (["--privileged=true"], "--privileged"),
                (["--mount", "type=bind,src=/,dst=/host"], "--mount"), (["--gpus", "all"], "not in the launch policy"),
                (["--pid=host"], "--pid"), (["--env-file", "/x"], "--env-file"), (["-v", "/h:/host:ro"], "nothing but /repo"),
                (["--volume=/b2:/repo"], None), (["-e", "CLAUDE_CODE_OAUTH_TOKEN=x"], "credential"),
                (["--env=HTTPS_PROXY=http://p:3128"], "forward proxy"), (["-itd"], "not in the launch policy")):
            with self.subTest(extra=extra):
                self.bad_box(*(BOX + extra + REPO + ["img"]), needle=needle)
        nocap = [x for x in BOX if x not in ("--cap-drop", "ALL")] + ["--cap-drop", "NET_RAW"] + REPO + ["img"]
        self.bad_box(*nocap, needle="cap-drop ALL")

    def test_sera_codex_sandbox_equals_form_and_variants(self):
        for cli in (["codex", "exec", "--sandbox=danger-full-access"],             # her case, verbatim
                    ["codex", "exec", "-sdanger-full-access", "-"], ["codex", "exec", "-s=danger-full-access", "-"],
                    ["codex", "exec", "-s", "read-only", "-s", "danger-full-access", "-"],
                    ["codex", "exec", "--sandbox", "read-only", "--sandbox=workspace-write", "-"],
                    ["codex", "exec", "-s", "read-only", "-c", 'sandbox_mode="danger-full-access"', "-"],
                    ["codex", "exec", "-s", "read-only", "--config=sandbox_mode=danger-full-access", "-"],
                    ["codex", "exec", "-s", "read-only", '-csandbox_mode="workspace-write"', "-"],
                    ["codex", "exec", "--json", "-"],                                   # no sandbox declared
                    ["codex", "exec", "-s"]):                                           # flag with no value
            with self.subTest(cli=cli):
                errs = deepsession.validate_spec(self.spec("codex", cli=cli))
                self.assertTrue(any("sandbox" in e for e in errs), (cli, errs))
        errs = deepsession.validate_spec(self.spec("codex", cli_resume=["codex", "exec", "resume", "{SESSION}", "-"]))
        self.assertTrue(any("cli_resume: the codex sandbox must be declared read-only" in e for e in errs), errs)

    def test_claude_cli_option_syntax_is_normalized(self):
        for cli, needle in ((["claude", "-p", "--permission-mode=bypassPermissions"], "permission mode"),
                            (["claude", "-p", "--permission-mode", "dontAsk", "--permission-mode", "acceptEdits"],
                             "permission mode"),
                            (["claude", "-p", "--add-dir", "/repo", "/"], "--add-dir"),
                            (["claude", "-p", "--add-dir=/etc"], "--add-dir"),
                            (["claude", "-p", "--add-dir"], "--add-dir"),
                            (["claude", "-p", "--dangerously-skip-permissions=true"], "forbidden CLI flag"),
                            (["claude", "-p", "-c", 'sandbox_mode="read-only"'], "sandbox_mode")):
            with self.subTest(cli=cli):
                errs = deepsession.validate_spec(self.spec("claude", cli=cli))
                self.assertTrue(any(needle in e for e in errs), (cli, errs))

    def test_sera_proxy_privileged_and_the_proxy_vector_on_effective_values(self):
        self.assertTrue(any("forbidden docker run flag --privileged" in e
                            for e in deepsession.validate_proxy_run(["--privileged"] + PROXY)))   # her case
        img = PROXY[-1]
        body = PROXY[:-1]
        for extra, needle in ((["--privileged=true"], "--privileged"), (["-u", "0"], "root"), (["--user=root"], "root"),
                              (["--network=bridge"], "--network is declared more than once"),
                              (["--net", "host"], "network"), (["-v", "/:/host:ro"], "policy files"),
                              (["-v", "/c2.json:/etc/credproxy/x.json"], "policy files"),
                              (["--cap-add", "NET_ADMIN"], "--cap-add"),
                              (["--security-opt", "apparmor=unconfined"], "security option"),
                              (["--read-only=false"], "read-only"), (["--name", "other"], "--name is declared more than once")):
            with self.subTest(extra=extra):
                errs = deepsession.validate_proxy_run(body + extra + [img])
                self.assertTrue(any(needle in e for e in errs), (extra, errs))
        # a proxy on the wrong network, or not named as the launcher names it
        swapped = ["--name", "p"] + PROXY[2:]
        self.assertTrue(any("container name" in e for e in deepsession.validate_proxy_run(swapped)))
        swapped = PROXY[:2] + ["--network", "eg"] + PROXY[4:]
        self.assertTrue(any("scout-deep-eg" in e for e in deepsession.validate_proxy_run(swapped)))

    def test_equals_form_mounts_are_hashed_into_the_descriptor(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "x.json"
            f.write_text("{}")
            h = deeplib._mount_hashes(["--volume=" + f"{f}:/etc/credproxy/config.json:ro", "-v", f"{f}:/etc/x:ro", "img"])
            self.assertEqual(set(h), {"/etc/credproxy/config.json", "/etc/x"})
            self.assertEqual(h["/etc/x"], deeplib.sha256_file(f))

    def test_reason_codes_carry_no_declared_values(self):
        errs = deepsession.validate_proxy_run(PROXY[:-1] + ["--security-opt", "label=SECRETVALUE", "--weird=SECRET2", PROXY[-1]])
        codes = deeplib.launch_codes(errs)
        self.assertTrue(codes)
        self.assertFalse(any("secret" in c for c in codes), codes)


# =========================================================================== F2: before-binding, end to end
class WeakenedDeclarationsF2(PairCase):
    """Her probe shape: the declaration is weakened BEFORE the audit binds it (the descriptor's own
    hash recomputed, so this is admissibility, not tampering). Each must SEAL with a specific code."""

    def weaken(self, fam, fn):
        f = self.p.pd / fam / "runtime.json"
        d = json.loads(f.read_text())
        fn(d)
        d["descriptor_sha256"] = deeplib.descriptor_sha(d)
        f.write_text(json.dumps(d))
        for g in ("claude", "codex"):
            self.p.audit(g)

    def test_sera_root_user(self):
        self.weaken("claude", lambda d: d["box_run_args"].__setitem__(d["box_run_args"].index("--user") + 1, "0:0"))
        self.assertSealed("claude: runtime: box_launch_vector_not_valid",
                          "claude: runtime: box_launch:box_the_box_runs_as_10001_10001_only",
                          "claude: runtime: inspect_box_user_not_the_declared_uid")

    def test_sera_arbitrary_network(self):
        self.weaken("claude", lambda d: d["box_run_args"].__setitem__(d["box_run_args"].index("--network") + 1,
                                                                      "arbitrary-egress-network"))
        self.assertSealed("claude: runtime: box_launch_vector_not_valid",
                          "claude: runtime: inspect_box_network_not_declared")

    def test_sera_codex_sandbox_equals(self):
        self.weaken("codex", lambda d: d.__setitem__("box_cli", ["codex", "exec", "--sandbox=danger-full-access"]))
        self.assertSealed("codex: runtime: box_launch_vector_not_valid",
                          "codex: runtime: box_launch:cli_the_codex_sandbox_must_be_read_only")

    def test_sera_proxy_privileged(self):
        self.weaken("claude", lambda d: d["proxy_run_args"].insert(0, "--privileged"))
        self.assertSealed("claude: runtime: proxy_launch_vector_not_valid",
                          "claude: runtime: proxy_launch:forbidden_docker_run_flag_privileged")

    def test_variants_equals_and_repeated(self):
        for fam, fn, code in (
                ("claude", lambda d: d["box_run_args"].insert(0, "--user=0:0"), "box_launch_vector_not_valid"),
                ("codex", lambda d: d["box_run_args"].insert(0, "--network=bridge"), "box_launch_vector_not_valid"),
                ("codex", lambda d: d["box_cli"].insert(2, "-sdanger-full-access"), "box_launch_vector_not_valid"),
                ("claude", lambda d: d["proxy_run_args"].insert(0, "--privileged=true"), "proxy_launch_vector_not_valid"),
                ("codex", lambda d: d["proxy_run_args"].insert(0, "--user=0"), "proxy_launch_vector_not_valid")):
            with self.subTest(code=code, fam=fam):
                self.fresh()
                self.weaken(fam, fn)
                self.assertSealed(f"{fam}: runtime: {code}")

    def test_existing_after_binding_mutation_still_seals(self):
        for g in ("claude", "codex"):
            self.p.audit(g)
        f = self.p.pd / "claude" / "runtime.json"
        d = json.loads(f.read_text())
        d["box_run_args"][d["box_run_args"].index("--user") + 1] = "0:0"
        d["descriptor_sha256"] = deeplib.descriptor_sha(d)
        f.write_text(json.dumps(d))
        self.assertSealed("claude: audit binding does not match the host records (runtime_sha256)")


# =========================================================================== F2: inspect evidence at release
class InspectEvidenceRelease(PairCase):
    """Evidence that disagrees with the declaration (written before binding, with the terminal
    receipt re-hashed so only the comparison can catch it) seals with an inspect_* code."""

    def evidence(self, fam, fn, rehash=True, record="run-meta.json"):
        """Mutate the evidence of fam's reviewer record (or its audit record) before the binding."""
        if record == "audit-run.json":
            for g in ("claude", "codex"):
                self.p.audit(g, parse=False)
        f = self.p.pd / fam / record
        r = json.loads(f.read_text())
        fn(r["runtime_evidence"])
        if rehash:
            r["terminal"]["runtime_evidence_sha256"] = deeplib.canon_sha(r["runtime_evidence"])
        f.write_text(json.dumps(r))
        for g in ("claude", "codex"):
            if record == "audit-run.json":
                run(AUDIT, "parse", str(self.p.pd), g, ok=False)
            else:
                self.p.audit(g)

    def net(self, ev, kind="int"):
        return next(v for k, v in ev["networks"].items() if k.startswith(f"scout-deep-{kind}-"))

    def test_disagreements_seal_with_specific_codes(self):
        cases = [
            (lambda ev: ev["box"].update(user="0:0"), "inspect_box_user_not_the_declared_uid"),
            (lambda ev: ev["box"].update(privileged=True), "inspect_box_privileged"),
            (lambda ev: ev["box"].update(readonly_rootfs=False), "inspect_box_rootfs_writable"),
            (lambda ev: ev["box"].update(cap_add=["SYS_ADMIN"]), "inspect_box_capabilities"),
            (lambda ev: ev["box"].update(security_opt=["seccomp=unconfined"]), "inspect_box_security_options"),
            (lambda ev: ev["box"].update(pid_mode="host"), "inspect_box_shares_a_host_namespace"),
            (lambda ev: ev["box"]["mounts"].append({"type": "bind", "destination": "/host", "rw": True, "source": "/"}),
             "inspect_box_mounts_not_declared"),
            (lambda ev: ev["box"].update(networks=sorted(ev["box"]["networks"] + ["bridge"])),
             "inspect_box_network_not_declared"),
            (lambda ev: self.net(ev).update(internal=False), "inspect_box_network_not_internal"),
            (lambda ev: self.net(ev).update(members=sorted(self.net(ev)["members"] + ["someone-else"])),
             "inspect_box_network_members_not_box_and_proxy"),
            (lambda ev: self.net(ev, "eg").update(members=sorted(self.net(ev, "eg")["members"] + ["x"])),
             "inspect_egress_network_members_not_proxy_only"),
            (lambda ev: ev["proxy"].update(privileged=True), "inspect_proxy_privileged"),
            (lambda ev: ev["proxy"].update(user="root"), "inspect_proxy_runs_as_root"),
            (lambda ev: ev["proxy"]["mounts"].append({"type": "bind", "destination": "/etc/credproxy/ca.pem", "rw": False,
                                                      "source": "/tmp/ca.pem"}), "inspect_proxy_mounts_not_declared"),
            (lambda ev: ev["proxy"].update(networks=sorted(ev["proxy"]["networks"] + ["bridge"])),
             "inspect_proxy_networks_not_box_and_egress"),
            (lambda ev: ev["box"].update(image="sha256:" + "e" * 64), "inspect_box_image_not_locked"),
            (lambda ev: ev["proxy"].update(image="sha256:" + "e" * 64), "inspect_proxy_image_not_locked"),
            (lambda ev: ev.update(proxy_name="scout-deep-proxy-other"), "inspect_proxy_missing"),
            (lambda ev: ev.update(error="container_inspect_failed"), "runtime_evidence_container_inspect_failed"),
        ]
        for fn, code in cases:
            with self.subTest(code=code):
                self.fresh()
                self.evidence("claude", fn)
                self.assertSealed(f"claude: runtime: {code}")
        # the auditor box's evidence is judged the same way
        self.fresh()
        self.evidence("codex", lambda ev: self.net(ev).update(internal=False), record="audit-run.json")
        self.assertSealed("codex: audit runtime: inspect_box_network_not_internal")

    def test_evidence_swapped_without_its_receipt(self):
        self.evidence("codex", lambda ev: ev.update(taken_at="2026-10-07T00:00:09Z"), rehash=False)
        self.assertSealed("codex: runtime: runtime_evidence_not_the_one_the_terminal_receipt_bound",
                          "codex: reviewer session: reviewer_terminal_contradicts_record:runtime_evidence")

    def test_only_a_probe_may_share_egress_with_the_fake_upstream(self):
        r = json.loads((self.p.pd / "claude" / "run-meta.json").read_text())
        desc = json.loads((self.p.pd / "claude" / "runtime.json").read_text())
        ev = r["runtime_evidence"]
        eg = self.net(ev, "eg")
        eg["members"] = sorted(eg["members"] + ["scout-deep-fake-canarycheck-x"])
        kw = dict(box_args=desc["box_run_args"], box_name=ev["box_name"], proxy_args=desc["proxy_run_args"],
                  proxy_name=ev["proxy_name"])
        self.assertEqual(deepsession.evidence_problems(ev, role="probe", **kw), [])
        for role in ("reviewer", "auditor"):
            self.assertIn("inspect_egress_network_members_not_proxy_only", deepsession.evidence_problems(ev, role=role, **kw))
        eg["members"] = sorted(eg["members"] + ["someone-else"])
        self.assertIn("inspect_egress_network_members_not_proxy_only", deepsession.evidence_problems(ev, role="probe", **kw))

    def test_evidence_missing(self):
        _edit_json(self.p.pd / "claude" / "run-meta.json", lambda r: r.pop("runtime_evidence") and None)
        for g in ("claude", "codex"):
            self.p.audit(g)
        self.assertSealed("claude: runtime: runtime_evidence_missing")


# =========================================================================== F2: inspect evidence at launch
class InspectEvidenceLaunch(unittest.TestCase):
    """The real session driver against tests/fakedocker.py: evidence recorded and bound on a normal
    launch; a box whose docker-reported containment differs from its declaration never gets a turn."""

    def setUp(self):
        self.p = Pair(("claude",))
        self.bin = Path(tempfile.mkdtemp())
        shutil.copy(HERE / "fakedocker.py", self.bin / "docker")
        os.chmod(self.bin / "docker", 0o755)
        self.log = self.bin / "calls.jsonl"
        fd = self.p.pd / "claude"
        (fd / "raw").mkdir(exist_ok=True)
        deeplib.seal(fd / "raw")
        dmy = deeplib.box_dummy("claude")
        (fd / "box-dummy.json").write_text(json.dumps(dmy))
        self.sp = {"family": "claude", "role": "reviewer", "name": "scout-deep-rev-claude-x",
                   "proxy_name": "scout-deep-proxy-x", "raw_dir": str(fd / "raw"), "fd": str(fd),
                   "pair_dir": str(self.p.pd), "meta_file": str(fd / "run-meta.json"), "timeout": 30, "max_repair": 0,
                   "prompt_file": str(fd / "prompt.txt"), "dummy_file": str(fd / "box-dummy.json"),
                   "exec_env": {"CLAUDE_CODE_OAUTH_TOKEN": dmy["values"][0]},
                   "run_args": ["--network", "scout-deep-int-x"] + BOX[2:] + [
                       "-v", f"{self.p.pd}/box/repo:/repo:ro", "--entrypoint", "sleep", "img", "infinity"],
                   "cli": ["claude", "-p", "--output-format", "stream-json"]}

    def tearDown(self):
        shutil.rmtree(self.bin)
        self.p.cleanup()

    def go(self, faults=""):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "FAKE_DOCKER_LOG": str(self.log),
               "FAKE_PAIR": str(self.p.pd), "FAKE_MODE": "lazy", "FAKE_INSPECT": faults, **self.p.cred_env}
        with mock.patch.dict(os.environ, env, clear=True):
            rc = deepsession.run_session(self.sp)
        calls = [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []
        return rc, calls, json.loads((self.p.pd / "claude" / "run-meta.json").read_text())

    def test_normal_launch_records_binds_and_passes_the_strict_receipt(self):
        rc, calls, meta = self.go()
        self.assertEqual(rc, 0)
        self.assertIn(["inspect", "scout-deep-rev-claude-x", "scout-deep-proxy-x"], calls)
        self.assertTrue(any(c[:2] == ["network", "inspect"] for c in calls))
        ev = meta["runtime_evidence"]
        self.assertEqual(ev["box"]["user"], "10001:10001")
        self.assertTrue(ev["networks"]["scout-deep-int-x"]["internal"])
        self.assertEqual(ev["networks"]["scout-deep-int-x"]["members"], ["scout-deep-proxy-x", "scout-deep-rev-claude-x"])
        self.assertEqual(meta["terminal"]["runtime_evidence_sha256"], deeplib.canon_sha(ev))
        # the strict F1 validator accepts what the real driver writes (positive control)
        self.assertEqual(deeplib.session_record_problems(meta, "reviewer"), [])
        self.assertEqual(sorted(meta["terminal"]), sorted(deeplib.TERMINAL_FIELDS))

    def test_divergent_evidence_refuses_before_any_turn(self):
        for fault, code in (("box_root", "inspect_box_user_not_the_declared_uid"),
                            ("box_privileged", "inspect_box_privileged"), ("box_writable", "inspect_box_rootfs_writable"),
                            ("box_caps", "inspect_box_capabilities"), ("box_other_network", "inspect_box_network_not_declared"),
                            ("box_extra_mount", "inspect_box_mounts_not_declared"),
                            ("net_external", "inspect_box_network_not_internal"),
                            ("net_extra_member", "inspect_box_network_members_not_box_and_proxy"),
                            ("proxy_privileged", "inspect_proxy_privileged"), ("proxy_root", "inspect_proxy_runs_as_root"),
                            ("proxy_extra_network", "inspect_proxy_networks_not_box_and_egress")):
            with self.subTest(fault=fault):
                if self.log.exists():
                    self.log.unlink()
                st = self.log.with_name(self.log.name + ".containers.json")
                if st.exists():
                    st.unlink()
                rc, calls, meta = self.go(fault)
                self.assertEqual(rc, 1)
                self.assertEqual(meta["session_error"], "runtime_evidence_rejected")
                self.assertIn(code, meta["runtime_evidence_problems"])
                self.assertFalse([c for c in calls if c[0] == "exec" and "claude" in c], "no turn ran")
                self.assertIn(["rm", "-f", "scout-deep-rev-claude-x"], calls)
                self.assertIn("reviewer_session_error", deeplib.session_record_problems(meta, "reviewer"))

    def test_launch_requires_the_proxy_name(self):
        self.sp.pop("proxy_name")
        rc, calls, meta = self.go()
        self.assertEqual((rc, meta["session_error"]), (2, "spec_invalid"))
        self.assertEqual(calls, [])


# =========================================================================== F3
class RouteDisclosureF3(unittest.TestCase):
    def test_owner_docs_name_every_forwarded_and_declined_route(self):
        disclosure = (DEEP / "DISCLOSURE.md").read_text()
        table = disclosure.split("## 2.", 1)[1].split("\n## ", 1)[0]
        containment = (DEEP / "CONTAINMENT.md").read_text()
        for fam, conf in deeplib.PROXY_CONFIG.items():
            c = json.loads((DEEP / conf).read_text())
            for meth, path in c["routes"]:
                self.assertIn(f"`{meth} {path}`", table, f"DISCLOSURE §2 omits {fam} {meth} {path}")
                self.assertIn(f"`{meth} {path}`", containment, f"CONTAINMENT omits {fam} {meth} {path}")
            for meth, path in c.get("decline_routes", []):
                self.assertIn(f"`{meth} {path}`", containment)



# =========================================================================== P5: her F2a reproducer, inverted
class SeraF2aReproducerInverted(PairCase):
    """the peer reviewer's additional_probes.py case `proxy_zero_padded_uid` (P4 review, 2026-10-07), verbatim
    in shape: `--user 00:00` prepended to the Claude reviewer's proxy vector and the matching inspect
    user set to `00:00` before binding, both hashes recomputed. Under C5 this RELEASED; it must SEAL."""

    def test_proxy_zero_padded_uid(self):
        f = self.p.pd / "claude" / "runtime.json"
        d = json.loads(f.read_text())
        d["proxy_run_args"][0:0] = ["--user", "00:00"]
        d["descriptor_sha256"] = deeplib.descriptor_sha(d)
        f.write_text(json.dumps(d))
        f = self.p.pd / "claude" / "run-meta.json"
        m = json.loads(f.read_text())
        m["runtime_evidence"]["proxy"]["user"] = "00:00"
        m["terminal"]["runtime_evidence_sha256"] = deeplib.canon_sha(m["runtime_evidence"])
        f.write_text(json.dumps(m))
        for g in ("claude", "codex"):
            self.p.audit(g)
        self.assertSealed("claude: runtime: proxy_launch_vector_not_valid",
                          "claude: runtime: proxy_launch:proxy_uid_noncanonical",
                          "claude: runtime: inspect_proxy_uid_noncanonical")
        admitted = deepgate.admit(self.p.pd)
        self.assertNotEqual(admitted[0].get("status") if isinstance(admitted, tuple) else None, "RELEASED")


if __name__ == "__main__":
    unittest.main()
