"""P9 / contract C10: Serafina's four required edits against C9, plus the bare-id residual.

F1  needles are the captured VALUES, kept apart from replacement spans: a value replaced together with
    its context (an assignment, a merged span, a connection string, a home path) must not survive bare
    anywhere in the derivative or in any admitted path.
F2  the redaction evidence is committed INTO the released generation and verified at read and deliver;
    a post-release edit, deletion or unbound record refuses consumption with a named reason.
F3  inspect prints closed, typed slots only (contamination in an allowed slot or a map key is withheld
    and counted) and reads every record through an alias-refusing path (symlink / hard link / symlinked
    family dir refused before any open).
F4  the marker namespace is reserved across every admitted original, in every mode; gate rule 10 FAILs
    on a marker the redaction record does not explain.
F5  `deep-review.sh inspect|redactions <bare id>` resolves under $DEEP_HOME/pairs or exits 3.

Every private-looking value is synthetic, assembled at runtime; no real owner data, bait or credential
is read, and nothing under ~/.athena is touched.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deepfixture import DEEP, GATE, LIB, REPO, Pair, run  # noqa: E402
import test_p8  # noqa: E402  (module import: its TestCases must not be collected again here)
from test_p8 import (EMAIL, FILLER, PHONE, PW, REDACT, SENT, AKIA, CLAUDE_MD,  # noqa: E402
                     marker_report, prose_repo)

sys.path.insert(0, str(DEEP))
import deepgate  # noqa: E402
import deeplib  # noqa: E402

CONN_PW = "Pw7" + "rTq9xZ2" + "mK4"
CONN = "postgres" + "://svc:" + CONN_PW + "@db.internal/app"


def _fallback(text):
    try:
        deeplib.redact_text(text)
    except deeplib.RedactionFallback as e:
        return e.args[0]
    return None


# =========================================================================== F1
class NeedlesNotSpans(unittest.TestCase):
    def test_bare_repeat_of_an_assignment_value(self):
        """Serafina's probe: the whole `name = value` span is replaced; the value repeated bare must
        not survive in the derivative (C9 admitted it with zero residual hits)."""
        t = f'db_password = "{PW}"\nReuse {PW} for this step.\n' + FILLER
        self.assertIn(PW, deeplib.scan_needles(t))
        self.assertEqual(_fallback(t), "redaction_residual")
        # control: the same assignment without the bare repeat is redacted, and the value is gone
        d, spans, _ = deeplib.redact_text(f'db_password = "{PW}"\n' + FILLER)
        self.assertEqual(len(spans), 1)
        self.assertNotIn(PW, d)

    def test_connection_string_components(self):
        self.assertIn(CONN_PW, deeplib.scan_needles(f"see {CONN}\n"))
        self.assertIn("svc", deeplib.scan_needles(f"see {CONN}\n"))
        self.assertEqual(_fallback(f"see {CONN}\nthe db pass is {CONN_PW} today\n" + FILLER), "redaction_residual")
        d, _s, _w = deeplib.redact_text(f"see {CONN}\n" + FILLER)
        self.assertNotIn(CONN_PW, d)

    def test_value_inside_a_merged_span(self):
        """An assignment whose value is a connection string: the two spans overlap and merge into one
        marker; the password inside is still a needle of its own."""
        line = f'db_password = "{CONN}"\n'
        hits = [h for h in deeplib.scan_spans(line) if h[1] == 1]
        self.assertGreaterEqual(len({h[4] for h in hits}), 2)  # assignment + connection_string overlap
        d, spans, _ = deeplib.redact_text(line + FILLER)
        self.assertEqual(len(spans), 1)                         # merged into one marker
        self.assertEqual(_fallback(line + f"fallback pass {CONN_PW} here\n" + FILLER), "redaction_residual")

    def test_home_path_user_component(self):
        home = "/Us" + "ers/kq7user" + "/notes/"
        self.assertIn("kq7user", deeplib.scan_needles(f"files under {home}\n"))
        self.assertEqual(_fallback(f"files under {home}\nask kq7user first\n" + FILLER), "redaction_residual")

    def test_path_component_and_box_through_preflight(self):
        """The assignment value as a directory name of another admitted file (no bare repeat in prose):
        C9's whole-assignment needle missed it; C10 falls back and keeps the file out."""
        for extra_line in ("", f"Reuse {PW} for this step.\n"):
            p = Pair(("claude",), repo={**REPO, "CLAUDE.md": f'db_password = "{PW}"\n' + extra_line + FILLER,
                                        "inventory/" + PW + "/notes.txt": "ordinary notes\n"},
                     preflight_opts=REDACT)
            try:
                pf = json.loads((p.pd / "preflight.json").read_text())
                ex = {e["path"]: e for e in pf["excluded"]}
                self.assertNotIn("CLAUDE.md", p.manifest["files"])
                self.assertEqual(ex["CLAUDE.md"].get("redaction_fallback"), "redaction_residual")
                self.assertFalse((p.pd / "box" / "repo" / "CLAUDE.md").exists())
                red = json.loads((p.pd / "redaction.json").read_text())
                self.assertEqual(red["files"], [])
                # needles never reach a record (the owner's own directory name stays an admitted path)
                for f in ("preflight.json", "redaction.json", "manifest.json"):
                    body = (p.pd / f).read_text()
                    self.assertNotIn('db_password = "', body)
                self.assertNotIn(PW.encode(), (p.pd / "redaction.json").read_bytes())
            finally:
                p.cleanup()

    def test_needles_never_written(self):
        p = Pair(("claude",), repo=prose_repo(), preflight_opts=REDACT)
        try:
            for f in ("preflight.json", "redaction.json", "manifest.json"):
                body = (p.pd / f).read_bytes()
                for v in (PW, EMAIL, "jane.doe", "jdoe"):
                    self.assertNotIn(v.encode(), body, f)
        finally:
            p.cleanup()


# =========================================================================== F2
class Released:
    """A released two-family redacted pair (the Rule10AndRelease shape)."""

    def make(self, repo=None, opts=REDACT, families=("claude", "codex")):
        p = Pair(families, repo=repo or prose_repo(), preflight_opts=opts)
        for fam in families:
            r = marker_report(p, fam) if opts else p.report(fam)
            (p.write_claude_evidence if fam == "claude" else p.write_codex_evidence)(r)
            self.assertEqual(p.check(fam)[0], 0)
            self.assertEqual(p.gate(fam)[0], 0)
            p.audit(fam)
        q = run(GATE, "release", str(p.pd), ok=False)
        self.assertEqual(q.returncode, 0, q.stdout + q.stderr)
        return p

    @staticmethod
    def gen_dir(p):
        return p.pd / "gen" / os.readlink(p.pd / "current").split("/")[1]

    @staticmethod
    def edit_gen_file(p, name, fn):
        gd = Released.gen_dir(p)
        os.chmod(gd, 0o700)
        f = gd / name
        os.chmod(f, 0o600)
        f.write_bytes(fn(f.read_bytes()))
        os.chmod(f, 0o400)
        os.chmod(gd, 0o500)

    @staticmethod
    def close(p):
        dd = p.pd / "deliverable"
        if dd.exists():
            dd.chmod(0o700)
        p.cleanup()


class EvidenceBound(Released, unittest.TestCase):
    def setUp(self):
        self.p = self.make()
        self.rp = self.p.pd / "redaction.json"
        self.original = self.rp.read_bytes()

    def tearDown(self):
        self.close(self.p)

    def _refused(self, reason):
        rd = run(GATE, "read", str(self.p.pd), "claude", ok=False)
        self.assertNotEqual(rd.returncode, 0)
        self.assertEqual(rd.stdout, "")
        self.assertIn(reason, rd.stderr)
        dv = run(GATE, "deliver", str(self.p.pd), ok=False)
        self.assertNotEqual(dv.returncode, 0)
        self.assertIn(reason, dv.stderr)
        self.assertFalse((self.p.pd / "deliverable" / "owner-review.json").exists())

    def test_generation_carries_the_record_and_its_binding(self):
        rel = json.loads((self.p.pd / "release.json").read_text())
        ev = rel["redaction_evidence"]
        gcopy = (self.gen_dir(self.p) / "redaction.json").read_bytes()
        self.assertEqual(gcopy, self.original)
        self.assertEqual(ev["sha256"], deeplib.sha256_bytes(self.original))
        self.assertEqual(ev["sha256"], self.p.manifest["redaction"]["record_sha256"])
        ent = self.p.manifest["files"]["CLAUDE.md"]
        self.assertEqual(ev["files"], [{"path": "CLAUDE.md", "original_sha256": ent["original_sha256"],
                                        "derivative_sha256": ent["sha256"]}])
        self.assertEqual(oct(os.stat(self.gen_dir(self.p) / "redaction.json").st_mode & 0o777), "0o400")
        rd = run(GATE, "read", str(self.p.pd), "claude")
        self.assertIn("3 entries rest on a withheld span", rd.stderr)

    def test_post_release_mode_none_edit_refuses(self):
        rec = json.loads(self.original)
        rec.update(mode="none", files=[], withheld_spans=0)
        self.rp.write_text(json.dumps(rec))
        self._refused("redaction_record_changed")

    def test_post_release_deletion_refuses(self):
        self.rp.unlink()
        self._refused("redaction_record_deleted")

    def test_restored_record_reads_again(self):
        self.rp.unlink()
        self.rp.write_bytes(self.original)
        rd = run(GATE, "read", str(self.p.pd), "claude")
        self.assertIn("3 entries rest on a withheld span", rd.stderr)
        run(GATE, "deliver", str(self.p.pd))
        out = json.loads((self.p.pd / "deliverable" / "owner-review.json").read_text())
        self.assertEqual(out["scope"]["redaction_mode"], "redact-prose")
        self.assertTrue(out["reports"]["claude"]["findings"][0]["redaction_unresolved"])

    def test_generation_copy_tamper_refuses(self):
        self.edit_gen_file(self.p, "redaction.json", lambda b: b.replace(b'"redact-prose"', b'"none"', 1))
        self._refused("redaction_evidence_changed")

    def test_unbound_generation_refuses(self):
        """A generation saying redacted but binding no evidence (the C9 shape) is refused, not read as none."""
        def drop(b):
            rel = json.loads(b)
            rel.pop("redaction_evidence")
            return (json.dumps(rel, indent=2) + "\n").encode()
        self.edit_gen_file(self.p, "release.json", drop)
        self._refused("redaction_evidence_unbound")

    def test_manifest_binding_changed_refuses(self):
        mp = self.p.pd / "manifest.json"
        man = json.loads(mp.read_text())
        man["redaction"]["record_sha256"] = "0" * 64
        mp.write_text(json.dumps(man))
        self._refused("redaction_evidence_mismatch")

    def test_record_replaced_by_symlink_refuses(self):
        alias = self.p.pd / "redaction-copy.json"
        alias.write_bytes(self.original)
        self.rp.unlink()
        self.rp.symlink_to(alias.name)
        self._refused("symlink")


class EvidenceAtRelease(Released, unittest.TestCase):
    def test_release_refuses_a_symlinked_record(self):
        p = Pair(("claude",), repo=prose_repo(), preflight_opts=REDACT)
        try:
            r = marker_report(p, "claude")
            p.write_claude_evidence(r)
            p.check("claude")
            p.gate("claude")
            p.audit("claude")
            rp = p.pd / "redaction.json"
            (p.pd / "redaction-copy.json").write_bytes(rp.read_bytes())
            rp.unlink()
            rp.symlink_to("redaction-copy.json")
            q = run(GATE, "release", str(p.pd), ok=False)
            rel = json.loads((p.pd / "release.json").read_text())
            self.assertEqual((q.returncode, rel["status"]), (4, "SEALED"))
            self.assertTrue(any("symlink" in x for x in rel["reasons"]), rel["reasons"])
        finally:
            self.close(p)


class ModeNoneGenerations(Released, unittest.TestCase):
    def test_mode_none_and_older_generations_read_unchanged(self):
        p = self.make(repo=dict(REPO), opts=(), families=("claude",))
        try:
            rel = json.loads((p.pd / "release.json").read_text())
            self.assertIsNone(rel["redaction_evidence"])
            rd = run(GATE, "read", str(p.pd), "claude")
            self.assertEqual(rd.stderr, "")
            # an older (C8/C9-era) generation has no redaction_evidence key at all: still read
            def drop(b):
                r = json.loads(b)
                r.pop("redaction_evidence")
                return (json.dumps(r, indent=2) + "\n").encode()
            self.edit_gen_file(p, "release.json", drop)
            self.assertEqual(run(GATE, "read", str(p.pd), "claude").returncode, 0)
            run(GATE, "deliver", str(p.pd))
            # ... but a redaction record appearing after the release is refused, not ignored
            (p.pd / "redaction.json").write_text(json.dumps({"mode": "redact-prose", "files": []}))
            rd = run(GATE, "read", str(p.pd), "claude", ok=False)
            self.assertNotEqual(rd.returncode, 0)
            self.assertIn("redaction_evidence_unbound", rd.stderr)
        finally:
            self.close(p)


# =========================================================================== F3
PHONE_KEY = PHONE.replace("(", "").replace(") ", "-")


class InspectNoLeakAllowedSlots(test_p8.InspectNoLeak):
    """The P8 no-leak test, extended: the canary token, a detected phone, an email (plain, base64- and
    hex-encoded), a vendor-shaped key and a box-dummy shape planted in ALLOWED scalar slots and as MAP
    KEYS of records inspect reads. None may print; each is counted as withheld or dropped."""

    def setUp(self):
        super().setUp()
        pd = self.p.pd
        canary = self.p.bait["canary_token"]
        b64 = base64.b64encode(f"mail {EMAIL} now".encode()).decode()
        hexed = f"mail {EMAIL} now".encode().hex()
        dummy = "sk-ant-oat01-" + deeplib.BOX_MARKER + "q" * 40
        self.planted = {canary, PHONE_KEY, EMAIL, b64, hexed, AKIA, dummy, f"{SENT}-slot"}

        def patch(name, fn):
            q = pd / name
            rec = json.loads(q.read_text())
            fn(rec)
            q.write_text(json.dumps(rec))
        patch("pair.json", lambda r: r.update(id=canary))
        patch("source-pin.json", lambda r: r.update(label=b64, kind=f"{SENT}-slot"))
        patch("preflight.json", lambda r: r["excluded"].append({"path": EMAIL, "reason": PHONE_KEY,
                                                                "kinds": [canary]}))
        for fam in ("claude", "codex"):
            def gate(r):
                r.update(pair_id=canary, reviewer_model=AKIA, exception=EMAIL)
                r["rules"][canary] = {"result": "PASS"}
                r["rules"][PHONE_KEY] = {"result": "PASS"}
                r["rules"]["5_secrets"]["result"] = canary
                r["failed_rules"] = [PHONE_KEY]
            patch(f"{fam}/gate.json", gate)
            patch(f"{fam}/run-meta.json", lambda r: r.update(model=dummy, reviewer_cli_version=hexed))
            patch(f"{fam}/box-checks.json", lambda r: r["checks"].update({EMAIL: {"result": "PASS"}}))
            patch(f"{fam}/audit.json", lambda r: r.update(confidence=canary, audited_at=PHONE_KEY))
        self.out = run(GATE, "inspect", str(pd)).stdout

    def _forbidden(self):
        return super()._forbidden() | self.planted

    def test_contamination_is_counted(self):
        v = json.loads(self.out)
        sc = v["screened"]
        self.assertGreaterEqual(sc["pair.json"]["values_withheld"], 1)
        self.assertGreaterEqual(sc["claude/gate.json"]["keys_dropped"], 2)
        self.assertGreaterEqual(sc["claude/gate.json"]["values_withheld"], 4)
        self.assertNotIn(PHONE_KEY, v["records"]["claude/gate.json"]["rules"])
        self.assertEqual(v["records"]["pair.json"]["id"], "[withheld]")
        self.assertEqual(v["records"]["claude/gate.json"]["verdict"], "PASS")   # legitimate slots still print


class InspectAliases(unittest.TestCase):
    """Record identity: the inspector never opens a file through an alias. Synthetic files only."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.pd = Path(self.td.name) / "20261007T000000Z-abcdef"
        self.pd.mkdir()
        self.value = "AKIA" + "A1B2C3D4E5F6G7H8"
        (self.pd / "bait.json").write_text(json.dumps({"id": self.value}))
        (self.pd / "manifest.json").write_text(json.dumps({"files_in_box": 1}))

    def tearDown(self):
        self.td.cleanup()

    def _inspect_tracking_opens(self):
        opened = []
        real_open = os.open

        def tracking(path, *a, **k):
            opened.append(os.path.realpath(path))
            return real_open(path, *a, **k)
        os.open = tracking
        try:
            view = deepgate.inspect_pair(self.pd)
        finally:
            os.open = real_open
        return view, opened

    def _assert_bait_never_opened(self, opened, view):
        bait = os.path.realpath(self.pd / "bait.json")
        self.assertNotIn(bait, opened)
        self.assertNotIn(self.value, json.dumps(view))
        self.assertIn("bait.json", view["never_opened"])

    def test_symlink_to_bait_is_refused_unopened(self):
        (self.pd / "pair.json").symlink_to("bait.json")
        view, opened = self._inspect_tracking_opens()
        self.assertIn({"record": "pair.json", "reason": "symlink"}, view["refused"])
        self.assertNotIn("pair.json", view["records"])
        self._assert_bait_never_opened(opened, view)

    def test_hard_link_to_bait_is_refused_unopened(self):
        os.link(self.pd / "bait.json", self.pd / "pair.json")
        view, opened = self._inspect_tracking_opens()
        self.assertIn({"record": "pair.json", "reason": "hard_link"}, view["refused"])
        self._assert_bait_never_opened(opened, view)

    def test_symlinked_family_dir_is_refused(self):
        other = Path(self.td.name) / "elsewhere"
        other.mkdir()
        (other / "gate.json").write_text(json.dumps({"verdict": "PASS", "pair_id": self.value}))
        (self.pd / "claude").symlink_to(other)
        view, opened = self._inspect_tracking_opens()
        self.assertIn({"record": "claude", "reason": "not_a_directory"}, view["refused"])
        self.assertNotIn("claude/gate.json", view["records"])
        self.assertNotIn(os.path.realpath(other / "gate.json"), opened)

    def test_release_link_must_be_the_committed_one(self):
        (self.pd / "release.json").symlink_to("bait.json")
        view, opened = self._inspect_tracking_opens()
        self.assertIn({"record": "release.json", "reason": "release_link_not_current"}, view["refused"])
        self._assert_bait_never_opened(opened, view)
        (self.pd / "release.json").unlink()
        (self.pd / "release.json").symlink_to("current/release.json")
        (self.pd / "current").symlink_to(".")                       # current -> not a generation
        view, opened = self._inspect_tracking_opens()
        self.assertIn({"record": "release.json", "reason": "current_not_a_generation"}, view["refused"])

    def test_no_pair_dir_is_refused_not_an_empty_view(self):
        empty = Path(self.td.name) / "empty"
        empty.mkdir()
        for sub in ("inspect", "redactions"):
            for arg in (str(empty), str(Path(self.td.name) / "absent")):
                q = run(GATE, sub, arg, ok=False)
                self.assertEqual(q.returncode, 3, (sub, arg, q.stdout))
                self.assertEqual(q.stdout, "")
                self.assertIn("refused", q.stderr)


class InspectReleasedPairStillReads(Released, unittest.TestCase):
    def test_committed_release_link_is_followed(self):
        p = self.make()
        try:
            v = deepgate.inspect_pair(p.pd)
            self.assertEqual(v["records"]["release.json"]["status"], "RELEASED")
            self.assertEqual(v["records"]["release.json"]["redaction_evidence"]["files"][0]["path"], "CLAUDE.md")
            self.assertEqual(v["refused"], [])
        finally:
            self.close(p)


# =========================================================================== F4
class MarkerNamespaceReserved(unittest.TestCase):
    MARKED = "# Rules\nOwner says [REDACTED:password#1]\n"

    def _pair(self, repo, opts, exc=None):
        o = tuple(opts)
        if exc is not None:
            self._td = tempfile.TemporaryDirectory()
            ep = Path(self._td.name) / "exc.json"
            ep.write_text(json.dumps({"declared_by": "owner", "exceptions": exc}))
            o += ("--exceptions", str(ep))
        return Pair(("claude",), repo=repo, preflight_opts=o)

    def _excluded(self, p):
        return {e["path"]: e for e in json.loads((p.pd / "preflight.json").read_text())["excluded"]}

    def test_unflagged_file_with_a_marker_redact_mode(self):
        p = self._pair({**REPO, "CLAUDE.md": self.MARKED}, REDACT)
        try:
            ex = self._excluded(p)
            self.assertEqual((ex["CLAUDE.md"]["reason"], ex["CLAUDE.md"]["redaction_fallback"]),
                             ("marker_reserved", "marker_collision"))
            self.assertNotIn("CLAUDE.md", p.manifest["files"])
            red = json.loads((p.pd / "redaction.json").read_text())
            self.assertEqual(red["files"], [])
            self.assertIn({"path": "CLAUDE.md", "reason": "marker_collision"}, red["fallbacks"])
            # Serafina's probe, gate side: the finding on the marker line now cites an unknown path
            r = p.report()
            r["findings"][0].update(path="CLAUDE.md", line=2)
            gate, _ = deepgate.gate_report(r, manifest=p.manifest, box=p.pd / "box" / "repo",
                                           schema=json.loads((p.pd / "run-schema.json").read_text()), echo=p.echo(),
                                           bait=p.bait, extra_canaries=[], box_verdict="PASS",
                                           receipts=p.receipts(), redaction=red)
            self.assertEqual(gate["verdict"], "FAIL")
        finally:
            p.cleanup()

    def test_default_mode_reserves_too(self):
        p = self._pair({**REPO, "CLAUDE.md": self.MARKED.lower()}, ())
        try:
            ex = self._excluded(p)
            self.assertEqual(ex["CLAUDE.md"]["reason"], "marker_reserved")
            self.assertNotIn("redaction_fallback", ex["CLAUDE.md"])
            self.assertNotIn("CLAUDE.md", p.manifest["files"])
            pf = json.loads((p.pd / "preflight.json").read_text())
            self.assertEqual(pf["redaction"], {"mode": "none", "files": 0, "withheld_spans": 0, "fallbacks": 0})
            self.assertFalse((p.pd / "redaction.json").exists())
        finally:
            p.cleanup()

    def test_excepted_file_with_a_marker(self):
        body = f"Ask {EMAIL}\n[REDACTED-LINE:password]\n" + FILLER
        p = self._pair({**REPO, ".claude/rules/excepted.md": body}, REDACT,
                       exc=[{"glob": ".claude/rules/excepted.md", "kinds": ["personal_email"], "reason": "ok"}])
        try:
            ex = self._excluded(p)
            self.assertEqual(ex[".claude/rules/excepted.md"]["reason"], "marker_reserved")
            self.assertEqual(ex[".claude/rules/excepted.md"]["kinds"], ["personal_email"])
            pf = json.loads((p.pd / "preflight.json").read_text())
            self.assertEqual(pf["excepted"], [])
            self.assertNotIn(".claude/rules/excepted.md", p.manifest["files"])
        finally:
            p.cleanup()
            self._td.cleanup()

    def test_flagged_candidate_and_marker_path(self):
        p = self._pair({**REPO, "CLAUDE.md": CLAUDE_MD + "keep [redacted:x#2] here\n",
                        "notes/[Redacted-Line:x].md": "plain notes\n"}, REDACT)
        try:
            ex = self._excluded(p)
            self.assertEqual((ex["CLAUDE.md"]["reason"], ex["CLAUDE.md"]["redaction_fallback"]),
                             ("private_info", "marker_collision"))
            self.assertEqual(ex["notes/[Redacted-Line:x].md"]["reason"], "marker_reserved")
            self.assertEqual(sorted(p.manifest["files"]), sorted(f for f in p.manifest["files"]
                                                                 if "edacted" not in f.lower()))
        finally:
            p.cleanup()

    def test_clean_files_still_admitted(self):
        p = self._pair(dict(REPO), REDACT)
        try:
            self.assertTrue(set(REPO) <= set(p.manifest["files"]))
            self.assertEqual(self._excluded(p), {})
        finally:
            p.cleanup()

    def test_gate_refuses_an_unexplained_marker(self):
        man = {"files": {"a.md": {"sha256": "x", "lines": 2}, "CLAUDE.md": {}}}
        self.assertEqual(deepgate.redaction_problems(None, man, {"a.md": "x\n[REDACTED:api_key#1]\n"}),
                         [{"path": "a.md", "problem": "redaction_marker_unexplained"}])
        self.assertEqual(deepgate.redaction_problems(None, man, {"a.md": "x\n[redacted-line:x]\n"}),
                         [{"path": "a.md", "problem": "redaction_marker_unexplained"}])
        self.assertEqual(deepgate.redaction_problems(None, man, {"a.md": "plain\n"}), [])
        self.assertIn("redaction_marker_unexplained", deepgate.VOCAB)

    def test_prompt_states_the_reservation(self):
        t = (DEEP / "reviewer-system.md").read_text()
        self.assertIn("a marker you meet is never the repository's", t)


# =========================================================================== F5
class WrapperBareId(unittest.TestCase):
    def test_bare_id_resolves_or_exits_3(self):
        p = Pair(("claude",), repo=prose_repo(), preflight_opts=REDACT)
        td = tempfile.TemporaryDirectory()
        try:
            home = Path(td.name)
            (home / "pairs").mkdir()
            pid = "20261007T000000Z-abcdef"
            (home / "pairs" / pid).symlink_to(p.pd)
            env = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", "HOME": td.name, "DEEP_HOME": td.name}
            sh = str(DEEP / "deep-review.sh")
            q = subprocess.run(["bash", sh, "inspect", pid], capture_output=True, text=True, env=env)
            self.assertEqual(q.returncode, 0, q.stderr)
            v = json.loads(q.stdout)
            self.assertIn("manifest.json", v["records"])
            self.assertNotIn("manifest.json", v["missing"])
            q = subprocess.run(["bash", sh, "redactions", pid], capture_output=True, text=True, env=env)
            self.assertEqual(q.returncode, 0, q.stderr)
            self.assertIn("path\tline\tkind\tmarker", q.stdout)
            for sub in ("inspect", "redactions"):
                for arg in ("20261007T000000Z-ffffff", "../pairs", ""):
                    q = subprocess.run(["bash", sh, sub, arg], capture_output=True, text=True, env=env)
                    self.assertEqual(q.returncode, 3, (sub, arg, q.stdout, q.stderr))
                    self.assertEqual(q.stdout, "")
        finally:
            td.cleanup()
            p.cleanup()


if __name__ == "__main__":
    unittest.main()
