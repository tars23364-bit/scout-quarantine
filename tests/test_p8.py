"""P8 / contract C9: redacted-prose mode and the sanitized record inspector.

`preflight --redact-prose` lets a flagged `agent_prose` file (no exception, no flagged name) enter the
box as a line-preserving derivative: every detector span becomes `[REDACTED:<kind>#<n>]`, a line-only
hit becomes `[REDACTED-LINE:<kind>]`, line numbers are kept, and any doubt falls back to whole-file
exclusion with a recorded reason. Gate rule 10 lists report entries resting on a marker line.
`deep-review.sh redactions` and `deep-review.sh inspect` print host records without values.

Every private-looking value here is synthetic and assembled at runtime (so this source carries no
scanner-shaped literal of its own); no real owner data and nothing under ~/.athena is read.
"""
import hashlib
import json
import os
import random
import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deepfixture import DEEP, GATE, LIB, REPO, Pair, run  # noqa: E402

sys.path.insert(0, str(DEEP))
import deepgate  # noqa: E402
import deeplib  # noqa: E402

B62 = string.ascii_letters + string.digits
REDACT = ("--redact-prose",)


def _gen(n, alphabet, ok, seed):
    rng = random.Random(seed)
    for _ in range(20000):
        r = "".join(rng.choice(alphabet) for _ in range(n))
        if ok(r):
            return r
    raise AssertionError("no candidate")


# ---- synthetic values (assembled, never literal) -------------------------------------------------
PHONE = "(" + "520) 555" + "-0142"
EMAIL = "jane.doe" + "@" + "corp-mail" + ".net"
IP = ".".join(("192", "168", "7", "21"))
PW = "Zq8" + "x7Lm2Pw9Rt4Kv"
AKIA = "AKIA" + _gen(16, string.ascii_uppercase + string.digits, lambda r: True, 81)
TAIL = _gen(30, B62, lambda r: sum(bool(set(r) & set(c)) for c in (string.ascii_lowercase, string.ascii_uppercase,
                                                                    string.digits)) == 3, 82)
SPLIT = AKIA + "/" + TAIL          # a vendor match covers the prefix, the generic heuristic the whole run
HOME = "/Us" + "ers/jdoe" + "/notes/"
PEM_BODY = _gen(64, B62 + "+/", lambda r: True, 83)
SEG_IP = ".".join(("10", "20", "30", "40"))

FILLER = "".join(f"Ordinary guidance line number {i} for the agent reading this file.\n" for i in range(40))
QUOTE = ("The release checklist runs before every deploy and the operator signs off on the "
         "rollback plan in writing.")

CLAUDE_MD = ("# Agent rules\n\n"
             f"Page the on-call at {PHONE} when the nightly job fails.\n"        # line 3
             f"Ask {EMAIL} for access to the staging bucket.\n"                  # line 4
             f"The build cache lives on {IP} inside the lab network.\n"          # line 5
             f"db_password = \"{PW}\"\n"                                         # line 6
             f"Rotate {SPLIT} every quarter.\n"                                  # line 7
             f"Scratch files go under {HOME} by default.\n"                      # line 8
             + QUOTE + "\n"                                                      # line 9
             + FILLER)
MARKER_LINES = {3, 4, 5, 6, 7, 8}
VALUES = (PHONE, EMAIL, IP, PW, AKIA, TAIL, SPLIT, HOME)


def prose_repo(**extra):
    return {**REPO, "CLAUDE.md": CLAUDE_MD, **extra}


def windows(v, n=8):
    return {v[i:i + n] for i in range(0, max(1, len(v) - n + 1))}


class Projection(unittest.TestCase):
    def test_scan_text_is_projection_and_spans_cover_detailed(self):
        for t in (CLAUDE_MD, FILLER, deeplib.PEM_BEGIN + "\n" + PEM_BODY + "\n"):
            det = deeplib.scan_text_detailed(t)
            self.assertEqual(deeplib.scan_text(t), [(k, l) for k, l, _s, _e, _d in det])
            self.assertLessEqual(set(det), set(deeplib.scan_spans(t)))
            for k, l, s, e, d in det:
                self.assertIn(d, deeplib.DETECTORS)
                if l:
                    self.assertLess(s, e)
        lines = CLAUDE_MD.splitlines()
        spans = {(l, lines[l - 1][s:e]) for _k, l, s, e, _d in deeplib.scan_spans(CLAUDE_MD)}
        for v, l in ((PHONE, 3), (EMAIL, 4), (IP, 5), (SPLIT, 7)):
            self.assertIn((l, v), spans)

    def test_every_match_not_only_the_first(self):
        t = f"call {PHONE} or {PHONE.replace('0142', '0199')}\n"
        self.assertEqual(len([h for h in deeplib.scan_text_detailed(t) if h[4] == "phone"]), 1)
        self.assertEqual(len([h for h in deeplib.scan_spans(t) if h[4] == "phone"]), 2)


class RedactText(unittest.TestCase):
    def test_line_preserving_markers_no_residual(self):
        d, spans, withheld = deeplib.redact_text(CLAUDE_MD)
        self.assertEqual(deeplib.line_count(d), deeplib.line_count(CLAUDE_MD))
        self.assertEqual(len(d.splitlines()), len(CLAUDE_MD.splitlines()))
        self.assertEqual({s["line"] for s in spans}, MARKER_LINES)
        self.assertEqual([s["marker"] for s in spans], [f"[REDACTED:{s['kind']}#{i}]" for i, s in enumerate(spans, 1)])
        for v in VALUES:
            for w in windows(v):
                self.assertNotIn(w, d)
        self.assertEqual(deeplib.derivative_residual(d), [])
        self.assertEqual(deeplib.scan_text(d), [])
        dl, ol = d.split("\n"), CLAUDE_MD.split("\n")
        for i, (a, b) in enumerate(zip(dl, ol), 1):
            if i not in MARKER_LINES:
                self.assertEqual(a, b)

    def test_split_value_across_marker_boundary_is_one_marker(self):
        d, spans, _ = deeplib.redact_text(f"Rotate {SPLIT} now.\n" + FILLER)
        self.assertEqual(d.splitlines()[0], "Rotate [REDACTED:api_key#1] now.")
        self.assertEqual(len(spans), 1)
        for w in windows(SPLIT, 6):
            self.assertNotIn(w, d)

    def test_crlf_endings_kept(self):
        t = CLAUDE_MD.replace("\n", "\r\n")
        d, _s, _w = deeplib.redact_text(t)
        self.assertEqual(d.count("\r\n"), t.count("\r\n"))
        self.assertEqual(deeplib.line_count(d), deeplib.line_count(t))

    def test_private_key_block_is_whole_lines(self):
        t = ("# deploy notes\n" + deeplib.PEM_BEGIN + "\n" + PEM_BODY + "\n" + deeplib.PEM_END + "\n" + FILLER)
        d, spans, _ = deeplib.redact_text(t)
        self.assertEqual([(s["line"], s["marker"]) for s in spans],
                         [(n, "[REDACTED-LINE:private_key]") for n in (2, 3, 4)])
        self.assertNotIn(PEM_BODY[:12], d)
        self.assertEqual(deeplib.line_count(d), deeplib.line_count(t))

    def test_transcript_lines_are_whole_lines(self):
        tl = "".join(json.dumps({"role": r, "content": "hello there"}) + "\n" for r in ("user", "assistant", "user"))
        t = "# log\n" + tl + FILLER
        d, spans, _ = deeplib.redact_text(t)
        self.assertEqual({s["line"] for s in spans}, {2, 3, 4})
        self.assertTrue(all(s["marker"] == "[REDACTED-LINE:transcript_or_memory_dump]" for s in spans))

    def _fallback(self, text):
        with self.assertRaises(deeplib.RedactionFallback) as cm:
            deeplib.redact_text(text)
        return cm.exception.args[0]

    def test_fallback_marker_collision(self):
        self.assertEqual(self._fallback(CLAUDE_MD + "see [REDACTED:phone_number#9] above\n"), "marker_collision")
        self.assertEqual(self._fallback(CLAUDE_MD + "see [redacted-line:x] above\n"), "marker_collision")

    def test_fallback_density_spans(self):
        many = "".join(f"call ({520 + i % 3}) 555-{1000 + i}\n" for i in range(51)) + FILLER * 2
        self.assertTrue(deeplib.scan_text(many))
        self.assertEqual(self._fallback(many), "redaction_density")

    def test_fallback_density_whole_lines(self):
        tl = "".join(json.dumps({"role": "user", "content": f"q{i}"}) + "\n" for i in range(6))
        self.assertEqual(self._fallback("# log\n" + tl + "".join(f"line {i}\n" for i in range(30))), "redaction_density")

    def test_fallback_residual_decoded_view(self):
        hexrun = ("mail " + EMAIL + " now").encode().hex()
        t = f"Page {PHONE} now\nblob {hexrun}\n" + FILLER
        self.assertEqual({k for k, _ in deeplib.scan_text(t)}, {"phone_number"})  # hex is a documented scanner gap
        self.assertEqual(self._fallback(t), "redaction_residual")

    def test_fallback_residual_value_survives_elsewhere(self):
        t = f"The nas is {SEG_IP}.\nlegacy id 1.{SEG_IP} still\n" + FILLER
        self.assertEqual(self._fallback(t), "redaction_residual")

    def test_fallback_unscannable(self):
        self.assertEqual(self._fallback(f"call {PHONE}\n" + "x" * 20001 + "\n"), "unscannable")
        self.assertEqual(self._fallback("# k\n" + deeplib.PEM_BEGIN + "\n" + PEM_BODY + "\n" + FILLER), "unscannable")
        self.assertEqual(self._fallback(f"call {PHONE}\u2028more\n" + FILLER), "unscannable")

    def test_percent_encoded_value_is_the_documented_gap(self):
        enc = EMAIL.replace("@", "%40")
        t = f"Page {PHONE} now\nmailto {enc}\n" + FILLER
        d, spans, _ = deeplib.redact_text(t)
        self.assertEqual(len(spans), 1)
        self.assertIn(enc, d)  # not detected, not redacted: DISCLOSURE.md section 7 names this gap


class RedactedPreflight(unittest.TestCase):
    def setUp(self):
        hexrun = ("mail " + EMAIL + " now").encode().hex()
        self.p = Pair(("claude", "codex"), repo=prose_repo(**{
            "README.md": REPO["README.md"] + f"Support line {PHONE} any time\n",                    # doc class: excluded
            "scripts/deploy.py": f"DB = '{EMAIL}'\n",                                         # code: excluded
            ".claude/rules/collide.md": "keep [REDACTED:api_key#1] as is\n" + f"{PHONE}\n",   # marker_collision
            ".claude/rules/dense.md": "".join(f"({520 + i % 3}) 555-{1000 + i}\n" for i in range(60)),
            ".claude/rules/net.md": f"The lab host is {SEG_IP}.\n" + FILLER,                  # path segment
            "inventory/" + SEG_IP + "/notes.txt": "rack notes\n",
            ".claude/rules/hex.md": f"Page {PHONE} now\nblob {hexrun}\n" + FILLER,               # residual
            ".claude/rules/long.md": f"call {PHONE}\n" + "y" * 20001 + "\n",                  # unscannable
            ".claude/rules/excepted.md": f"Ask {EMAIL}\n" + FILLER,                           # exception path
        }), preflight_opts=REDACT + ("--exceptions", str(self._exc())))

    def _exc(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        p = Path(self._td.name) / "exc.json"
        p.write_text(json.dumps({"declared_by": "owner", "exceptions": [
            {"glob": ".claude/rules/excepted.md", "kinds": ["phone_number"], "reason": "partial on purpose"}]}))
        return p

    def tearDown(self):
        self.p.cleanup()
        self._td.cleanup()

    def test_binding_and_fallbacks(self):
        pd, man = self.p.pd, self.p.manifest
        pf = json.loads((pd / "preflight.json").read_text())
        red = json.loads((pd / "redaction.json").read_text())
        src = (self.p.src / "CLAUDE.md").read_bytes()
        box = (pd / "box" / "repo" / "CLAUDE.md").read_bytes()
        # the box holds the derivative only, line-preserving, bound into the manifest
        self.assertNotEqual(box, src)
        self.assertEqual(deeplib.line_count(box.decode()), deeplib.line_count(src.decode()))
        ent = man["files"]["CLAUDE.md"]
        self.assertEqual((ent["redacted"], ent["original_sha256"], ent["sha256"]),
                         (True, hashlib.sha256(src).hexdigest(), hashlib.sha256(box).hexdigest()))
        self.assertEqual(man["manifest_sha256"], deeplib.manifest_hash(pd / "box" / "repo", self.p.files))
        self.assertEqual(man["redaction"]["record_sha256"], hashlib.sha256((pd / "redaction.json").read_bytes()).hexdigest())
        self.assertEqual([f["path"] for f in red["files"]], ["CLAUDE.md"])
        f = red["files"][0]
        self.assertEqual(set(f), {"path", "original_sha256", "derivative_sha256", "transformation", "line_count",
                                  "kinds", "spans", "withheld_count"})
        self.assertEqual((f["transformation"], f["line_count"], f["withheld_count"]),
                         ("redact/1", ent["lines"], len(MARKER_LINES)))
        self.assertEqual({s["line"] for s in f["spans"]}, MARKER_LINES)
        self.assertEqual(set(f["spans"][0]), {"line", "kind", "marker"})
        self.assertEqual((pf["redaction"]["mode"], pf["redaction"]["files"], pf["redaction"]["withheld_spans"]),
                         ("redact-prose", 1, len(MARKER_LINES)))
        # fallbacks: each reason recorded, the file excluded whole as private_info
        ex = {e["path"]: e for e in pf["excluded"]}
        want = {".claude/rules/collide.md": "marker_collision", ".claude/rules/dense.md": "redaction_density",
                ".claude/rules/net.md": "redaction_residual", ".claude/rules/hex.md": "redaction_residual",
                ".claude/rules/long.md": "unscannable"}
        for path, reason in want.items():
            self.assertEqual((ex[path]["reason"], ex[path].get("redaction_fallback")), ("private_info", reason), path)
            self.assertNotIn(path, man["files"])
        self.assertEqual({(x["path"], x["reason"]) for x in red["fallbacks"]}, set(want.items()))
        # not eligible: doc class, code class, a matching (partial) exception -> excluded as before, no fallback
        for path in ("README.md", "scripts/deploy.py", ".claude/rules/excepted.md"):
            self.assertEqual(ex[path]["reason"], "private_info")
            self.assertNotIn("redaction_fallback", ex[path])
        self.assertEqual(ex[".claude/rules/excepted.md"]["exception_did_not_cover"], ["personal_email"])
        # the run echo the reviewer copies back is unchanged in shape (path + reason only)
        echo = self.p.echo("claude")
        self.assertTrue(all(set(e) == {"path", "reason"} for e in echo["exclusions"]))
        self.assertNotIn("CLAUDE.md", {e["path"] for e in echo["exclusions"]})

    def test_withheld_values_never_leave_src(self):
        """No withheld value (nor an 8-char window of the split token) in any file of the pair outside
        the host-side src/: box, manifest, preflight, redaction record, prompts, schemas."""
        needles = [v.encode() for v in VALUES] + [w.encode() for w in windows(SPLIT)]
        for p in self.p.pd.rglob("*"):
            if p.is_file() and "src" not in p.relative_to(self.p.pd).parts[:1]:
                try:
                    b = p.read_bytes()
                except PermissionError:
                    continue
                for n in needles:
                    self.assertNotIn(n, b, str(p.relative_to(self.p.pd)))


class ModeNone(unittest.TestCase):
    def test_default_is_whole_file_exclusion(self):
        p = Pair(("claude",), repo=prose_repo())
        try:
            pf = json.loads((p.pd / "preflight.json").read_text())
            self.assertEqual(pf["redaction"], {"mode": "none", "files": 0, "withheld_spans": 0, "fallbacks": 0})
            self.assertFalse((p.pd / "redaction.json").exists())
            self.assertNotIn("redaction", p.manifest)
            self.assertNotIn("CLAUDE.md", p.manifest["files"])
            self.assertEqual(deeplib.redaction_summary(p.pd), {"mode": "none", "files": 0, "withheld_spans": 0})
            rec, _ = deepgate.gate_report(p.report(), manifest=p.manifest, box=p.pd / "box" / "repo",
                                          schema=json.loads((p.pd / "run-schema.json").read_text()), echo=p.echo(),
                                          bait=p.bait, extra_canaries=[], box_verdict="PASS", receipts=p.receipts())
            self.assertEqual((rec["verdict"], rec["rules"]["10_redaction"]["result"], rec["rules"]["10_redaction"]["mode"]),
                             ("PASS", "CLEAR", "none"))
        finally:
            p.cleanup()


def marker_report(p, fam):
    """Bait finding FIRST, so the released report's indices differ from the raw report's."""
    r = p.report(fam)
    bait_f = r["findings"][1]
    r["findings"] = [
        bait_f,
        {"severity": "medium", "confidence": "medium", "status": "inferred", "area": "secrets_private_info",
         "path": "CLAUDE.md", "line": 6, "affected_behavior": "A database credential sits in agent prose.",
         "preconditions": "Anyone who can read the rules file.", "risk": "Credential exposure.",
         "fix": "Move it to a secret store."},
        {"severity": "low", "confidence": "high", "status": "observed", "area": "enforced_vs_prose_gates",
         "path": "CLAUDE.md", "line": 9, "affected_behavior": "Deploy sign-off is prose only.",
         "preconditions": "An operator skips the step.", "risk": "Unreviewed rollbacks.", "fix": "Gate it in CI."},
        r["findings"][0],
    ]
    r["private_info"] = r["private_info"] + [{"path": "CLAUDE.md", "line": 4, "kind": "personal_email"}]
    r["instruction_shaped"] = r["instruction_shaped"] + [
        {"path": "CLAUDE.md", "line": 3, "paraphrase": "tells the agent to page someone"},
        {"path": "CLAUDE.md", "line": 10, "paraphrase": "general guidance"}]
    return r


AFFECTED = ["$.findings[0]", "$.private_info[0]", "$.instruction_shaped[0]"]  # indices of the RELEASED report (bait entries stripped)


class Rule10AndRelease(unittest.TestCase):
    def setUp(self):
        self.p = Pair(("claude", "codex"), repo=prose_repo(), preflight_opts=REDACT)
        for fam in ("claude", "codex"):
            r = marker_report(self.p, fam)
            (self.p.write_claude_evidence if fam == "claude" else self.p.write_codex_evidence)(r)

    def tearDown(self):
        dd = self.p.pd / "deliverable"
        if dd.exists():
            dd.chmod(0o700)
        self.p.cleanup()

    def _pure(self, report, redaction="file"):
        red = json.loads((self.p.pd / "redaction.json").read_text()) if redaction == "file" else redaction
        return deepgate.gate_report(report, manifest=self.p.manifest, box=self.p.pd / "box" / "repo",
                                    schema=json.loads((self.p.pd / "run-schema.json").read_text()),
                                    echo=self.p.echo(), bait=self.p.bait, extra_canaries=[], box_verdict="PASS",
                                    receipts=self.p.receipts(), redaction=red)[0]

    def test_rule10_lists_affected_by_released_json_path(self):
        rec = self._pure(marker_report(self.p, "claude"))
        r10 = rec["rules"]["10_redaction"]
        self.assertEqual(rec["verdict"], "PASS", rec["failed_rules"])
        self.assertEqual((r10["result"], r10["mode"], r10["redacted_files"], r10["withheld_spans"]),
                         ("FLAG", "redact-prose", 1, len(MARKER_LINES)))
        self.assertEqual(r10["redaction_affected"], AFFECTED)
        self.assertEqual(r10["indexed_over"], "released_report")

    def test_rule10_fails_on_a_record_that_disagrees(self):
        red = json.loads((self.p.pd / "redaction.json").read_text())
        red["files"][0]["spans"][0]["line"] = 1
        rec = self._pure(marker_report(self.p, "claude"), redaction=red)
        self.assertEqual(rec["rules"]["10_redaction"]["result"], "FAIL")
        self.assertIn("10_redaction", rec["failed_rules"])
        rec = self._pure(marker_report(self.p, "claude"), redaction=None)  # manifest says redacted, no record
        self.assertEqual([x["problem"] for x in rec["rules"]["10_redaction"]["problems"]], ["redaction_record_missing"])

    def test_rule4_still_catches_a_quote_of_the_remaining_text(self):
        r = marker_report(self.p, "claude")
        r["findings"][2]["risk"] = QUOTE[:60]
        rec = self._pure(r)
        self.assertIn("4_verbatim", rec["failed_rules"])
        r = marker_report(self.p, "claude")
        dl = (self.p.pd / "box" / "repo" / "CLAUDE.md").read_text().split("\n")
        r["findings"][2]["risk"] = dl[2][:58]  # a quote that runs through a marker
        self.assertIn("[REDACTED:", r["findings"][2]["risk"])
        self.assertIn("4_verbatim", self._pure(r)["failed_rules"])

    def test_release_read_deliver_redactions(self):
        for fam in ("claude", "codex"):
            self.assertEqual(self.p.check(fam)[0], 0)
            rc, g = self.p.gate(fam)
            self.assertEqual((rc, g["verdict"]), (0, "PASS"), g["failed_rules"])
            self.assertEqual(g["rules"]["10_redaction"]["redaction_affected"], AFFECTED)
            self.assertEqual(g["sanitizer_withheld"], 0)
            self.p.audit(fam)
        q = run(GATE, "release", str(self.p.pd), ok=False)
        rel = json.loads((self.p.pd / "release.json").read_text())
        self.assertEqual((q.returncode, rel["status"]), (0, "RELEASED"), rel.get("reasons"))
        self.assertEqual(rel["redaction"], {"mode": "redact-prose", "files": 1, "withheld_spans": len(MARKER_LINES)})
        rd = run(GATE, "read", str(self.p.pd), "claude")
        self.assertEqual(json.loads(rd.stdout)["findings"][0]["path"], "CLAUDE.md")
        self.assertIn(", ".join(AFFECTED), rd.stderr)
        self.assertIn("unresolved", rd.stderr)
        run(GATE, "deliver", str(self.p.pd))
        out = json.loads((self.p.pd / "deliverable" / "owner-review.json").read_text())
        self.assertEqual(out["scope"]["redacted_files"],
                         [{"path": "CLAUDE.md", "coverage": "read the redacted derivative",
                           "withheld_spans": len(MARKER_LINES)}])
        r = out["reports"]["claude"]
        self.assertEqual([bool(x.get("redaction_unresolved")) for x in r["findings"]], [True, False, False])
        self.assertTrue(r["private_info"][0]["redaction_unresolved"])
        self.assertTrue(r["instruction_shaped"][0]["redaction_unresolved"])
        md = (self.p.pd / "deliverable" / "owner-review.md").read_text()
        self.assertIn("Read the redacted derivative", md)
        self.assertIn("unresolved: withheld span", md)

    def test_release_refuses_a_redaction_record_changed_after_prepare(self):
        for fam in ("claude", "codex"):
            self.p.check(fam)
            self.p.gate(fam)
            self.p.audit(fam)
        rp = self.p.pd / "redaction.json"
        rec = json.loads(rp.read_text())
        rec["note"] = "edited"
        rp.write_text(json.dumps(rec))
        q = run(GATE, "release", str(self.p.pd), ok=False)
        rel = json.loads((self.p.pd / "release.json").read_text())
        self.assertEqual((q.returncode, rel["status"]), (4, "SEALED"))
        self.assertIn("redaction record does not match the one bound into the manifest", rel["reasons"])
        self.assertEqual(rel["redaction"]["mode"], "redact-prose")


class ReviewerPrompt(unittest.TestCase):
    def test_marker_paragraph(self):
        t = (DEEP / "reviewer-system.md").read_text()
        self.assertIn("[REDACTED:<kind>#<n>]", t)
        self.assertIn("[REDACTED-LINE:<kind>]", t)
        self.assertIn("A conclusion that rests on a marked span is `inferred`, never `observed`.", t)


# =========================================================================== redactions + inspect
class RedactionsCli(unittest.TestCase):
    def test_owner_review_list_has_no_values(self):
        p = Pair(("claude",), repo=prose_repo(), preflight_opts=REDACT)
        try:
            out = run(GATE, "redactions", str(p.pd)).stdout
            rows = [l.split("\t") for l in out.splitlines()[2:]]
            self.assertEqual(out.splitlines()[1], "path\tline\tkind\tmarker")
            self.assertEqual({int(r[1]) for r in rows}, MARKER_LINES)
            self.assertTrue(all(r[0] == "CLAUDE.md" and r[3].startswith("[REDACTED:") for r in rows))
            for v in VALUES:
                for w in windows(v):
                    self.assertNotIn(w, out)
        finally:
            p.cleanup()
        q = Pair(("claude",), repo=prose_repo())
        try:
            self.assertIn("mode none", run(GATE, "redactions", str(q.pd)).stdout)
        finally:
            q.cleanup()


SENT = "SENTINEL" + "q7v"


class InspectNoLeak(unittest.TestCase):
    """`inspect` prints allowlisted keys only. Every forbidden string of the pair's raw records (bait values,
    the canary token, everything in box-dummy*.json and session-spec*.json, and anything held under a key
    named headers, auth_b64, values, exec_env or env in ANY record) is absent from its output."""

    def setUp(self):
        self.p = Pair(("claude", "codex"), repo=prose_repo(), preflight_opts=REDACT)
        for fam in ("claude", "codex"):
            r = marker_report(self.p, fam)
            (self.p.write_claude_evidence if fam == "claude" else self.p.write_codex_evidence)(r)
            self.p.check(fam)
            self.p.gate(fam)
            self.p.audit(fam)
        run(GATE, "release", str(self.p.pd), ok=False)
        pd = self.p.pd
        for fam in ("claude", "codex"):
            fd = pd / fam
            (fd / f"box-dummy-{fam}.json").write_text(json.dumps({"auth_b64": f"{SENT}-dummy-auth-{fam}",
                                                                  "token": f"{SENT}-dummy-token-{fam}"}))
            (fd / "box-dummy-audit.json").write_text(json.dumps({"token": f"{SENT}-dummy-audit-{fam}"}))
            (fd / f"session-spec-{fam}.json").write_text(json.dumps({
                "exec_env": {"CODEX_HOME": f"{SENT}-exec-env-{fam}"}, "env": [f"{SENT}-env-{fam}"],
                "headers": {"authorization": f"{SENT}-hdr-{fam}"}, "argv": [f"{SENT}-argv-{fam}"]}))
            # forbidden keys planted INSIDE records inspect does read: the allowlist must drop them
            for name in ("run-meta.json", "gate.json", "audit.json", "box-checks.json"):
                rec = json.loads((fd / name).read_text())
                rec.update({"values": [f"{SENT}-values-{name}"], "headers": {"x": f"{SENT}-headers-{name}"},
                            "auth_b64": f"{SENT}-auth-{name}", "canary_token": f"{SENT}-canary-{name}",
                            "exec_env": {"A": f"{SENT}-exec-{name}"}, "env": {"B": f"{SENT}-env-{name}"},
                            "unlisted_key": f"{SENT}-unlisted-{name}"})
                (fd / name).write_text(json.dumps(rec))
        for name in ("pair.json", "manifest.json", "preflight.json", "redaction.json"):
            rec = json.loads((pd / name).read_text())
            rec["values"] = [f"{SENT}-values-{name}"]
            rec["headers"] = {"cookie": f"{SENT}-cookie-{name}"}
            (pd / name).write_text(json.dumps(rec))
        self.out = run(GATE, "inspect", str(pd)).stdout

    def tearDown(self):
        self.p.cleanup()

    def _forbidden(self) -> set[str]:
        pd = self.p.pd
        found = set()
        bait = json.loads((pd / "bait.json").read_text())
        found |= {v for v in bait["values"]} | {bait["canary_token"]}

        def strings(node):
            if isinstance(node, dict):
                for v in node.values():
                    yield from strings(v)
            elif isinstance(node, list):
                for v in node:
                    yield from strings(v)
            elif isinstance(node, str):
                yield node

        def under_keys(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in deepgate.INSPECT_FORBIDDEN_KEYS:
                        found.update(strings(v))
                    under_keys(v)
            elif isinstance(node, list):
                for v in node:
                    under_keys(v)

        for p in pd.rglob("*.json"):
            rel = p.relative_to(pd)
            if rel.parts[0] in ("src", "box", "gen", "current", "deliverable") or not os.access(p, os.R_OK):
                continue
            try:
                rec = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            if deepgate.INSPECT_NEVER_OPEN.match(p.name):
                found.update(strings(rec))
            under_keys(rec)
        return {s for s in found if len(s) >= 6}

    def test_inspect_prints_no_forbidden_string(self):
        forbidden = self._forbidden()
        # the walk really found the planted material and the bait
        self.assertGreaterEqual(len([s for s in forbidden if s.startswith(SENT)]), 40)
        self.assertTrue(any(s.startswith("CANARY-") for s in forbidden))
        for s in sorted(forbidden):
            self.assertNotIn(s, self.out)
        self.assertNotIn(SENT, self.out)  # nothing planted, not even under an unlisted key
        for k in deepgate.INSPECT_FORBIDDEN_KEYS:
            self.assertNotIn(f'"{k}"', self.out)

    def test_inspect_shows_the_sanitized_view(self):
        v = json.loads(self.out)
        recs = v["records"]
        self.assertEqual(recs["release.json"]["status"], "RELEASED")
        self.assertEqual(recs["release.json"]["redaction"]["mode"], "redact-prose")
        self.assertEqual(recs["claude/gate.json"]["verdict"], "PASS")
        self.assertEqual(recs["claude/gate.json"]["rules"]["10_redaction"]["redaction_affected"], AFFECTED)
        self.assertEqual(recs["manifest.json"]["manifest_sha256"], self.p.manifest["manifest_sha256"])
        self.assertEqual(recs["redaction.json"]["files"][0]["path"], "CLAUDE.md")
        self.assertNotIn("spans", recs["redaction.json"]["files"][0])
        self.assertIn("bait.json", v["never_opened"])
        self.assertIn("audit_result", recs["codex/audit.json"])
        self.assertEqual(set(recs["claude/audit.json"]["concerns"]), {"count"})
        for v_ in VALUES:
            self.assertNotIn(v_, self.out)

    def test_specs_never_name_a_forbidden_key(self):
        for spec in deepgate.INSPECT_SPECS.values():
            self.assertFalse(deepgate._spec_keys(spec) & deepgate.INSPECT_FORBIDDEN_KEYS)


if __name__ == "__main__":
    unittest.main()
