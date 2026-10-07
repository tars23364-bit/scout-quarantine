"""P10 / contract C11: Serafina's three residuals against C10.

R1  the marker reservation covers every admitted PATH, including a file whose text is redaction-eligible
    (C10 skipped `rel in redacted` before the path check); gate rule 10 FAILs on any admitted path that
    carries a marker prefix, since no record can explain one.
R2  the inspector screens its WHOLE emitted object (diagnostic names and never_opened entries included)
    and applies the canary / box-dummy screens to the decoded (base64, hex) views of every string.
R3  inspect reads every record through pinned directory descriptors: the pair dir and each intermediate
    directory are opened O_DIRECTORY|O_NOFOLLOW, their identity checked against the lstat, and the leaf
    opened relative to its pinned parent, so a directory swapped after the check is not followed.

Every private-looking value is synthetic, assembled at runtime; no real owner data, bait or credential
is read, and nothing under ~/.athena is touched.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deepfixture import DEEP, REPO, Pair  # noqa: E402
from test_p8 import FILLER, PW, REDACT  # noqa: E402

sys.path.insert(0, str(DEEP))
import deepgate  # noqa: E402
import deeplib  # noqa: E402

MARKED_PATHS = (".claude/rules/[REDACTED:password#1].md", ".claude/rules/[redacted-line:x].md")
FLAGGED = f'db_password = "{PW}"\n' + FILLER          # a detected assignment + harmless filler (her R1 body)
CLEAN = "ordinary instructions\n"


# =========================================================================== R1
class MarkerPathReserved(unittest.TestCase):
    def _run(self, path, body, opts):
        p = Pair(("claude",), repo={**REPO, path: body}, preflight_opts=opts)
        pf = json.loads((p.pd / "preflight.json").read_text())
        ex = {e["path"]: e for e in pf["excluded"]}
        return p, pf, ex

    def _assert_nowhere(self, p, path):
        self.assertNotIn(path, p.manifest["files"])
        self.assertFalse(any(deeplib.MARKER_PREFIX_RE.search(f) for f in p.manifest["files"]))
        box = p.pd / "box" / "repo"
        self.assertFalse(any(deeplib.MARKER_PREFIX_RE.search(q.relative_to(box).as_posix())
                             for q in box.rglob("*")))

    def _gate(self, p, red):
        return deepgate.gate_report(p.report(), manifest=p.manifest, box=p.pd / "box" / "repo",
                                    schema=json.loads((p.pd / "run-schema.json").read_text()), echo=p.echo(),
                                    bait=p.bait, extra_canaries=[], box_verdict="PASS", receipts=p.receipts(),
                                    redaction=red)[0]

    def test_flagged_text_marker_path_redact_mode(self):
        """Her R1 case: redaction-eligible text under a marker path. C10 admitted it redacted:true."""
        for path in MARKED_PATHS:
            with self.subTest(path=path):
                p, pf, ex = self._run(path, FLAGGED, REDACT)
                try:
                    self.assertEqual((ex[path]["reason"], ex[path]["redaction_fallback"]),
                                     ("private_info", "marker_collision"))
                    self._assert_nowhere(p, path)
                    red = json.loads((p.pd / "redaction.json").read_text())
                    self.assertEqual(red["files"], [])
                    self.assertIn({"path": path, "reason": "marker_collision"}, red["fallbacks"])
                    self.assertEqual(pf["redaction"]["files"], 0)
                    gate = self._gate(p, red)
                    self.assertEqual(gate["rules"]["10_redaction"]["result"], "CLEAR")
                    self.assertEqual(gate["verdict"], "PASS")   # the marked file never reached the box
                finally:
                    p.cleanup()

    def test_clean_text_marker_path_both_modes(self):
        for path in MARKED_PATHS:
            for opts in ((), REDACT):
                with self.subTest(path=path, opts=opts):
                    p, _pf, ex = self._run(path, CLEAN, opts)
                    try:
                        self.assertEqual(ex[path]["reason"], "marker_reserved")
                        self.assertEqual(ex[path].get("redaction_fallback"), "marker_collision" if opts else None)
                        self._assert_nowhere(p, path)
                    finally:
                        p.cleanup()

    def test_flagged_text_marker_path_default_mode(self):
        p, _pf, ex = self._run(MARKED_PATHS[0], FLAGGED, ())
        try:
            self.assertEqual(ex[MARKED_PATHS[0]]["reason"], "private_info")
            self.assertNotIn("redaction_fallback", ex[MARKED_PATHS[0]])
            self._assert_nowhere(p, MARKED_PATHS[0])
        finally:
            p.cleanup()

    def test_unmarked_flagged_file_still_redacted(self):
        """Control: the same body under an ordinary path is still admitted as a redacted derivative."""
        p, _pf, _ex = self._run(".claude/rules/db.md", FLAGGED, REDACT)
        try:
            self.assertTrue(p.manifest["files"][".claude/rules/db.md"].get("redacted"))
        finally:
            p.cleanup()

    def test_rule10_fails_on_a_marker_path(self):
        for path in MARKED_PATHS:
            with self.subTest(path=path):
                man = {"files": {"a.md": {}, path: {"sha256": "x", "lines": 1}}}
                probs = deepgate.redaction_problems(None, man, {"a.md": "plain\n", path: "plain\n"})
                self.assertEqual(probs, [{"path": "[withheld]", "problem": "redaction_marker_in_path"}])
                # a marker path in the manifest only (no box text) is still refused
                self.assertEqual(deepgate.redaction_problems(None, man, {"a.md": "plain\n"}),
                                 [{"path": "[withheld]", "problem": "redaction_marker_in_path"}])
        self.assertEqual(deepgate.redaction_problems(None, {"files": {"a.md": {}}}, {"a.md": "plain\n"}), [])
        self.assertIn("redaction_marker_in_path", deepgate.VOCAB)

    def test_gate_fails_a_box_that_admitted_a_marker_path(self):
        """The second check: a box/manifest that carries a marker path (as C10 produced) FAILs rule 10."""
        p, _pf, _ex = self._run(".claude/rules/db.md", FLAGGED, REDACT)
        try:
            red = json.loads((p.pd / "redaction.json").read_text())
            path = MARKED_PATHS[0]
            box = p.pd / "box" / "repo"
            (box / path).parent.mkdir(parents=True, exist_ok=True)
            (box / ".claude/rules/db.md").rename(box / path)
            p.manifest["files"][path] = p.manifest["files"].pop(".claude/rules/db.md")
            for f in red["files"]:
                if f["path"] == ".claude/rules/db.md":
                    f["path"] = path
            gate = self._gate(p, red)
            self.assertEqual(gate["rules"]["10_redaction"]["result"], "FAIL")
            self.assertIn({"path": "[withheld]", "problem": "redaction_marker_in_path"},
                          gate["rules"]["10_redaction"]["problems"])
            self.assertEqual(gate["verdict"], "FAIL")
        finally:
            p.cleanup()


if __name__ == "__main__":
    unittest.main()
