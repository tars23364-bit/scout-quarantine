# Deep review contract changelog

The contract version is `sha256` over the files in `deeplib.CONTRACT_FILES` (name + per-file
sha256, sorted): the reviewer and auditor prompts, the report schema, the gate, lib, audit,
depth and session code, the depth policy, the launch script, the three Dockerfiles, the codex
entrypoint, both allowlists and squid.conf. `deep-review.sh contract` prints it.

Rules:
- `deep-review.sh pair` refuses to run on a version that has no entry here.
- Every change to a contract file gets a new entry: what changed, why, and what it means for
  earlier results. A pair records `contract_version` + `contract_label`, and `pair-labels`
  marks a rerun of the same source with the contracts its earlier pairs ran under.
- Entries are append-only. A version that ran must never be edited away.

## C0 pre-contract (P0 + P1, 2026-10-06)
- No version was recorded. Pairs from P0/P1 have no `contract_version` in their manifest and are
  labelled `pre-contract` by `pair-labels`. P1 made one post-hoc reviewer-prompt change between
  its agent-pulse pairs 2 and 3, disclosed in the P1 receipt.

## C1 P2 freeze (2026-10-07)
- contract_version: a12793b715a2573124b450423950c99f0c0db2b8854e35d56e6a2181c2ab43aa
- Depth: `deepdepth.py` (classification fixed before the run, reading plans, read receipts from
  the trusted tool log, truncation-aware credit), gate rule `9_read_depth`, `depth-policy.json`
  (`max_repair_turns` 2; codex `tool_output_token_limit` 25000 with a 16 KB whole-output credit
  window, head/tail 8 KB above it).
- Sessions: `deepsession.py` drives every model box (idle container + `docker exec` per turn,
  Claude `--session-id`/`--resume`, Codex `exec resume`), validates each spec, removes the box on
  every path. The Claude token is no longer in the container env. The Codex auth file arrives
  over stdin (`codex-entry.sh` `idle` / `put-auth` / `put-schema`). The env-var path is removed.
- Reviewer prompt: a new "Coverage and required reading" section, and the task message carries
  a REQUIRED READING plan and a no-history line. This was written before any P2 run, not tuned on
  results. Schema unchanged (`deep-report/2`).
- Gate: base64/hex decoding for rules 4 and 5, box-credential shapes in rule 5, `run{}`
  unexpected keys counted not named, JSON paths over known keys only, the whole record sanitized,
  exceptions -> verdict ERROR.
- Box checks: `admitted_credential_absent`, `credential_shapes_absent`, every turn's init
  toolset checked, egress record names allowlisted hosts only.
- Audit: bound to host-computed facts (`binding`, `binding_sha256`), the routing checked where it
  is planned and where it runs, concern lines screened by the verbatim/secret/link/decoded rules.
- Release: contract consistency, binding recomputation, session failure reasons, exception-safe
  and all-or-nothing unseal.
- Probes: `toolcheck` and `codexcheck` run through the session driver with a resumed second
  turn and credential-path probes; new `disclosurecheck`.
- Effect on earlier results: P1's released agent-pulse pair `c72af2` would FAIL rule 9 (its
  Claude half skimmed the daemon and never opened the test suite). Its release stands as a P1
  record and is not evidence of depth.

## C2 package-scan fixes + signal safety (2026-10-07)
- contract_version: ca774fbfa682eba729e5641374d8dddce17ac6660ec4bd39fdad567b1fe6adfd
- Why: the P2 package must pass the preflight scanner with no exceptions, and the scanner run over
  the deep code itself found false positives in contract files. Also, stopping a pair with
  SIGTERM left its box, proxy, networks and volume running (seen live on the aborted C1 pair
  `20261007T013902Z-49c15d`).
- Detector (`deeplib.py`): `reviewer` (the box's synthetic uid-10001 user) joins the generic
  home users; a call expression (`func(arg`) is not a password value; a token carrying a compact
  UTC stamp (a host run id, `name-YYYYMMDDTHHMMSSZ-hex`) is not a high-entropy secret. The
  selftest fixtures and the bait key armour are assembled at runtime, so the source has no literal
  PII or key shape. Regression tests in `tests/test_p2.py` (DetectorRegressionsP2).
- `deepsession.py`: SIGTERM/SIGHUP/SIGINT unwind through the session's finally (box removed, raw
  resealed, `session_error: stopped_by_signal`, exit 143). `deep-review.sh`: the pair's EXIT trap
  first sweeps every container/network/volume named with the pair id, then runs release.
- Effect on earlier results: C1 ran probes, a synthetic smoke pair (`888542`, RELEASED), a live
  injected-timeout pair (`2d70ab`, SEALED), and the agent-pulse pair `49c15d`, which was stopped by
  hand at the Codex reviewer's start to make this fix and is not a result. All probes were re-run under C2.

## C3 Serafina's P2 EDIT/HOLD fixes R1-R4 (2026-10-07)
- contract_version: f9187f9f41135fc6dc1d2a730e3c89a241745813c47ac3039b7a9af134da072d
- Why: her review of the C2 package (EDIT/HOLD, 2026-10-06) with eight synthetic probes on the exact
  C2 controls. All eight reproduced on C2; seven are now inverted regression tests that fail on C2 and
  pass on C3 (`tests/test_p3.py` SeraProbesInverted; p06 was a positive probe and still passes).
- R1, audit completion: `deepaudit.completion()` re-derives a completed audit from host and sealed
  records only (cross-family identity, model, CLI, contract; the session driver's terminal receipt
  with exit exactly 0 and turn-file hashes, written last; the family's terminal success event; input
  = stored prompt = build_prompt(report as gated); reply and verdict hashes; egress proof). Release
  re-derives it and never trusts `audit.json` alone; reviewer exit must be exactly 0. `jdump` is atomic.
- R2, crash-atomic release: one immutable generation `gen/<id>/` (both reports + release.json),
  committed by one `os.replace` of `current`; readers admit only from it, by hash, all or nothing.
- R3, credential boundary: no real credential in any box. `credproxy.js` (new; replaces squid:
  `squid.conf` and `Dockerfile.proxy` leave the contract) holds it, requires the box's exact dummy,
  strips every box auth header, sets the real one, forwards the contract routes over verified TLS to
  the one allowlisted host, scrubs responses. Boxes get dummies (`deeplib.box_dummy`). New in the
  contract: `credproxy.js`, `credproxy-claude.json`, `credproxy-codex.json`, `Dockerfile.credproxy`,
  and the check tooling `fake-upstream.js` and `memscan.js`. Seccomp is unchanged.
- R4, effective runtime: a runtime descriptor per box, bound and re-checked at release against the
  contract, the new `images.lock.json` (reviewer aec3b516, codex 700f3271, credproxy 7ad8794f) and
  the containers' own reports.
- Prompts and schema: unchanged from C2 (`reviewer-system.md`, `auditor-deep.md`,
  `deep-report.schema.json` byte-identical). The Claude auditor's system prompt moved from a shell
  string into `deepaudit.AUDIT_SYSTEM`, same text. No prompt was tuned on any P3 result.
- Effect on earlier results: every C2 record lacks the completion receipt, the runtime descriptor
  and a committed generation, so no C2 pair can be re-released under C3. The C2 agent-pulse pair
  `20261007T014639Z-910035` stays a C2 record. Pre-freeze development runs of the P3 probes
  (netcheck, canarycheck, boxcheck, toolcheck, memcheck, codexcheck, an ad-hoc structured-output
  smoke) ran on unlogged code and are not C3 evidence; every probe is re-run under C3.

## C4 one Claude route discovered by the C3 live pair (2026-10-07)
- contract_version: a9029cb897bafe8fda1af02aac8d28151da951a26cd55f6a2940af8e28cf1ea2
- C3 -> C4 diff: `credproxy-claude.json` routes `[["POST", "/v1/messages"]]` -> `[["POST", "/v1/messages"],
  ["POST", "/v1/messages/count_tokens"]]`. Same upstream host (`api.anthropic.com`, allowlist unchanged),
  same strip-then-set header replacement, same TLS policy; no other file of the contract changed, no
  image changed (the config is mounted, so `images.lock.json` is unchanged).
- Why: the C3 agent-pulse pair `20261007T040253Z-c9b1ce` showed Claude Code 2.1.292 calling
  `POST /v1/messages/count_tokens?beta=true` 8 times during a real review (no grounding or smoke run
  had made that call). The proxy refused each (403 `route_not_allowlisted`), the box check
  `egress_allowlisted_only` FAILED on the denials, and release correctly SEALED the pair. The
  endpoint set of that pair is now a test fixture (`tests/fixtures/c3-pair-endpoints.json`, derived
  from its proxy logs with their sha256) and `test_p3.RouteCoverageC4` requires the route lists to
  equal it exactly, plus refusals of neighbouring paths.
- Effect on earlier results: the C3 pair stays SEALED as a C3 record (evidence that the egress check
  seals a real run). The next agent-pulse pair is a rerun under C4.

## C5 Serafina's P3/C4 review fixes F1-F2 (2026-10-07)
- contract_version: 48087c9f803f415c27f76d609dcf94bcfc04081ccd5bfdea14394e17d355d171
- C4 -> C5 diff in the contract: `deepaudit.py`, `deepgate.py`, `deeplib.py`, `deepsession.py`,
  `deep-review.sh`. Unchanged: prompts and schema (`reviewer-system.md`, `auditor-deep.md`,
  `deep-report.schema.json`), both allowlists, the proxy code and both route configs
  (`credproxy.js`, `credproxy-claude.json`, `credproxy-codex.json`), all Dockerfiles, `codex-entry.sh`,
  `depth-policy.json`, `deepdepth.py`, `fake-upstream.js`, `memscan.js` and `images.lock.json` (no image
  rebuilt). No route, allowlist, prompt or image changed.
- Why: her review of the P3/C4 package (REVISE, report sha256 a32bd771...20af6) with eight synthetic
  paired probes on the exact C4 controls: two malformed terminal receipts and four weakened launch
  declarations RELEASED, and an empty audit record parsed PASS (sealed only by a runtime check).
- F1, session records: `deeplib.load_record` rejects a missing, malformed, non-object or empty record
  by name; `deeplib.session_record_problems` requires the terminal receipt's closed schema
  (written_at, exit, timed_out, session_error, turn_files, stdin_sha256, runtime_evidence_sha256),
  success in every status, and no contradiction with the outer record (exit, timed_out,
  session_error, turns, evidence, timestamps). `deepaudit.completion` binds the complete receipt;
  `deepgate.release_state` re-derives the reviewer's AND the auditor's record itself; the binding
  gains `reviewer_terminal_sha256`.
- F2, effective launch: docker run vectors are parsed as docker parses them and judged on their
  effective values against an option allowlist, for the box AND the proxy (`validate_proxy_run`, new);
  CLI options are normalized (codex sandbox in every syntax, Claude permission mode, variadic
  `--add-dir`). The session driver records `docker inspect` of the box and its proxy and `docker
  network inspect` of their networks, refuses to start a turn on any difference from the
  declaration, and binds the evidence in its terminal receipt; release compares it with the runtime
  descriptor and `images.lock.json`. `deep-review.sh` passes `proxy_name` to every session spec.
- Effect on earlier results: C3 stays SEALED and C4 stays RELEASED as written; their records lack the
  inspect evidence and the C5 receipt fields, so neither can be re-released under C5. The next
  agent-pulse pair is a rerun under C5.

## C6 Serafina's P4/C5 review fix F2a (2026-10-07)
- contract_version: b5b9d7509b56cfca8d842303239604ca0cc5a5ebd8a418cfc21b897b4ee21b1b
- C5 -> C6 diff in the contract: `deepsession.py` only. Unchanged: every other contract file, so no
  prompt, schema, allowlist, route config, proxy code, Dockerfile, `deep-review.sh`, depth policy or
  image changed, and no launch vector the launcher emits changed.
- Why: her review of the P4/C5 package (REVISE, report sha256 de6eb0ae...2884b): `_is_root` compared
  literal strings, so a proxy `--user 00:00` with matching inspect user `00:00`, made before binding,
  RELEASED; `00000:10001`, `+0:0` and `-0:0` were classified non-root too. Moby resolves numeric user
  components with strconv.Atoi, so each is uid 0.
- F2a: `deepsession.user_identity` is the one rule for every box vector (reviewer, auditor, probe),
  the proxy vector and the inspect evidence of both. It judges the raw string, before any trim or int
  coercion: each half must be an ASCII canonical decimal `0|[1-9][0-9]*` in 0..4294967294 or an ASCII
  name `[A-Za-z_][A-Za-z0-9_.-]*`; anything else is `uid_noncanonical` (refused, never normalized).
  Root (user half `0` or `root`, or an empty user) stays its own reason, `runs_as_root`. The group
  half's spelling is checked; its value carries no policy, as in C5. `_is_root` is removed.
- Effect on earlier results: C3 stays SEALED, C4 and C5 stay RELEASED as written. The C5 pair's
  records pass the C6 policy unchanged (its declared users are `10001:10001` and the credproxy image
  default), but they are bound to C5 and are not re-released under C6.

## C7 Serafina's P5/C6 review residual: oversized decimal components (2026-10-07)
- contract_version: 3069d016557f03b29b8fc024f93d08f5a386e2fbeffd4b3651da2de6cdb17deb
- C6 -> C7 diff in the contract: `deepsession.py` only (`user_identity` and one constant). Unchanged:
  every other contract file, so no prompt, schema, allowlist, route config, proxy code, Dockerfile,
  `deep-review.sh`, depth policy or image changed, and no launch vector the launcher emits changed.
- Why: her review of the P5/C6 package (ACCEPT, F2a closed; report sha256 c0973c6c...a5220) named one
  low, non-blocking residual: `user_identity` called `int()` on a canonical decimal of any length, so a
  4301-digit uid or gid exceeded Python's default int-conversion limit and raised ValueError. A matching
  declaration/evidence pair made before binding still SEALED (release exit 4, zero reports), but on
  "release check raised ValueError" instead of the named reason.
- Fix: a decimal component longer than ten digits (the length of 4294967294) is `uid_noncanonical`
  before any int conversion, in the user and the group half; ten digits or fewer are judged by value
  as in C6. The interpreter limit is not widened. No other behaviour changed.
- Effect on earlier results: C3 stays SEALED, C4 and C5 stay RELEASED as written; no record is
  relabeled or re-released under C7.

## C8 Rule 5 structural exemption after the first third-party pair (2026-10-07)
- contract_version: 7ea7e5aa674d889b974f9b45add1b7423ffea46731a69180eedf010a075b8f9e
- C7 -> C8 diff in the contract: `deepgate.py` and `deeplib.py`. Unchanged: every other contract file,
  so no prompt, schema, allowlist, route config, proxy code, Dockerfile, `deep-review.sh`, depth policy
  or image changed, and no launch vector the launcher emits changed.
- Why: pair 20261007T082235Z-81a82e (first third-party source, C7) SEALED on both families with one
  rule-5 hit each, kind `api_key`, at `$.coverage.<key>`. The string was a host-built manifest path whose
  directory names plus one 23-character directory read as a 52-character token to the GENERIC
  high-entropy heuristic (`HIGH_ENT_RE`); no vendor pattern matched. The reviewers did nothing wrong.
- Fix (Serafina's structural edit applied, not value equality): `deeplib.scan_text_detailed` returns
  each hit's detector (kinds unchanged; `scan_text` is its projection). Rule 5 sets aside ONLY the
  `generic_high_entropy` detector, on the string itself (not a decoded view), and ONLY in a structural
  position enumerated from `deep-report.schema.json` (coverage keys; `findings[].path`,
  `private_info[].path`, `instruction_shaped[].path`; never `run.exclusions[].path`) whose exact string
  rule 2 validated against the manifest at that position. Vendor patterns, every other detector,
  decoded views, box credential shapes and the whole-report bait, canary and extra-canary searches still
  apply there; every other position is scanned as before. The rule records
  `structural_strings_checked` and `structural_generic_suppressed` (json path, kind, detector only).
- Owner deliverable: `scope.naming_warnings`, kind `token_shaped_name`, host-derived from the manifest
  (a naming warning, not proof a secret exists). A path that matches a concrete pattern, another
  detector, a decoded view, a credential shape or a known value is listed as "path withheld".
- Effect on earlier results: C3 stays SEALED, C4 and C5 stay RELEASED, pair 81a82e stays SEALED under
  C7 as written; nothing is relabeled, rerun or re-released under C8.

## C9 Redacted-prose mode and the sanitized record inspector (2026-10-07)
- contract_version: bcb42cbec5c04d049dc12d3182584d67bba346bc2d892680e2667ed59e4f3b7d
- C8 -> C9 diff in the contract: `deeplib.py`, `deepgate.py`, `deep-review.sh` and `reviewer-system.md`.
  Unchanged: every other contract file, so no auditor prompt, schema (`deep-report.schema.json`),
  allowlist, route config, proxy code, Dockerfile, depth policy, session driver or image changed. The
  emitted launch vectors keep their shape; the Claude reviewer's `--system-prompt` argument carries the
  one added `reviewer-system.md` paragraph (the Codex prompt starts with the same bytes).
- Why: on the first third-party pairs the preflight dropped a whole file when one line tripped a
  detector, which hid the agent-facing prose (CLAUDE.md, rules files) from both reviewers: the prose an
  agent reader would obey was the prose least reviewed. Design input: Serafina's position of
  2026-10-07 05:3x (separately admitted redacted-prose mode, local redaction before hosted review,
  digests bound with a line map, line-preserving typed markers, rescan, coverage "read the redacted
  derivative" with withheld-span counts, affected findings unresolved, whole-file exclusion the
  fallback). Creighton's go 2026-10-07 05:55.
- Change: `preflight --redact-prose` (opt-in; `pair` passes it through; mode recorded in
  `preflight.json`, `manifest.json`, `release.json`). Only `agent_prose` files that would be excluded as
  `private_info`, with no matching exception entry and no flagged name. Each detector span becomes
  `[REDACTED:<kind>#<n>]`, each line-only hit (transcript lines, private key blocks)
  `[REDACTED-LINE:<kind>]`; line count and numbers are the original's. Fallback to whole-file exclusion
  with `redaction_fallback`: `redaction_density` (>10% whole-line markers or >50 markers),
  `redaction_residual` (rescan with the scanner, decoded views and credential shapes; or a withheld value
  surviving in the derivative or an admitted path), `marker_collision`, `unscannable`. `redaction.json`
  binds `original_sha256`, `derivative_sha256`, `redact/1`, line count and spans (line, kind, marker);
  manifest entries gain `redacted: true` and `original_sha256`, and `manifest_sha256` covers the
  derivative bytes. `scan_text_detailed` returns `(kind, line, start, end, detector)` (its `scan_text`
  projection is unchanged; `scan_spans` reports every match for the redactor). Gate rule `10_redaction`
  lists by json path (over the report as released) every findings[], private_info[] and
  instruction_shaped[] entry whose path:line lands on a marker line (FLAG, never FAIL) and FAILs a
  redaction record that disagrees with the manifest or the box; release refuses a record that is not the
  one bound into the manifest. `read` names the affected entries on stderr; the deliverable says "read
  the redacted derivative" with per-file counts and marks the entries unresolved. New read-only
  subcommands: `redactions <pair>` (path, line, kind, marker; never a value) and `inspect <pair>`
  (allowlisted keys per record; never bait values, canary, box dummies, session env, headers,
  auth_b64 or any key named values).
- Unchanged: bait, canary, rules 0 to 9, allowlists, proxy, images, schema. A pair run without
  `--redact-prose` preflights, gates and releases as under C8 (rule 10 CLEAR, `redaction.mode: none`).
- Effect on earlier results: none; nothing relabeled, rerun or re-released. C3 stays SEALED, C4 and C5
  stay RELEASED, pair 81a82e stays SEALED under C7, and every C8 pair stands as written under C8.

## C10 Serafina's four required edits to C9, plus the bare-id residual (2026-10-07)
- contract_version: 5c23c4c1e652da41ff0fe518981c2b3bbfa22e3b53de562f86efd47cb45bdb9d
- C9 -> C10 diff in the contract: `deeplib.py`, `deepgate.py`, `deep-review.sh` and `reviewer-system.md`.
  Unchanged: every other contract file, so no auditor prompt, schema, allowlist, route config, proxy
  code, Dockerfile, depth policy, session driver or image changed. The emitted launch vectors keep their
  shape; the Claude reviewer's `--system-prompt` argument carries one added sentence (the marker
  reservation, below).
- Why: Serafina's C9 review (EDIT, 2026-10-07; report sha256 e280ba23...) found four defects by
  synthetic probe: F1 a detected assignment value surviving bare beside its redacted assignment (and in an
  admitted path) while the file was admitted `redacted: true`; F2 `read` and `deliver` trusting the
  mutable pair-root `redaction.json` after release (edit to mode none or delete it: exit 0, coverage and
  unresolved flags gone); F3 the inspector printing a canary in an allowed scalar or a map key and
  opening `pair.json -> bait.json` through a symlink; F4 a literal marker in an unflagged `CLAUDE.md`
  admitted unchanged, gate PASS and rule 10 CLEAR, while the reviewer prompt says every marker is
  host-written. Plus her residual r1: `inspect <bare id>` returned an all-missing view with exit 0.
- Change: F1 `scan_needles` captures every detected VALUE (assignment value, connection-string user and
  password, email and its local part, home-path user, every vendor / generic / phone / IP match) apart
  from the replacement spans; `redact_text` falls back `redaction_residual` when any needle, merged-span
  text or whole-line body survives in the derivative, and preflight when one is part of an admitted
  path. F2 release commits the record's bytes into the generation (`gen/<id>/redaction.json`, 0400) and
  binds `redaction_evidence` (record sha256, bytes, mode, and per redacted file the original and
  derivative digests) in `release.json`; `read` and `deliver` verify the committed copy, the manifest
  binding and the pair-root record and refuse with a named reason (`redaction_record_changed`,
  `redaction_record_deleted`, `redaction_evidence_changed`, `redaction_evidence_mismatch`,
  `redaction_evidence_unbound`); release refuses a symlinked or hard-linked record. F3 `inspect` prints
  closed typed slots (field grammars plus rule 5's decoded secret screen, the link screen and canary /
  box-dummy shapes), map keys from fixed per-record sets, and a per-record `screened` count; records are
  read through `_read_regular` (lstat regular, one link, O_NOFOLLOW, same inode), family dirs must be
  real directories, and `release.json` is followed only as `release.json -> current/release.json ->
  gen/<32 hex>/release.json`. F4 any admitted original whose bytes or path carry a marker prefix (any
  case, either mode, clean or exception-matched) is excluded `marker_reserved` (plus
  `redaction_fallback: marker_collision` under `--redact-prose`); rule 10 FAILs
  `redaction_marker_unexplained`; `reviewer-system.md` says a marker is never the repository's. F5
  `deep-review.sh inspect|redactions <pair_id>` resolves `$DEEP_HOME/pairs/<id>`, else exit 3; the
  python side exits 3 on a directory that is not a pair.
- Unchanged: the detectors (phone-before-period, hostnames and percent-encoding stay documented gaps,
  DISCLOSURE.md section 7), rules 0 to 9, bait, canary, allowlists, proxy, images, schema.
- Effect on earlier results: none; nothing relabeled, rerun or re-released. Default-mode preflight now
  also withholds a file that already carries a marker prefix; no recorded pair is re-preflighted. A
  C9-released generation that used `--redact-prose` binds no evidence and is refused by C10 `read` and
  `deliver` (`redaction_evidence_unbound`); C9's redacted-prose mode was held for review before any
  third-party use, so none is expected (not checked on disk: the house pairs directory was not opened).
  Mode-none generations read as before.
