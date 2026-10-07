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
