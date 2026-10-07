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
