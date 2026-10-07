# Deep review: what is disclosed, to whom, and what the detectors cannot see

This is the disclosure scope of `deep-review.sh pair`. It says what data leaves the host, which
provider receives it, what never leaves, and how each claim is tested. Read it before you run a
pair on someone else's code, and tell the owner what it says.

## 1. The owner-authorised data scope

- **What is reviewed.** One working-tree snapshot (a tarball or a directory), pinned by sha256
  and commit, minus whatever the privacy preflight withholds (section 3). Nothing else from the
  host is mounted into any box.
- **Who must agree.** The repository owner, for each provider that will receive the code. A pair
  always uses TWO providers: each family reviews the code, and each report is audited by the
  *other* family. So the default two-family pair sends repo content to both providers, and
  repo-derived report text to both (section 2). A single-family pair (`--families claude`)
  sends repo content to one provider only, but its report still goes to the OTHER provider's
  auditor, and release requires that audit. So an owner who agrees to one provider only must
  either also agree to the other provider seeing the gated report (paths, line numbers and the
  reviewer's own words: no verbatim run of 48+ chars of repo text and no scanner-shaped secret,
  but paraphrase of the code is its whole content), or accept that the pair
  cannot release.
- **Git history is neither mounted nor claimed.** VCS directories (`.git`, `.hg`, `.svn`) are
  dropped at stage time for a directory source and excluded by the preflight for a tarball. Every
  manifest records `git_history: {mounted: false, claimed: false}`. Every reviewer prompt says
  the box holds no history. The owner deliverable lists history under "not covered". A
  history sweep needs a full clone, which this pipeline does not do.
- **Nothing is executed.** No repo code runs, and no install or build steps run, in any box or
  on the host.

## 2. What leaves the host, and to whom

| Channel | Destination (via the per-run credential proxy: one host, port 443, verified TLS, contract routes only) | Content |
|---|---|---|
| Claude reviewer | the Anthropic API (`allowlist.txt`; `POST /v1/messages` and `POST /v1/messages/count_tokens` only: the second carries the same content to count its tokens, and is called by Claude Code during a real review) | the fixed system prompt (`reviewer-system.md`); the task message (host-computed file list, run echo, required-reading plan); **every repo file the reviewer reads with Read/Grep**; host repair messages (paths + line ranges only); the model's own output |
| Codex reviewer | the ChatGPT backend (`allowlist-codex.txt`; `POST /backend-api/codex/responses`, `GET /backend-api/codex/models` only) | the same system text and task message; **the output of every shell command it runs over `/repo`** (file contents); host repair messages; its own output |
| Codex auditor of the Claude report | the ChatGPT backend | `auditor-deep.md` + host-computed gate facts + the host file list + **the Claude report exactly as gated** |
| Claude auditor of the Codex report | the Anthropic API | the same, with the Codex report |
| Everything else | nothing | the gate, release, receipts and deliverable run on the host; no telemetry (`DISABLE_TELEMETRY`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, codex `analytics.enabled=false`, plugins/apps/browser/web search disabled) |

- Planted bait (fake credentials and a canary instruction file) also reaches the reviewers'
  providers. The values are random and fake.
- The auditor input is exactly the gated report plus the fixed auditor prompt. Nothing from
  `raw/` reaches it: no reviewer stream, no tool output, no reasoning (tested, section 5).
  The auditor box mounts no repo, and the session driver refuses an auditor spec that does.
- The model requests carry the operator's real credential, set by the proxy: the provider sees an
  authenticated request from the operator's account, as it would from the CLI on the host.
- What the providers do with what they receive (retention, training, abuse review) is governed
  by each provider's terms for the account in use. Nothing here controls it.

## 3. What never leaves the host

- **Files the preflight withholds**: symlinks, special files, files over 512 KiB, binaries,
  non-UTF-8 files, control-character-heavy files, VCS metadata, and every file whose content or
  name the scanner flags. The only way back in is an exception declared by the owner (path glob +
  kind), and type exclusions can never be excepted. Since C9, a run started with `--redact-prose`
  admits a flagged `agent_prose` file as a redacted derivative instead (section 7); the original
  still never leaves the host.
- **The staged source** (`src/`) stays host-side. Only `box/repo` (the admitted copy, content
  only, no modes, links or xattrs) is mounted into the Claude box. The Codex box reads a volume
  filled from that same copy and hash-verified against the manifest before and after the run.
- **Sealed output** (`raw/`: reviewer streams, tool output, the raw report) never unseals.
- **Every real credential.** No box holds one (C3, CONTAINMENT.md): each box gets a fresh dummy of
  the right shape, and the real credential exists only in the credential proxy, which sets it on the
  routed requests after stripping whatever auth the box sent. No host HOME, SSH agent, Docker socket
  or keychain is reachable from a box.

## 4. Scanner limits (copied from `DETECTOR_LIMITS` in `deeplib.py`; every manifest carries them)

Detects:
- private key blocks (PEM / OpenSSH / PGP)
- provider-shaped tokens: AWS AKIA/ASIA, GitHub ghp_/gho_/ghu_/ghs_/ghr_/github_pat_, Anthropic sk-ant-, OpenAI sk-/sk-proj-, Slack xox?-, Google AIza, Stripe live keys, npm_, Hugging Face hf_, JWTs
- secret-named assignments (key/secret/token/password = value) with a non-placeholder value
- URLs with embedded user:password
- high-entropy strings >= 32 chars in base64/base62 alphabets (entropy >= 4.5 bits/char)
- email addresses (placeholder and noreply domains ignored)
- phone numbers (NANP 3-3-4 with separators, +E.164 10-14 digits)
- host-identifying config: home-directory paths with a user name, RFC1918 / CGNAT IPv4
- credential-shaped file names (.env*, id_*, *.pem, *.key, .netrc, credentials*, ...)
- transcript / memory-dump shaped files (*.jsonl, chat-role JSON lines, names like transcript / conversation / memory-dump)

Cannot detect:
- low-entropy or dictionary passwords not assigned to a secret-named key
- unnamed random tokens shorter than 32 chars or using fewer than 3 character classes
- unnamed tokens starting with '/' that contain 2+ '/' and read as paths (entropy < 4.6)
- hex-only secrets (max 4.0 bits/char, below the entropy threshold) unless provider-shaped
- secrets split across lines, encoded (base64 of a key, rot13), or built at runtime
- personal data in free prose: names, street addresses, health or family details
- anything in git history (the snapshot has none)
- files excluded for type/size are not scanned at all; they are excluded, not cleared

Stance: fail closed. Unscannable files are excluded with a reason, and a scanner crash stops
the run. A file that passes is not proven free of private material.

## 5. How the claims are tested

| Claim | Test |
|---|---|
| An excluded file is unreachable through a symlink, a directory symlink, a hard link, a renamed copy of its content, or `.git`, for a directory source and a tarball | `deep-review.sh disclosurecheck`: no model call. The fixture plants all five routes. Both box images list and grep `/repo` from inside the box (the Claude bind mount and the Codex volume); a positive-control grep for admitted text must hit in the same box; the excluded values must be absent from every file of the pair except the host-side `src/`, including prompts, schemas, reading plans, manifest, preflight record, listings and their stderr logs. Unit twin: `test_p2.Disclosure.test_excluded_file_unreachable_by_every_alternate_route` |
| Auditor input = gated report + fixed prompt, nothing from `raw/` | `test_p2.Disclosure.test_auditor_input_is_exactly_the_gated_report_and_the_fixed_prompt`: a sentinel planted in the reviewer's tool output and stream is absent; the prompt equals `build_prompt(gated report, gate, file list)` byte for byte; the embedded report hashes to `gated_raw_sha256` |
| No attachments or extra mounts | `deepsession.validate_spec` refuses `-i/--image`, `--file`, `--add-dir` other than `/repo`, MCP and plugin flags, extra `-v` mounts, a writable `/repo`, a repo mount on an auditor, and a credential in the container env (`test_p2.Disclosure.test_session_specs_refuse_attachments_mounts_and_bypasses`) |
| History not mounted or claimed | the manifest's `git_history` block, the prompt line, `disclosurecheck` |

## 6. Detector bounds and residual risk in the report gate

The gate (`deepgate.py`) is mechanical, and its detectors have bounds. Each one below has a test
that pins it (`test_p2.DetectorBounds`):

- **Verbatim**: a 48-char window after casefold and whitespace collapse. A 47-char quote passes
  (`test_the_verbatim_window_is_48_chars_47_passes`), so short quotes, single code lines under
  48 chars, and identifiers are not caught.
- **Paraphrase** is not detectable mechanically (`test_paraphrase_passes`). A reviewer can carry
  a close paraphrase of repo prose, including injected instructions, into its report.
- **Encodings**: base64/base64url runs of 24+ chars and hex runs of 32+ digits are decoded when
  the result is printable text, and the decoded text meets the verbatim and secret checks too
  (`test_base64_and_hex_encoded_quotes_fail`, `test_base64_and_hex_encoded_secrets_fail`).
  Not decoded: rot13, reversed or interleaved text, one word per field, text split across
  fields or findings, other bases, compression, translation.
- **Secrets** in the report are found only by the same scanner as the preflight (section 4
  limits), plus exact bait values, the canary, and the box credential shapes.
  Since C8, in a structural position (a coverage key, or a `path` field outside the run echo) whose
  exact string rule 2 validated against the manifest, the generic token-shape heuristic alone is set
  aside and listed (`structural_generic_suppressed`). So a generic-looking secret that IS a repo file
  name passes rule 5 there; it is the owner's own name, and the deliverable lists it as a
  `token_shaped_name` naming warning. Concrete vendor shapes, decoded views, box credential shapes,
  bait and canaries still fail it (`tests/test_p7.py`).
- **Instruction screen**: a fixed phrase list that FLAGs and never FAILs. A paraphrased
  injection is CLEAR (`test_paraphrased_injection_is_not_flagged_residual`). The cross-family
  model audit is the control there, and an audit verdict is evidence, never authority.
- **Public records** (gate record, box checks, audit concern lines) are sanitized and bounded
  (CONTAINMENT.md section 5). They carry verdicts, counts, manifest paths and JSON paths over
  known schema keys only.

Last control: after a release, a person (or a reading agent under its own rules) reads the code
itself. No report is trustworthy alone.

## 7. Redacted-prose mode (C9, opt-in)

`deep-review.sh pair ... --redact-prose` (recorded as `redaction.mode` in `preflight.json`,
`manifest.json` and `release.json`; `none` when the flag is not used). It exists because whole-file
exclusion hid the prose an agent reader would obey (rules files, CLAUDE.md) from both reviewers.

- **Scope.** Only files of depth class `agent_prose` that the content scan would exclude as
  `private_info`, with no exception entry matching them and no flagged file name. Code, config,
  docs and everything else keep whole-file exclusion.
- **Local, before any model.** The host replaces each detector span in place with
  `[REDACTED:<kind>#<n>]` and each line-only hit (transcript-shaped lines, the lines of a private key
  block) with `[REDACTED-LINE:<kind>]`. Line count and line numbers are the original's. The box gets
  the derivative only; the original stays in the host-side `src/`. `redaction.json` binds each file's
  original and derivative digests, transformation `redact/1`, line count and its spans (line, kind,
  marker). The original digest is integrity metadata, never permission to read the original.
- **What the providers see.** The derivative, like any admitted file: the remaining text, and the
  kind and line of every withheld span (the markers). Not the withheld text.
- **Coverage wording.** For these files the review "read the redacted derivative"; the deliverable
  says so and gives the withheld-span count per file. Gate rule 10 lists every finding, private-info
  flag and instruction-shaped entry whose `path:line` lands on a marker line; the deliverable marks
  those entries unresolved, and `deep-review.sh read` names them. `deep-review.sh redactions <pair>`
  is the owner's review list (path, line, kind, marker; never a value).
- **Whole-file exclusion stays the fallback**, with the reason recorded (`redaction_fallback` in
  `preflight.json`, `fallbacks` in `redaction.json`): `redaction_density` (more than 10% of lines are
  whole-line markers, or more than 50 markers), `redaction_residual` (the derivative still hits the
  full detector set: the scanner, the gate's base64/hex decoded views and the box credential shapes;
  or a withheld value survives elsewhere in the derivative or inside an admitted file path),
  `marker_collision` (the original already contains a marker prefix), `unscannable` (a line over
  20000 chars, an unterminated private key block, a line separator other than `\n` / `\r\n`, or any
  fault while redacting).
- **C10: needles are values, not spans.** A marker may replace more than the value (a whole
  `name = value` assignment, two overlapping detector spans merged into one, a whole line). The
  residual check therefore uses every captured VALUE as a needle, apart from the replacement spans:
  the assignment's value, a connection string's user and password, an email and its local part, a
  home path's user name, every vendor / generic / phone / IP match, every merged span and every
  whole-line body. Any needle found anywhere in the derivative or inside any admitted path is
  `redaction_residual`. Needles exist in memory only and never reach a record. Short needles (a
  two-letter user name) make the fallback likely; that is the intended direction. Not covered: a
  needle repeated in ANOTHER admitted file's text (that file is admitted or excluded by its own scan,
  in every mode, as before C9).
- **C10: the marker namespace is the host's.** Any admitted original (clean, exception-matched,
  in either mode) whose bytes or path contain a marker prefix, any case, is withheld whole with
  reason `marker_reserved` (and `redaction_fallback: marker_collision` under `--redact-prose`). Gate
  rule 10 FAILs on a marker prefix the redaction record does not explain
  (`redaction_marker_unexplained`), so every marker a reviewer meets is one this transformation wrote,
  as the reviewer prompt now says.
- **C10: the evidence is bound at consumption.** Release commits the redaction record's bytes INTO
  the released generation (`gen/<id>/redaction.json`, 0400) and binds its sha256 and each redacted
  file's original and derivative digests in `release.json` (`redaction_evidence`). `read` and `deliver`
  use that copy and refuse (non-zero, named reason) when it does not hash to its binding, when the
  manifest binds another record, when the pair's own `redaction.json` was edited or deleted after
  release, or when a generation binds no evidence while anything says redacted. A mode-none pair, and
  any older generation without the field, reads as before as long as nothing says redacted.
- **Rule 10 is positional, not semantic.** It lists entries whose `path:line` lands exactly on a
  marker line. A line-0 or file-level claim, a conclusion drawn on a nearby line, a summary sentence
  or an argument across lines can still rest on withheld text and is not flagged. `CLEAR` means no
  entry sits on a marker line; it is not proof that no conclusion depends on withheld text. That
  needs an explicit completeness read by the sisters before delivery.
- **The host holds no owner values.** The residual checks know only what the detectors matched. A
  value the detectors miss (section 4 "Cannot detect") is neither redacted nor excluded and reaches
  the reviewers inside the derivative, exactly as it would in any admitted file. Value-aware checking
  against the owner's real secrets is the owner's boundary: they review the `redactions` list, and the
  derivative if they wish, before anything is delivered.
- **Encoded values: the gap is unchanged.** A percent-encoded value (`%40` for `@`, `%2F` for `/`)
  is not decoded by the preflight scanner, so it is not detected and not redacted
  (`tests/test_p8.py`, `test_percent_encoded_value_is_the_documented_gap`). The rescan decodes base64
  and hex runs only. Also observed while building C9 and unchanged by it: a phone number directly
  followed by a period is not matched by the phone detector, so it is neither excluded nor redacted.
  This gap is inherited from C8 (independently reproduced by Serafina); closing it changes which files
  are excluded and is left for a C11 decision. Hostnames are not a preflight detector at all (the
  report gate's link rule sees them; the preflight does not), so a hostname in prose is neither
  excluded nor redacted. C10 changes none of these detectors.
- **Markers do not sanitize instruction authority.** Redaction removes values, not intent: what
  remains of a redacted agent file is still untrusted prose that may address the reviewer, and the
  reviewer prompt treats it as data like every repo file. A marker is host text, not repository text
  and not an instruction; a conclusion resting on one is `inferred`, never `observed`.
