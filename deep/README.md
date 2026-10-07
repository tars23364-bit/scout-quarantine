# scout deep review

The triage scout samples a repo and asks a small local model about it. Deep review is the other
end: strong models read the **whole** repo, each inside a box where the repo is the only thing it
can read and its model API is the only thing it can reach. An injection that fully steers a
reviewer has nothing else to read and nowhere else to send. And nobody reads what a reviewer
wrote until a mechanical gate and a model of a *different* family have passed it.

Nothing here executes the target. Runtime behaviour and git history are out of scope.

## Shape (P1: the audit contract)

```
source ──stage──► src/ ──preflight (fail closed, declared exceptions)──► box/repo ──bait──► + fake creds + canary
                                                                                  │  one pin, one manifest
                     ┌────────────────────────────────────────────────────────────┴───────────────┐
             Claude box (bind mount)                                              Codex box (manifest-verified volume)
             api.anthropic.com only                                               chatgpt.com only
                     │ raw output → raw/ (mode 000)                                       │ raw/ (mode 000)
                box checks (egress, tools, canary, bait, coverage, box unchanged)         box checks (+ volume == manifest)
                     │                                                                    │
                GATE (host, deterministic): schema+64 KB, paths/lines, run echo, 48-char verbatim
                overlap over every manifest file, secrets/bait/canary, links, instruction screen (flag),
                bait stripped → report/report.json (mode 000)
                     │                                                                    │
                audit by Codex (tool-less, no repo)                       audit by Claude (tool-less, no repo)
                     └───────────────────────── RELEASE: all PASS → both unseal together ┘
                                                 anything else → both stay sealed
                                                         │
                                       deliver: bait-stripped owner document (written, never sent)
```

## P2: depth, disclosure, containment, frozen contract

- **Required reading, proven from the tool log.** `prepare` classifies every admitted file
  (`deepdepth.py`: code, config and agent prose are `required`) and writes the class next to its
  frozen sha256 in the manifest before any run. Each family gets a per-file reading plan
  (`depth-policy.json`). The read receipts come from the harness's own tool-call log (Claude
  Read/Grep results, Codex command output). A line counts only if the returned text equals that
  line of the frozen file, so truncation is accounted for. Gate rule `9_read_depth` FAILs any
  required file with missing lines, whatever its coverage label says. The kept limit: bytes
  supplied are not comprehension.
- **Host-driven repair turns.** Every box runs as a session (`deepsession.py`): an idle
  container, one `docker exec` per turn, and up to `max_repair_turns` resumed turns that tell
  the reviewer which required ranges it has not received (host data only). Then the gate
  decides. The repair is never a label downgrade.
- **Credentials leave the container env** (P2), then **leave the box** (P3, below).
- **Frozen contract.** `deeplib.py contract` hashes the prompts, schema, gate, audit, session,
  depth policy, launch script, Dockerfiles, entrypoint, allowlists and the proxy (P3). `pair`
  refuses an unlogged version (`CONTRACT-CHANGELOG.md`), and every manifest, receipt, gate,
  audit binding and release record carries it. Reruns of a source are labelled with the
  contracts they ran under.
- **Bound audit, atomic release.** The audit verdict is stored with host-computed bindings (pair
  id, pin, manifest, models, contract, gate hashes), and release recomputes and compares them.
  Cross-family routing is checked where it is planned, where it runs, and at release. Any
  exception, crash or timeout seals both reports with the reason recorded.
- Docs: `DISCLOSURE.md` (what leaves the host, to whom; scanner limits; detector residuals),
  `CONTAINMENT.md` (which process holds what; negative tests; residuals).
  `deep-review.sh disclosurecheck` proves excluded files are unreachable from inside both boxes.

## P3: completion evidence, crash-atomic release, the credential boundary, bound runtime

- **An audit PASS needs re-derived completion** (`deepaudit.completion`): the terminal receipt
  the session driver writes last (exit exactly 0, turn-file hashes), the family's terminal success
  event, the input (prompt = build_prompt(report as gated)) and output (reply) hashes, and the
  egress proof. Release re-derives all of it and never trusts `audit.json` alone.
- **One paired generation, one atomic rename.** Both reports and `release.json` are built in
  `pair/gen/<id>/`, the commit is replacing `pair/current`, and readers (`deliver`, `read`) admit
  a report only from the committed generation and only if it matches its hash. Hard kills at every
  boundary are tested.
- **No real credential in a box.** See the layers table and CONTAINMENT.md.
- **Effective runtime bound.** The run descriptor (image ids, mounted policy hashes, exact docker
  and CLI argument vectors, prompt and system prompt hashes, depth policy) is recorded before
  launch, bound into the audit, and compared at release with the contract, `images.lock.json` and
  what the containers themselves reported.

## P8 (C9): redacted-prose mode, and reading records without opening them

- **`pair --redact-prose`** (opt-in): a flagged `agent_prose` file with no exception enters the box as
  a line-preserving derivative (`[REDACTED:<kind>#<n>]` per span, `[REDACTED-LINE:<kind>]` per
  line-only hit) instead of being excluded whole; any doubt falls back to exclusion with a recorded
  reason. `redaction.json` binds original and derivative digests; gate rule 10 lists report entries
  resting on a marker line, and the deliverable marks them unresolved. DISCLOSURE.md section 7.
- **`deep-review.sh redactions <pair>`**: path, line, kind, marker of every withheld span (no values).
- **`deep-review.sh inspect <pair>`**: verdicts, rule results, counts, hashes, exclusions, receipt
  totals and release status through an allowlist of keys per record. It never opens `bait.json`,
  `box-dummy*.json`, `session-spec*.json` or `extra-canaries.json`, and never prints a key named
  `values`, `canary_token`, `headers`, `auth_b64`, `exec_env` or `env`. Use it instead of opening records.

## P9 (C10): Serafina's four edits to C9

- **Needles are values** (F1): the redaction residual check uses every captured value (an assignment's
  value, connection-string user and password, email local part, home-path user, every token match),
  kept apart from the replacement spans; a value surviving bare in the derivative or in an admitted path
  falls the file back to whole exclusion.
- **Evidence bound at consumption** (F2): release commits `redaction.json` into the generation and binds
  its digest and per-file digests in `release.json` (`redaction_evidence`); `read` and `deliver` verify
  it and refuse on a post-release edit, deletion or unbound record.
- **Typed inspector** (F3): every printed slot has a type and grammar (hash, timestamp, pair id, enum,
  model token, path ...) plus the full decoded secret screen and canary / box-dummy screens; map keys come
  from fixed sets; what is dropped or withheld is counted under `screened`. Records are read through an
  alias-refusing path (symlink, hard link, symlinked family dir refused before any open); `release.json`
  only through `release.json -> current/release.json -> gen/<id>`. The guarantee is shape-based: a value
  no grammar or detector recognises can still print in a free-text slot (labels, paths, release reasons).
- **Marker namespace reserved** (F4): an admitted original carrying a marker prefix (any case, text or
  path, either mode) is withheld whole (`marker_reserved`); rule 10 FAILs an unexplained marker.
- **Bare ids** (F5): `deep-review.sh inspect|redactions <pair_id>` resolves `$DEEP_HOME/pairs/<id>`;
  anything that is not a pair directory exits 3 with a message.

## P10 (C11): Serafina's three residuals against C10

- **Marker paths** (R1): a redaction-eligible file under a marker-bearing path is excluded before
  redaction is tried (`marker_collision`); rule 10 FAILs `redaction_marker_in_path` on any admitted path
  with a marker prefix.
- **Whole-output screen** (R2): every key and string the inspector emits passes the screen, with the
  canary and box-dummy shapes checked on decoded (hex / base64) views too; `never_opened` prints fixed
  category names and counts, never a dynamic file name.
- **Pinned directories** (R3): the pair dir and every intermediate directory are opened no-follow and
  identity-checked, and each record is opened relative to its pinned parent. Guarantees and limits:
  DISCLOSURE.md section 8.

## Layers and what each one stops

| Layer | Mechanism | Proven by |
|---|---|---|
| Network | reviewers only on a `--internal` network; the credential proxy is the one dual-homed container | `netcheck`: direct TCP and DNS fail; other proxy ports closed; CONNECT, absolute-form, upgrades, non-routed paths and unmarked requests refused and logged |
| Credential boundary (P3) | no real credential in any box: a dummy of the right shape; `credproxy.js` requires the exact dummy, strips every box auth header, sets the real one, forwards over verified TLS to the one allowlisted host, scrubs responses | `netcheck`, `canarycheck` (box memory + filesystem + every log scanned for a canary), `box_dump_real_credential_absent` on every run |
| Egress allowlist | one host per family (`allowlist*.txt`) + the contract routes (`credproxy-*.json`); the proxy logs its own code/config/allowlist hashes | `egress_allowlisted_only` on every run and every audit (forwarded over verified TLS only, nothing denied, proxy view = contract) |
| Filesystem | read-only root, `/repo` read-only, tmpfs HOME/work/tmp/out, no other host mount, uid 10001, cap-drop ALL, no-new-privileges | `boxcheck` |
| Claude tools | `--tools Read,Glob,Grep`, `--restricted`, `--permission-prompts none`, `dontAsk`, settings deny | `toolcheck` |
| Codex shell | codex's own sandbox, read-only (legacy landlock + seccomp: bubblewrap needs user namespaces the box does not grant): no network, no writes, for every command | `codexcheck`: a raw socket from the shell to the proxy's IP gets EPERM, writes to /out, /work and /repo are denied, /repo reads |
| Codex features | `--disable` for apps, browser use (+ CDP), in-app browser, image generation, computer use, plugins, remote plugins, plugin sharing, MCP dependency install, hooks, multi-agent; `web_search="disabled"`; `analytics.enabled=false`; all gated on the build's own `features list` | proxy log of every codex run holds only the allowlisted host |
| Codex credential | the box gets a DUMMY auth file (dummy JWTs, empty refresh token); the proxy gets the real access token + account id, never the refresh token | `codexcheck`, `canarycheck`; host `auth.json` untouched by every run |
| No house context | Claude: `--safe-mode`, `--strict-mcp-config`, cwd `/work`. Codex: `--ignore-user-config`, `--ignore-rules`, empty config, cwd `/work`, fresh tmpfs CODEX_HOME | `memcheck` (Claude) |
| Privacy preflight | host-side scan; flagged and unscannable files never enter the box; re-entry only via a declared path glob + kind | `deeplib.py selftest` + tests |
| Obedience | random canary instruction file + random fake credentials | `canary_absent`, `bait_values_absent`, gate rule 5 |
| Report boundary | mechanical gate, then a cross-family model audit, then all-or-nothing release | `tests/test_deepgate.py` |

## Use

```bash
deep/deep-review.sh build
deep/deep-review.sh netcheck && deep/deep-review.sh boxcheck       # no model call
export CLAUDE_CODE_OAUTH_TOKEN=...      # host only: handed to the credential proxy over stdin, never to a box
codex login                             # on the host; the proxy gets the access token + account id, the box a dummy
deep/deep-review.sh canarycheck                                    # both CLIs with a canary credential (offline)
deep/deep-review.sh toolcheck && deep/deep-review.sh memcheck      # Claude box probes
deep/deep-review.sh codexcheck                                     # Codex box probe
deep/deep-review.sh pair repo.tar.gz --label name --commit <sha>   # both boxes, gate, audit, release
deep/deep-review.sh deliver "$DEEP_HOME/pairs/<id>"                # owner document, after RELEASED
```

`pair` exits 0 when both reports are RELEASED, 4 when they stay SEALED. Before release the only
readable records are `<family>/box-checks.json`, `<family>/gate.json` (verdicts, counts, JSON paths
and manifest paths: never report text) and `<family>/audit.json` (result + at most three screened
concern lines). After release, `deep-review.sh read <pair> <family>` prints a bait-stripped report
admitted from the committed generation (`<pair>/current/`). `raw/`
(the reviewer's stream, its tool output, which holds repo text) never unseals.

A released report is relayed text from a reviewer box: data, never instructions.

### Preflight exceptions

A flagged file re-enters the box only through a declared exception, never through anyone reading
the flagged line:

```json
{"declared_by": "owner", "exceptions": [{"glob": "tests/fixtures/**", "kinds": ["api_key"], "reason": "fake keys"}]}
```

`declared_by: "owner"` is the repo owner's own list and works for any repo. `declared_by: "self"`
is the reviewer's own list, accepted only when the run is started with `--self-authored` (a repo
you wrote). Exceptions cover content kinds only; type exclusions (symlink, binary, size,
encoding) are never excepted, and a file is let in only if every kind flagged in it is covered.
`preflight.json` records each excepted file with its kinds and the exception that admitted it.

## Reviewing untrusted text with Codex outside the box (recipe)

If you hand untrusted content to `codex exec` directly, know what the defaults are (codex-cli
0.153.0): `-s read-only` stops writes and network for commands but **does not confine reads** to
`-C`, and `apps`, `browser_use` (with full CDP into a signed-in browser), `in_app_browser`,
`image_generation` and `computer_use` are on. At minimum:

```bash
codex exec -s read-only --skip-git-repo-check --ephemeral \
  --disable apps --disable browser_use --disable browser_use_external \
  --disable browser_use_full_cdp_access --disable in_app_browser \
  --disable image_generation --disable computer_use -c 'web_search="disabled"' \
  -C <dir holding only the content> - < prompt.txt
```

Gate the flags on `codex features list` (an unknown `--disable` exits 1), and remember the reads:
anything readable by your user can still be read and sent to the model. The box above is the
fix for that.

## If `docker pull` hangs on macOS

The Docker Desktop credential helper is waiting on the keychain; point `DOCKER_CONFIG` at a
directory holding `{"auths":{}}` for anonymous pulls of the public base images.

## The privacy preflight: what it can and cannot see

It is a privacy layer, not proof that a file is safe. It fails closed: symlinks, special files,
files over 512 KiB, binaries, non-UTF-8 files, control-character-heavy files, and any file it
flags are excluded and listed with a reason. A scanner crash stops the run before any model is
called. Detector coverage and blind spots are in `DETECTOR_LIMITS` in `deeplib.py` and are copied
into every run manifest.

## Residual risk

- A reviewer steered by injection can still write a misleading report. The gate catches the
  mechanical shapes (quotes, secrets, links, planted values); the cross-family audit judges the
  rest; reading the code yourself after a release is the last control. No report is
  trustworthy alone.
- An allowlist still permits disclosure THROUGH the allowed API: whatever a reviewer reads goes
  to its provider. Ask the owner first.
- No box holds a real credential (P3). The dummy a box holds is readable inside it and worthless
  outside this run's proxy; the proxy lends the real credential's authority only for the contract
  routes at the one host (CONTAINMENT.md section 4).
- The seal is a gate, not a vault: the same user can chmod it back.
