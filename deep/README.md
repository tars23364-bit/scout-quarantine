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

## Layers and what each one stops

| Layer | Mechanism | Proven by |
|---|---|---|
| Network | reviewers only on a `--internal` network; the proxy is the one dual-homed container | `netcheck`: direct TCP and DNS fail; CONNECT to non-allowlisted hosts, lookalikes, port 80 and plain HTTP all 403 and logged |
| Egress allowlist | squid `dstdomain` exact match + port 443 + CONNECT only; one allowlist per family | `egress_allowlisted_only` on every run and every audit |
| Filesystem | read-only root, `/repo` read-only, tmpfs HOME/work/tmp/out, no other host mount, uid 10001, cap-drop ALL, no-new-privileges | `boxcheck` |
| Claude tools | `--tools Read,Glob,Grep`, `--restricted`, `--permission-prompts none`, `dontAsk`, settings deny | `toolcheck` |
| Codex shell | codex's own sandbox, read-only (legacy landlock + seccomp: bubblewrap needs user namespaces the box does not grant): no network, no writes, for every command | `codexcheck`: a raw socket from the shell to the proxy's IP gets EPERM, writes to /out, /work and /repo are denied, /repo reads |
| Codex features | `--disable` for apps, browser use (+ CDP), in-app browser, image generation, computer use, plugins, remote plugins, plugin sharing, MCP dependency install, hooks, multi-agent; `web_search="disabled"`; `analytics.enabled=false`; all gated on the build's own `features list` | proxy log of every codex run holds only the allowlisted host |
| Codex credential | the box gets an in-memory auth file with the access token and an EMPTY refresh token; the auth host is not allowlisted | `CodexBoxAuth` tests; host `auth.json` untouched by every run |
| No house context | Claude: `--safe-mode`, `--strict-mcp-config`, cwd `/work`. Codex: `--ignore-user-config`, `--ignore-rules`, empty config, cwd `/work`, fresh tmpfs CODEX_HOME | `memcheck` (Claude) |
| Privacy preflight | host-side scan; flagged and unscannable files never enter the box; re-entry only via a declared path glob + kind | `deeplib.py selftest` + tests |
| Obedience | random canary instruction file + random fake credentials | `canary_absent`, `bait_values_absent`, gate rule 5 |
| Report boundary | mechanical gate, then a cross-family model audit, then all-or-nothing release | `tests/test_deepgate.py` |

## Use

```bash
deep/deep-review.sh build
deep/deep-review.sh netcheck && deep/deep-review.sh boxcheck       # no model call
export CLAUDE_CODE_OAUTH_TOKEN=...      # Claude box + Claude auditor; passed by NAME only
codex login                             # on the host; the Codex box gets a non-refreshable copy in memory
deep/deep-review.sh toolcheck && deep/deep-review.sh memcheck      # Claude box probes
deep/deep-review.sh codexcheck                                     # Codex box probe
deep/deep-review.sh pair repo.tar.gz --label name --commit <sha>   # both boxes, gate, audit, release
deep/deep-review.sh deliver "$DEEP_HOME/pairs/<id>"                # owner document, after RELEASED
```

`pair` exits 0 when both reports are RELEASED, 4 when they stay SEALED. Before release the only
readable records are `<family>/box-checks.json`, `<family>/gate.json` (verdicts, counts, JSON paths
and manifest paths: never report text) and `<family>/audit.json` (result + at most three screened
concern lines). After release, `<family>/report/report.json` is the bait-stripped report. `raw/`
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
- The Codex box's access token is a bearer for the whole ChatGPT backend host, and its shell can
  read it (codex's read-only sandbox reads everything in the box). The shell has no network, the
  gate refuses token-shaped strings in a report, and a token seen in tool output fails the box
  checks; the model itself can still put it in its own API request (to its own issuer).
- Tokens are visible to the Docker daemon (`docker inspect` while a box runs).
- The seal is a gate, not a vault: the same user can chmod it back.
