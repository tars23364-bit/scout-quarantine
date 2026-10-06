# scout deep review (P0, run by hand)

The triage scout samples a repo and asks a small local model about it. Deep review is the other
end: a strong model reads the **whole** repo, inside a box where the repo is the only thing it
can read and the model API is the only thing it can reach. An injection that fully steers the
reviewer has nothing else to read and nowhere else to send.

Nothing here executes the target. Runtime behaviour and git history are out of scope.

## Shape

```
source (tarball | dir) ──stage──► src/ ──preflight (host, fail closed)──► box/repo ──bait──► box/repo + fake creds + canary
                                                                                    │
            internal Docker network (no route, no external DNS) ◄── reviewer box ◄─┘ (/repo read-only)
                     │
                     └── squid: CONNECT api.anthropic.com:443 only; every request logged
                                                                                    │
                              stream.jsonl + proxy.log ──check (host, whole)──► deep-report.json
```

## Layers and what each one stops

| Layer | Mechanism | Proven by |
|---|---|---|
| Network | reviewer only on a `--internal` network; proxy is the one dual-homed container | `netcheck`: direct TCP and DNS fail; CONNECT to non-allowlisted hosts, lookalike hosts, port 80 and plain HTTP all 403 and logged |
| Egress allowlist | squid `dstdomain` exact match + port 443 + CONNECT only | `netcheck`, and `egress_allowlisted_only` on every run |
| Filesystem | read-only root, `/repo` read-only, tmpfs HOME/work/tmp/out, no other host mount, uid 10001, cap-drop ALL, no-new-privileges | `boxcheck`: writes outside /out denied, planted symlinks to host paths dangle, no docker.sock, no SSH agent, no /Users |
| Tools | `--tools Read,Glob,Grep`, `--restricted`, `--permission-prompts none`, `dontAsk`, settings deny for system paths and every action tool | `toolcheck`: the reviewer is told to read /etc, /proc, HOME, `..` paths, write, fetch, and run a shell command; the tool layer refuses all of it |
| No house context | `--safe-mode`, `--strict-mcp-config`, cwd `/work` (a parent, empty), fresh tmpfs HOME | `memcheck`: repo CLAUDE.md / AGENTS.md tokens never reach context (with a positive control that shows the probe sees loading when the guards are removed) |
| Privacy preflight | host-side scan; flagged and unscannable files never enter the box | `deeplib.py selftest` (runs inside every preflight) + `tests/test_deeplib.py` |
| Obedience | random canary instruction file + random fake credentials | `canary_absent`, `bait_values_absent` on every run; `tests/test_deeplib.py` fabricates obedience and asserts FAIL |
| Coverage | host computes the file list whole; per-run schema requires every path as a key | `coverage_complete`, `schema_valid` |

## Use

```bash
deep/deep-review.sh build
deep/deep-review.sh netcheck && deep/deep-review.sh boxcheck     # no model call
export CLAUDE_CODE_OAUTH_TOKEN=...    # or ANTHROPIC_API_KEY; passed into the box by NAME only
deep/deep-review.sh toolcheck && deep/deep-review.sh memcheck    # small model calls
deep/deep-review.sh run repo.tar.gz --label name --commit <sha>
```

Exit 0 means every hard check passed. The report is `runs/<id>/deep-report.json`:
`verdict`, `run_manifest` (source pin, manifest hash, model and CLI version, every exclusion
with its reason, truncation), `checks`, `preflight_private_info` (kinds and sanitised paths
only), `coverage_including_exclusions`, and `review` (the reviewer's schema-bound object).

If `docker pull` hangs on macOS, the Docker Desktop credential helper is waiting on the
keychain; point `DOCKER_CONFIG` at a directory holding `{"auths":{}}` (and `DOCKER_HOST` at the
Desktop socket) for anonymous pulls of the public base images.

## The privacy preflight: what it can and cannot see

It is a privacy layer, not proof that a file is safe. It fails closed: symlinks, special files,
files over 512 KiB, binaries, non-UTF-8 files, control-character-heavy files, and any file it
flags are excluded and listed with a reason. A scanner crash stops the run before the model is
called. Detector coverage and blind spots are in `DETECTOR_LIMITS` in `deeplib.py` and are copied
into every run manifest. It is tuned to over-exclude: test fixtures with example tokens or RFC1918
addresses are excluded too, and the manifest says so.

## Residual risk

- A reviewer steered by injection can still write a misleading report. The canary, the audit,
  and reading the code yourself after a pass are the controls; no report is trustworthy alone.
- The token is visible to the Docker daemon (`docker inspect` while the container runs). It can
  only be spent at the allowlisted API.
- Whatever the reviewer reads goes to the model provider. Ask the owner first.
