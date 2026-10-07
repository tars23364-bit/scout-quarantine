# Deep review: actual containment

The short claim is "the reviewer can read only the repo and reach only its model API". This page
says which process holds what, what enforces each separation, and where the claim stops. Every
row names the probe that tests it.

## 1. Per family: who holds the credential, who can reach the proxy

| | Claude box | Codex box |
|---|---|---|
| Container main process | `sleep infinity` (holds nothing) | `scout-codex-entry idle` -> `sleep infinity` (holds nothing) |
| Credential | `CLAUDE_CODE_OAUTH_TOKEN`, passed by NAME to each `docker exec` of the `claude` CLI, never to the container env (`docker inspect` does not show it) | a non-refreshable auth file (access + id token, EMPTY refresh token), written over stdin by `scout-codex-entry put-auth` into the tmpfs `$CODEX_HOME/auth.json` (0600), never in any env var |
| Who holds it | the `claude` process, in its environment | the `codex` process reads the file; **the sandboxed shell can read it too** (section 3) |
| Who can reach the proxy | the `claude` process (node, via `HTTPS_PROXY`) | the `codex` process (via `HTTPS_PROXY`); **not** the shell: seccomp denies it a socket |
| Model-driven tool layer | Claude Code's own tools, restricted to `Read, Glob, Grep` (+ the `StructuredOutput` reply channel). No shell, no write, no fetch tool exists | codex's shell tool, every command run under codex's read-only sandbox (legacy landlock + seccomp) |
| What separates the tool layer from the credential and the network | Claude Code's permission layer **inside the same process**: `--restricted` confines file tools to `/work` + `/repo`, settings deny `/proc`, `/etc`, `/home`, `/sys`, `/root`, `/usr`, `/tmp`, and there is no tool that can open a socket | the kernel: seccomp makes `socket()` fail with EPERM for every shell command, and landlock denies every write. Reads are NOT confined (section 3) |
| Writable tmpfs HOME | written by the `claude` process itself (its session store, so a repair turn can `--resume`); the model has no write tool | written by the `codex` process itself (session files for `exec resume`, the auth file); shell commands cannot write it (landlock) |

### Reconciling "the shell has no network and no writes" with a networked client and a writable HOME

They are different processes with different enforcement. The CLI process (the model client) must
reach its API and keep a session, so it gets the proxy and a tmpfs HOME. The model never runs
code in that process. Anything the model asks to do runs through the tool layer. For Codex that
is a separate sandboxed child with no socket and no writes, enforced by the kernel. For Claude it
is a fixed set of read-only tools, enforced by Claude Code's permission checks. The only data path
from the model to the network is the CLI's own request to its own API, which is section 4.

## 2. Negative tests (all in `deep-review.sh`, results under `$DEEP_HOME/checks/`)

| Probe | What it attempts | Expected | Where proven |
|---|---|---|---|
| `netcheck` | from a box on the internal network: direct TCP, DNS, CONNECT to a non-allowlisted host, a lookalike host, port 80, plain HTTP; the Docker socket | all fail; squid logs `TCP_DENIED`; only the allowlisted host tunnels | `netcheck.txt`, `proxy.log` |
| `boxcheck` | writes everywhere but `/out`, symlinks to host paths, Docker socket, SSH agent, host `/Users`, capabilities | denied / dangling / absent; `CapEff` 0; `NoNewPrivs` 1 | `boxcheck.txt` |
| `toolcheck` (Claude, 2 turns, the second on `--resume`) | Read `/etc/passwd`, `/proc/self/status`, `/proc/self/environ` and `/proc/1/environ` (the token), `/home/reviewer/.claude/.credentials.json`, `.claude.json`; Glob `/`, `/home/reviewer`; Grep `/etc`, `/proc/self`; traversal; write; fetch the model API; run a shell | every outside attempt refused by the tool layer (`is_error`), in BOTH turns; no write, fetch or shell tool in any turn's init | `toolcheck.json` |
| `codexcheck` (Codex, 2 turns, the second on `exec resume`) | from the sandboxed shell: a raw socket to the proxy's IP; a CONNECT to the proxy by name; a fetch of the model API through the proxy env; writes to `/out`, `/work`, `/repo` and the tmpfs `$CODEX_HOME`; a read of the auth file (size only, never content) | `NET EPERM`; the by-name probes fail at resolution (`EAI_AGAIN`: the shell cannot open the DNS socket either); every write denied; `/repo` readable; **the auth file READABLE** (recorded as the residual, not passed off) | `codexcheck.json` |
| `memcheck` (+ positive control) | repo `CLAUDE.md` / `AGENTS.md` auto-loading into context | not loaded; the control (cwd `/repo`, safe mode off) does load | `memcheck.txt` |
| box checks on every run | the admitted credential (exact 32-char windows) in the report, the model's text, or tool output; credential-shaped strings (Anthropic `sk-ant-…`, JWT) in the report or the model's text | `admitted_credential_absent` and `credential_shapes_absent` PASS, else the box and the gate FAIL | `box-checks.json`; unit: `test_p2.Containment` with synthetic tokens of the admitted shapes |

## 3. Residual: the Codex shell can read its own credential

Codex 0.153.0's `read-only` sandbox confines writes and network for commands, not reads. It has
restricted-read "permission profiles", but they refuse to run under the legacy landlock backend
("permission profiles requiring direct runtime enforcement are incompatible with
--use-legacy-landlock"). The non-legacy backend is bubblewrap, which needs user namespaces that
the box's default seccomp profile denies. So a shell command can `cat` the auth file. It cannot
send it anywhere (no socket, no writes). It can only print it into the conversation, and from
there the model can put it in its own API request (section 4) or in its report. The report is
screened for credential shapes and the admitted credential's exact windows, and so are the
model's messages and reasoning. A hit fails the box. The token is short-lived (it expires on its
own) and cannot be refreshed from the box: the refresh token is empty and the auth host is not
allowlisted.

Closing this would need a custom seccomp profile allowing `unshare(CLONE_NEWUSER)` in the box, so
that codex's bubblewrap backend and restricted reads can run. That trades more kernel surface
inside the container for a credential the shell cannot read, and it is not done here.

For Claude, the separation between the model's tools and the token is Claude Code's own
permission layer in the same process, not an OS boundary. A bug in its path handling would let a
Read reach `/proc/self/environ`. `toolcheck` tests the paths a reviewer could use. It cannot
prove there are no others.

## 4. Residual: the allowlisted API is an outbound channel

Each box can reach exactly one host, and that host receives whatever the model is steered to
put in its requests: repo content (by design), and potentially the box's own credential or
anything else the model has seen in the box. The allowlist constrains WHERE data goes, not WHAT.
The controls are these: the box holds nothing else worth sending (no host files, no other
credential, nothing of the operator's); the only reachable host is the credential's own issuer;
and the owner agreed to that provider seeing the code. Codex's allowlisted host is its whole
backend, a broad API surface for its token. Only the codex process, never the model or the
shell, can make requests to it.

## 5. Public records cannot carry sealed text out

Before release, three records are readable. All are host-shaped by construction and re-checked:

- `gate.json`: `deepgate.sanitize_public` keeps a string only if it is a manifest path, a hash, a
  timestamp, a JSON path over known schema keys, a validator message over such a path, a fixed
  vocabulary token, or a host-written value (model name, pair id) of plain token shape. Anything
  else becomes `[withheld]` and is counted (`sanitizer_withheld`). Kept strings are bounded
  (300 chars) and screened by the report gate's secret and link rules. Model-written keys
  are never echoed: JSON paths show `[key]`, and unexpected `run{}` keys are counted, not
  named. A gate exception records only the exception's type.
- `box-checks.json`: verdicts and host-derived counts. The egress record names allowlisted
  hosts only and counts the rest, because a host a box asked for is chosen inside the box.
- `audit.json`: result, confidence, at most 3 concern lines of at most 300 chars each. Each
  line is withheld whole if it, or any base64/hex run decoded from it, carries a secret
  shape, a credential shape, a link or host name, or a 48-char window of repo text.

Tests: `test_p2.Sanitizer`, `test_p2.Containment.test_public_egress_record_never_names_a_non_allowlisted_host`.
