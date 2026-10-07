# Deep review: actual containment

The short claim is "the reviewer can read only the repo, reach only its model API, and holds no
real credential". This page says which process holds what, what enforces each separation, and
where the claim stops. Every row names the probe that tests it.

Contract C3 (P3, R3) moved the credential boundary out of the boxes. In C2 each box held its own
model credential and the Codex shell could read it. In C3 no real credential exists in any box.

## 1. Per family: who holds what

| | Claude box | Codex box | Credential proxy |
|---|---|---|---|
| Image / main process | `scout/deep-reviewer`, `sleep infinity` | `scout/deep-codex`, `scout-codex-entry idle` -> `sleep infinity` | `scout/deep-credproxy`, `node credproxy.js` (uid 10002) |
| Credential it holds | a **dummy** OAuth token of the real shape, fresh per box, set only on each `docker exec` of the `claude` CLI | a **dummy** ChatGPT auth file (dummy access/id JWTs, dummy account id, empty refresh token), fresh per box, written over stdin to the tmpfs `$CODEX_HOME/auth.json` | the **real** credential (Claude: the OAuth token; Codex: the access token + account id, never the refresh token), handed in over `docker exec -i ... put` stdin, written 0600 to its own tmpfs, read once into memory and the file unlinked |
| Networks | the run's `--internal` network only | the run's `--internal` network only | the internal network AND an egress network: the only dual-homed container |
| How its model client reaches the API | `ANTHROPIC_BASE_URL=http://egress-proxy:8080`, plain HTTP to the proxy; no forward-proxy variables exist in the box | a custom codex provider (`requires_openai_auth=true`, `supports_websockets=false`, `base_url=http://egress-proxy:8080/backend-api/codex`) plus `chatgpt_base_url` | TLS to the one host in its mounted allowlist (`api.anthropic.com` / `chatgpt.com`), port 443, certificate verification on (Node's bundled roots), SNI = that host |
| Model-driven tool layer | Claude Code's own tools, restricted to `Read, Glob, Grep` (+ `StructuredOutput`). No shell, write or fetch tool exists | codex's shell tool, every command under codex's read-only sandbox (legacy landlock + seccomp): no socket, no writes | none: the proxy runs no model and no tool |

Grounded before building (P3 receipt §2): Claude Code 2.1.292 starts with a dummy
`sk-ant-oat01-` token and sends every request to `ANTHROPIC_BASE_URL` with `authorization: Bearer
<token>` and the OAuth beta header. codex-cli 0.153.0 in ChatGPT-login mode honours a custom
provider's `base_url` for `/responses` and `/models` (with `authorization` and `chatgpt-account-id`
from the auth file), and `chatgpt_base_url` for its auxiliary backend calls.

## 2. What the credential proxy enforces (`credproxy.js`, contract file)

For every request from a box:

1. **Routes.** Only an origin-form request whose (method, path) is in the family's contract config
   is forwarded: Claude `POST /v1/messages`; Codex `POST /backend-api/codex/responses` and
   `GET /backend-api/codex/models`. A `CONNECT`, an absolute-form target (using the proxy as a
   forward proxy), a protocol upgrade (websocket) and any other path are refused and logged
   `denied`. One auxiliary codex request (`GET /backend-api/wham/settings/user`) is pinned in the
   contract as `declined`: answered 404 by the proxy itself, never forwarded.
2. **Box marker.** Every box-marker header must carry EXACTLY the dummy value issued to this box
   (Claude: `authorization`; Codex: `authorization` and `chatgpt-account-id`), compared in constant
   time. Anything else is refused before any upstream contact.
3. **Strip, then set, never merge.** Every header the box sent that can carry auth or identity
   (`authorization`, `proxy-authorization`, `x-api-key`, `api-key`, `cookie`, `cookie2`,
   `chatgpt-account-id`, `openai-organization`, `openai-project`, `x-anthropic-*`, forwarding
   headers) and every hop-by-hop header, including `host`, is removed. Only then are the real
   values set, once each. The box's `Host` is never used.
4. **One host, verified TLS.** The upstream is the single host in the mounted allowlist (the proxy
   exits at start if the file holds anything else), port 443, `rejectUnauthorized`, SNI and the
   certificate's name checked by Node. A test configuration may add a CA file; such a
   configuration is never the contract, and release refuses it (R4).
5. **Scrub responses.** `accept-encoding: identity` is forced upstream so the body can be read; the
   real header values and the bare token are replaced by `[scrubbed]` in response headers and in
   the streamed body (with a carry-over buffer, so a value split across chunks is still caught);
   `set-cookie` is dropped.
6. **Its own view, logged.** The first log line states the sha256 of the proxy's code, its config
   and its allowlist AS THE PROXY READ THEM. Every box check, audit egress proof and release
   compares those with the frozen contract and with the allowlist copy that was mounted.

### Reconciling a networked client, a writable HOME and "no credential in the box"

The CLI process (the model client) needs to reach its API and keep a session, so it gets the
proxy's address and a tmpfs HOME. It authenticates with a dummy that is worthless anywhere but at
this run's proxy, which accepts it only on the run's internal network, only for the routed paths,
and only while the run lasts. The model never runs code in the CLI process. Its tool layer is
either read-only file tools (Claude) or a sandboxed child with no socket (Codex). So the only data
path from the model to the network is the CLI's own request to the proxy (section 4), and the real
credential is on the other side of it.

## 3. Negative tests (all in `deep-review.sh`, results under `$DEEP_HOME/checks/`)

| Probe | What it attempts | Expected | Where proven |
|---|---|---|---|
| `netcheck` phase A (offline: both networks `--internal`; the proxy holds a synthetic CANARY; a hostile fake TLS upstream reflects every auth header it gets) | from a box: DNS and TLS to the upstream directly; direct TCP; the old squid port and port 443 on the proxy; HTTP `CONNECT` to the upstream via the proxy; an absolute-form request; a routed path without the marker; a non-routed path with it; a websocket upgrade; then a routed request carrying the marker plus `x-api-key`, `Cookie`, `Proxy-Authorization`, `OpenAI-Organization`, `X-Forwarded-For` and a spoofed `Host` | every alternate path fails, each refusal under its own logged reason; the routed request is forwarded, the upstream sees exactly the canary once in each real header and none of the box's auth headers, `Host` = the allowlisted name, and the reflection comes back `[scrubbed]` | `netcheck.json`, `probes.tsv`, `upstream.log`, `proxy-a.log` |
| `netcheck` TLS | an upstream whose certificate names another host; a proxy that trusts a different CA | `502`, `ERR_TLS_CERT_ALTNAME_INVALID` / `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, nothing crosses | `proxy-a.log`, `proxy-tls.log` |
| `netcheck` phase B | the CONTRACT config + allowlist of each family against the real host, with a canary as the credential | `401` from the real API, `tls.authorized` true, peer CN = the host, the proxy's start line = the contract | `proxy-real-*.log` |
| `canarycheck` (offline, both real CLIs) | a full CLI turn through the box + proxy + hostile upstream with a canary as the proxy's credential; while the upstream HOLDS the first model request, every process's memory in the box (and in the proxy) is dumped and scanned by value; after the turn, the box filesystem + process env dump, the stream logs, stderr and every file of the check | the canary reaches the upstream exactly; its reflection is scrubbed; 0 canary windows in box memory, the box dump and every file; positive controls: the box's own dummy IS found in box memory and the canary IS found in proxy memory | `canarycheck.json`, `<family>/memscan.json`, `<family>/run-meta.json` (`box_dump`) |
| box checks on every run | the REAL credential (exact 32-char windows) in the report, the model's text, or tool output, with the comparator REQUIRED (no real-credential input is a FAIL); the box's dummy in model-written text; credential shapes in model-written text; the session driver's box dump (every tmpfs, every process's environ and argv, `docker diff`, `docker inspect`) scanned for the real credential by value | `admitted_credential_absent`, `box_dummy_absent_from_output`, `credential_shapes_absent`, `box_dump_real_credential_absent` PASS, else the box and the gate FAIL | `box-checks.json`; `test_p3.DummyCredentialsR3` |
| egress on every run and audit | the proxy log: forwarded requests only to the allowlisted host over verified TLS, nothing denied, the proxy's own code/config/allowlist hashes = the contract and the mounted copy | `egress_allowlisted_only` PASS / the audit's egress proof | `box-checks.json`, `audit.json` |
| launch evidence on every session (P4, F2) | a launch declaration weaker than the policy (another uid, another network, a writable root, extra caps or security options, an extra mount, a privileged or root proxy) in ANY docker or CLI option syntax (`--opt=v`, `--opt v`, `-uV`, aliases, repeats: the effective last value is judged, and single-valued security options may appear once); and docker reporting a containment that differs from the declaration | refused before launch (`deepsession.validate_launch`, an option allowlist for both the box and the proxy vector); after `docker run` the driver records `docker inspect` of the box and the proxy and `docker network inspect` of their networks (internal flag, members = box + proxy only) and starts no turn on any difference; the evidence is bound by the terminal receipt and compared again with the runtime descriptor at release | `run-meta.json` / `audit-run.json` `runtime_evidence`; `release.json` runtime reasons; `test_p4` |
| `boxcheck` | writes everywhere but `/out`, symlinks to host paths, Docker socket, SSH agent, host `/Users`, capabilities | denied / dangling / absent; `CapEff` 0 | `boxcheck.txt` |
| `toolcheck` (Claude, 2 turns, the second on `--resume`) | Read `/proc/self/environ`, `/proc/1/environ`, the credentials file, `.claude.json`, other system paths; Glob/Grep outside; write, fetch, shell | refused by the tool layer in both turns; the box dump holds 0 windows of the real credential | `toolcheck.json` |
| `codexcheck` (Codex, 2 turns, the second on `exec resume`) | from the sandboxed shell: a raw socket to the proxy's IP, `CONNECT` by name, an API fetch, writes, a read of the auth file (size only) | `NET EPERM`; writes denied; the auth file is readable and holds the DUMMY only; the box dump holds 0 windows of the real credential | `codexcheck.json` |
| `memcheck` (+ positive control) | repo `CLAUDE.md` / `AGENTS.md` auto-loading | not loaded; the control does load | `memcheck.txt` |
| unit (`tests/test_p3.py`, no Docker) | `CredProxyR3` runs `credproxy.js` and `fake-upstream.js` under the host's node: strip/set, scrub at chunk boundaries, routes, `CONNECT`, absolute form, upgrade, both TLS negatives, the one-host allowlist, no credential loaded | as above | `python3 -m unittest discover -s tests` |

## 4. Residuals (what is still true)

- **The dummy is readable inside the box.** Codex's shell can read the dummy auth file (its
  read-only sandbox does not confine reads), and the Claude CLI's environment holds the dummy
  token. The dummy authenticates nothing anywhere; the proxy accepts it only from this run's
  internal network, for the routed paths, for the run's lifetime. A report or model text holding
  it fails the box checks (exact dummy) and the gate (credential shape).
- **The proxy lends the real credential's authority, bounded.** Any process in a box that can
  reach the proxy can make the routed model requests with the real credential (spend on the
  account), exactly as the CLI does. In the Codex box only the codex process can (its shell has no
  socket); the Claude box has no tool that opens a socket. The routes cut the surface from a whole
  host to one or two endpoints (P2's "a bearer for the whole ChatGPT backend" is closed).
- **The allowlisted API is still an outbound channel.** Through the routed endpoints, the model
  can send anything it has seen in the box to its own provider: repo content (by design), the
  dummy, nothing else of the operator's. The proxy constrains WHERE and WHICH ENDPOINT, not WHAT.
- **Scrubbing is exact-value.** The proxy scrubs the real header values and the bare token. An
  upstream that returned the credential encoded or split differently would not be scrubbed. The
  real APIs do not reflect credentials; the hostile fake upstream that does is how this is tested.
- **The memory scan is byte-level.** A value held only as a two-byte string or a rope could be
  missed. The positive controls bound this: the same scan finds the box's dummy in box memory and
  the canary in proxy memory.
- **Claude's tool-layer separation is still in-process** (Claude Code's permission checks, not an
  OS boundary). It now guards only the dummy: a path-handling bug would expose nothing real.
- **The host can read the proxy.** The real credential is in the proxy process's memory on the
  local Docker host for the run's duration. It is no longer in any container's env, so `docker
  inspect` does not show it.
- **The seal is a gate, not a vault.** Report admission is the committed generation (R2); modes are
  an accidental-read guard for the same user.

## 5. Public records cannot carry sealed text out

Before release, three records are readable. All are host-shaped by construction and re-checked:

- `gate.json`: `deepgate.sanitize_public` keeps a string only if it is a manifest path, a hash, a
  timestamp, a JSON path over known schema keys, a validator message over such a path, a fixed
  vocabulary token, or a host-written value (model name, pair id) of plain token shape. Anything
  else becomes `[withheld]` and is counted (`sanitizer_withheld`). Kept strings are bounded
  (300 chars) and screened by the report gate's secret and link rules. Model-written keys
  are never echoed: JSON paths show `[key]`, and unexpected `run{}` keys are counted, not
  named. A gate exception records only the exception's type.
- `box-checks.json`: verdicts and host-derived counts. The egress record names allowlisted hosts
  only and counts the rest. In C3 a box cannot choose a host at all; a forward to anything but the
  allowlisted host would be a proxy fault, and is still only counted.
- `audit.json`: result, confidence, at most 3 concern lines of at most 300 chars each (each withheld
  whole on a secret shape, a credential shape, a link or host name, or a 48-char window of repo
  text, also inside decoded base64/hex), plus the completion record: fixed reason codes and hashes.

Tests: `test_p2.Sanitizer`, `test_p2.Containment.test_public_egress_record_never_names_a_non_allowlisted_host`.
