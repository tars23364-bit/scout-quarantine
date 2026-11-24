# scout-quarantine

A quarantine reader for persistent AI agents. Before your agent clones a repo, installs a
package, or reads a page someone handed it, Scout fetches the thing in a throwaway container,
extracts it twice with no network, has a local model write a schema-bounded security report,
has a *second* model audit that report, and only then unseals it for the agent.

The agent reads last. That is the whole design.

Built for [persistent-agent-guide](https://github.com/tars23364-bit/persistent-agent-guide)
readers: a long-running agent that fetches the web into a session with real capabilities needs
a gate between "found this" and "read this". Extracted from a production agent (Athena) where it
has run since March 2026 and was rebuilt in September 2026.

## Threat model

The attacker controls the content: a repo, a package tarball, a web page. Their goal is a prompt
injection that your agent obeys, or credentials the agent carries. Scout assumes:

- **The content is hostile until read safely.** Fetch happens in a container with all
  capabilities dropped, read-only root, non-root user, no hooks. Nothing is executed.
- **One reader is not enough.** Two extraction passes with different sampling must agree; a
  seeded canary must survive both. Disagreement or a missing canary aborts before any model runs.
- **The scan model can be fooled.** Its output is forced into a JSON schema whose enums bound the
  verdict, so content cannot change the report's shape. An 8B model still misses subtle attacks,
  which is why:
- **A different model family audits the report** for injection passthrough, consistency, and
  omission, and is told never to quote it. The agent sees the auditor's three lines, not the
  report, until the audit passes.
- **The report is sealed on disk** (mode 000) until `scout audit` unseals it. Reading an
  unaudited report requires a deliberate act outside the normal flow.

What it does **not** do: it does not run code, so runtime behaviour (postinstall scripts, build
steps) is inferred from reading, not observed. Bait canaries catch *modification* of planted
fake credentials; a read-only exfil attempt inside a no-network container leaves no trace, and
no-network is the control there. The fetch container has open internet, so a hostile repo can
tell it is being fetched. The model sees a budgeted sample of the target, not every file.

## What the verdict covers

The COVERAGE header and SCOPE section report distinct text files read, full and truncated
files, and the union of source bytes in the excerpts sent to the model. Files not read
are not covered. SAFE_TO_USE means safe for an AI agent to READ/adopt those excerpts;
it says nothing about software correctness, safety to RUN, or what the code controls.
Partial coverage adds `(sampled, see SCOPE)` in Markdown; JSON recommendation enums stay
unchanged and `coverage_partial` is true. The census uses the extractor's `text/*` MIME
classification, excluding `.git`, symlinks and the pipeline canary. Budget omissions count
files with no included view; omitted alternate views are also counted separately. Legacy
extractions without census/range metadata report unknown totals and remain partial.

A `--type=url` target that is an HTML page is judged as rendered text, not as markup. The
model sees the title and meta text, the visible text, the links, the sources the page pulls
in or posts to (scripts, frames, embeds, objects, forms, stylesheets), and the text a browser
would not show: comments, text inside elements hidden by the `hidden` attribute,
`aria-hidden="true"` or an inline hiding style, `<template>` content, and `alt`, `title`,
`aria-label` and `placeholder` attribute text. Control, zero-width and bidi characters appear
as visible `\u{XXXX}` escapes. It does not judge inline script and style bodies; the report's
SCOPE section says how many were left out and how large they were. Text hidden by stylesheet
classes cannot be told from visible text and is judged as visible. When the
verdict is CLEAN and coverage is not partial, the rendered text is held in the zone's `held/`
dir (mode 000, outside the report the auditor works in). An audit PASS moves it to
`report/rendered-page.txt`; any other audit result deletes it.

## Quickstart

Prerequisites: Docker, [ollama](https://ollama.com), Python 3.9+, bash. Optional: the
[Codex CLI](https://github.com/openai/codex) as the auditor (see `audit/README.md` for the
offline alternative).

```bash
git clone https://github.com/tars23364-bit/scout-quarantine
cd scout-quarantine
./setup.sh            # builds two images, pulls qwen3:8b (~5 GB), writes config, links `scout`
scout doctor          # says what is still missing
```

Then scan something:

```bash
scout https://github.com/some/repo        # exit 0 = done, report SEALED
scout audit <zone>                        # unseals on PASS/INCONCLUSIVE, exit 4 if it stays sealed
```

Details in [SETUP.md](SETUP.md).

## Claude Code plugin

`plugin/` is a thin Claude Code plugin: the `scout` skill (when to fire, what the exit codes
mean, the isolation rule), the `/scout` command, and a SessionStart hook that runs
`scout doctor -q` so a half-installed host is loud rather than silent. It carries none of the
infrastructure; run `setup.sh` first.

```
claude plugin marketplace add tars23364-bit/scout-quarantine
claude plugin install scout@scout-quarantine
```

Other harnesses: the skill text is plain Markdown; drop it wherever your agent reads its
operating rules and expose `scout` on PATH.

## Layout

```
scout.sh              orchestrator: scan | audit | doctor | record-audit
setup.sh              one-shot host setup
lib/scoutlib.py       host helpers: trust check, model analysis, audit tiers, history
lib/merge-extractions.py, lib/validate-schema.py, lib/scout-prompt.md
docker/               Dockerfile.fetch, Dockerfile.extract, fetch.sh, extract.sh,
                      render_html.py (HTML page to prefixed text, runs in the extract image)
audit/                auditor-prompt.md (model-agnostic), README.md (the tiers)
config.example.json   copied to $SCOUT_HOME/config.json by setup
plugin/               the Claude Code plugin
```

State lives in `$SCOUT_HOME` (default `~/.local/state/scout`): `config.json`,
`trusted-sources.json`, `history.json` (append-only mission log), `zones/` (one dir per scan).
Nothing in the repo is state.

## Pipeline

1. **Prepare.** Zone dir, mission file, four bait canaries hashed.
2. **Fetch.** `scout/fetch` is the only container with network. Shallow clone with hooks
   disabled, or the registry tarball / sdist without installing it.
   **Render (url only).** If the downloaded file is HTML, `render_html.py` runs in the extract
   image with `--network=none` and replaces it with rendered-text parts small enough that one
   excerpt reads each part whole; the raw page and a `render.json` record go to the zone's
   `source/` dir, which the extractions never see. A render that fails stops the scan.
3. **Extraction canary.** A random UUID file is seeded into the target; both extractions must report it.
4. **Dual extraction.** Two `scout/extract` containers with `--network=none`. A reads key files
   plus a random sample; B reads a different random sample and different line ranges. Only A
   sees the bait files.
5. **Schema check** on both extraction JSONs.
6. **Canaries**, before any model sees content. Failure exits 2 and notifies.
7. **Consistency and merge.** Trees, counts, sizes, canary, indicators must agree.
8. **Analysis.** ollama chat API on the host, explicit 32k context, instructions in the system
   message, extraction in the user message between markers, schema-constrained reply.
   For a rendered page, the parts are then copied to `held/rendered-page.txt` (mode 000) if the
   verdict is CLEAN, coverage is full and every part is still present; otherwise it is withheld.
   The audit step moves it into the report on PASS and deletes it on anything else.
9. **Seal.** Report dir goes to mode 000. `scout audit` is the only sanctioned way back.

## Configuration

`config.json` keys that matter: `default_model` / `fast_model` (ollama names), `auditor`
(`codex` | `ollama` | `none`), `audit_model` (for the ollama tier), `allow_unaudited_read`
(default false), `auto_trust_on_clean` (must stay false), container limits, sampling sizes.

Env: `SCOUT_HOME`, `SCOUT_ROOT`, `OLLAMA_HOST`, `SCOUT_NOTIFY_CMD` (a command receiving
`"<title>" "<message>"` on HOSTILE and canary failures), `SCOUT_NOTIFY=0` to silence.

## License

MIT.
