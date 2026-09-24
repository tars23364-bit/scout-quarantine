# The auditor: second reader, different model family

Scout's local model writes the report. Nobody trusts one model. A second reader audits the
report for injection passthrough, format, consistency, and omission, and the agent reads the
report only after that audit. Three tiers, strongest first. Set `auditor` in `config.json`.

| `auditor` | What reads the report | Strength |
|---|---|---|
| `codex` | `codex exec` (OpenAI Codex CLI), read-only sandbox, reads the two report files itself | Best: a third model family, separate from both the scan model and the agent |
| `ollama` | a second local model (`audit_model`) unlike the scan model, schema-bounded reply | Real diversity, fully offline. Scan on qwen, audit on llama |
| `none` | nobody | Honest floor: every run records `UNAVAILABLE` |

The prompt is `auditor-prompt.md`, the same for every tier. It tells the auditor to use its own
words and never quote the report, so the auditor's three-line reply is safe for the agent to read.

## What happens to the report

After a scan the report directory is **sealed** (mode 000 plus a `SEALED` marker). `scout audit
<zone>` unseals it for the auditor, records the result in `metadata.json` and `history.json`,
and leaves it readable only when:

- the scan verdict is not HOSTILE, and
- the audit is PASS or INCONCLUSIVE, or it is UNAVAILABLE and `allow_unaudited_read` is true.

Otherwise it is sealed again and `scout audit` exits 4. A HOSTILE report never unseals.

The seal is a gate, not a vault: the same user can `chmod` it back. Its job is to make reading an
unaudited report a deliberate act outside the normal flow, so an agent following the skill cannot
drift into it.

## Choosing

Have Codex or another CLI model? Use `codex`. Offline, or one vendor only? Use `ollama` and pull a
second model from a different family than the scanner. Neither? Leave `none`, keep
`allow_unaudited_read` false, and treat every INCONCLUSIVE as "a human looks before anything is
adopted".
