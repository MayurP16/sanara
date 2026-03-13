# LLM Data Policy

Defaults:
- Agentic fallback disabled.
- Enabled only with BYO key (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) and subject to workflow/policy controls.
- `llm_context_mode: minimal` by default.
- `llm_provider: anthropic` by default.
- Default model pins:
  - Anthropic: `claude-sonnet-4-6`
  - OpenAI: `gpt-4o-mini`

Provider selection:
- `llm_provider: anthropic` uses `ANTHROPIC_API_KEY`.
- `llm_provider: openai` uses `OPENAI_API_KEY`.
- `anthropic_model` and `openai_model` can be set in `.sanara/policy.yml` or via action inputs per run.

Modes:
- `minimal`: narrowest context collection.
- `module` / `repo`: broader context collection when explicitly enabled.

Controls:
- Allow/deny globs from policy scope what files are included in LLM context.
- Known secret patterns (AWS keys, PEM headers, GitHub and Slack tokens) are scrubbed from Terraform content before it is sent to the LLM. This is best-effort pattern matching, not comprehensive secret scanning.
- Artifact writers redact known runtime secrets (`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`) from selected text outputs.
- Emit `agentic/llm_ledger.json` with file hashes and byte counts.
- Emit `agentic/trace.jsonl` for tool/decision traceability.
