# AGENTS.md

## Agent skills

### Issue tracker

Issues live in GitHub Issues on Drewtopia/redact, through the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles, each label named for its role: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root, created when first needed. See `docs/agents/domain.md`.

### Docs pages

Writing, moving or syncing a page on the docs site under `docs/`, including the docs a code change owes: see `docs/agents/writing-docs.md`.

### Releases

release-please makes every release; never push a tag or edit a version by hand. See `docs/agents/releases.md`.

## AI attribution

Anything an agent writes in this repo says so.

- **Commits:** a `Co-Authored-By:` trailer naming the agent. Claude Code adds it from `.claude/settings.json`.
- **PR bodies:** end with a line naming the agent. Claude Code adds it from the same file.
- **Issues and comments** made with `gh`: end the body with `_Drafted by <agent>, an AI agent._`
