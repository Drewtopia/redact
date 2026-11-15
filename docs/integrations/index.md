# Integrations

redact works with anything that prints text: it reads stdin and writes stdout. These pages show it with particular tools. None of them are required, and redact works the same without them. See [Use with any tool](../guide/any-tool).

| Tool | What the page shows |
| :- | :- |
| [Claude Code](./claude-code) | A mod that masks prompts, tool results, CLAUDE.md and subagent tasks, and puts real values back in local commands |
| [Codex CLI](./codex) | A hook that masks tool output |
| [Chat windows](./clipboard) | Masking what you paste |
| [Git hooks and CI](./git-ci) | Failing a commit or a build that would leak |
| [fnox](./fnox) | Hiding the secrets fnox sets |
| [mise](./mise) | Installing redact, and hiding a project's `[env]` |
