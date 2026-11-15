# Use with any tool

redact reads stdin and writes stdout, so anything that can run a command can use it. Send the text through `redact` before a model, a person, or a log reads it:

```sh
some-command 2>&1 | redact
```

The [integrations](../integrations/) show this with particular agents and tools. None of them are required.

## Put real values back

A tool that runs commands for a model may need the real value back when the model uses a placeholder. Use `redact scan --json`. It returns byte spans and labels, never the values, and you keep the placeholder map yourself. The [Claude Code mod](https://github.com/Drewtopia/redact/tree/main/claude-plugin) is a worked example.
