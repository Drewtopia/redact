# With Claude Code

Anything that reaches Claude's conversation stays in it: it is sent again on every turn, saved in the session file and copied into every subagent. The only fix is to keep it out.

## Pipe output yourself

The simplest way: run the command, pipe it through redact, paste the result.

```sh
az boards work-item show --id 1234 -o json | redact
```

## Inside Claude Code

Claude runs its own commands, so piping by hand does not cover them. A Claude Code mod can scan every tool result before Claude reads it, swap each hidden part for a placeholder, and put the real value back when Claude uses the placeholder in a command. That keeps the saved transcript clean too.

redact is built to be the detector behind such a mod: `redact scan --json` returns the positions to hide, never the values, and the mod keeps the placeholders and their real values in memory for the session.

::: tip Hooks or a mod?
Claude Code hooks can rewrite a tool's output (`updatedToolOutput`), but they cannot rewrite your prompt, and the transcript saved on disk keeps the original. A mod covers prompts, CLAUDE.md, attachments and subagent tasks as well.
:::

## Two placeholders, one value

Inside one run, the same value always gets the same placeholder. Across runs it does not, unless you set a key:

```sh
export REDACT_KEY=$(openssl rand -hex 32)
```

See [How it works](../reference/how-it-works).
