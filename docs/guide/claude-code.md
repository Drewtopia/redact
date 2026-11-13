# With Claude Code

Anything that reaches Claude's conversation stays in it: it is sent again on every turn, saved in the session file and copied into every subagent. The only fix is to keep it out.

## Install the mod

The `redact` mod runs everything that enters the conversation through redact before Claude reads it, and puts the real value back when Claude uses a placeholder in a command.

1. Install the binary (see [Getting started](./getting-started)), and check that Claude Code can find it:

   ```sh
   redact scan --help
   ```

2. In Claude Code, install the mod, then answer `y` to add the marketplace and pick a scope:

   ```
   /plugin install redact --marketplace Drewtopia/redact
   ```

Your [config](../reference/config) applies as it does in a pipe: the same packs, `me`, `env`, `allow` and overrides. The mod runs redact in the session's folder, so `dir` overrides and `env_files` follow the project you are in.

::: warning One redactor at a time
Turn off any other redacting mod (such as `transcript-redactor`) first. With two, the other one masks first, its placeholders reach Claude, and redact cannot put the real value back.
:::

## What it covers

| Where text enters | What the mod does |
| :- | :- |
| Your prompt, and context a hook adds to it | Hides each part before it is sent |
| Every tool result: Bash, Read, Grep, MCP tools, subagent answers | Hides each part before Claude reads it |
| CLAUDE.md and the context on the first message | Hides each part |
| `@`-mentioned files | Refuses a file that holds something to hide, and points Claude to the Read tool, whose result is hidden |
| A subagent's task | Hides each part; a workflow agent whose prompt holds one is not started |

A Bash command's own text is passed on as `--command` (through `REDACT_COMMAND`), so a `command` [override](../reference/config#overrides) applies to it alone.

## Placeholders going back in

When Claude writes a placeholder into a command or a file, the mod swaps it back for the real value, so `curl -H "x-api-key: [SECRET-9692fb16]"` still works. Three rules keep that safe:

- **Only local tools.** Bash, Write, Edit, MultiEdit, NotebookEdit, Read, Glob and Grep get real values. Agent, WebFetch, WebSearch and MCP tools never do. Change the list with the `restoreTools` setting.
- **Nothing leaves through git or GitHub.** A `git commit`, `git tag`, `gh pr`, `gh issue` or `gh api` command keeps its placeholders, so a commit message or issue body cannot carry the value off the machine.
- **No shell code.** A value holding spaces, quotes, `$` or other shell characters is not put into a Bash command. The call is refused, and Claude is told to write the value to a file and read it from there. A person's name with a space in it is such a value.

Whatever a tool prints of a value it was handed comes back hidden, even where no rule would find it.

## When redact cannot run

The mod fails closed. If the binary is missing, too old, or exits with an error (a pack that will not load), the mod withholds the text instead of passing it raw, and a toast says why. Point the `binary` setting at a full path if `redact` is not on Claude Code's `PATH`.

## Settings

Claude Code asks for these when you install the mod; change them later in the `/plugin` menu:

| Setting | Default | What it does |
| :- | :- | :- |
| `binary` | `redact` | The redact command to run |
| `restoreTools` | `Bash,Write,Edit,MultiEdit,NotebookEdit,Read,Glob,Grep` | Tools that get the real value behind a placeholder |
| `notify` | on | A count on the tool row and a toast on a prompt when something is hidden |

## Without the mod: a hook

A plain [PostToolUse hook](https://code.claude.com/docs/en/hooks) can mask Bash output with nothing but redact and `jq`. It covers less than the mod: it cannot rewrite your prompt, it puts no real value back into commands, and the session file on disk keeps the original output.

Save this as `~/.claude/hooks/redact-bash.sh` and make it executable:

```sh
#!/bin/sh
# PostToolUse hook for Claude Code: masks a Bash call's stdout and stderr.
in=$(cat)
out=$(printf '%s' "$in" | jq -r '.tool_response.stdout // ""' | redact) &&
err=$(printf '%s' "$in" | jq -r '.tool_response.stderr // ""' | redact) ||
  { out='redact failed, so this output was withheld'; err=''; }
printf '%s' "$in" | jq --arg o "$out" --arg e "$err" \
  '{hookSpecificOutput: {hookEventName: "PostToolUse", updatedToolOutput: (.tool_response + {stdout: $o, stderr: $e})}}'
```

Then add it to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "~/.claude/hooks/redact-bash.sh" }] }
    ]
  }
}
```

## Pipe output yourself

Without either, run the command, pipe it through redact, and paste the result:

```sh
gh issue view 1234 | redact
```

## Two placeholders, one value

The mod keeps one placeholder per value for the whole session. In a pipe, the same value gets the same placeholder within one run, and a new one in the next, unless you set a key:

```sh
export REDACT_KEY=$(openssl rand -hex 32)
```

See [How it works](../reference/how-it-works).
