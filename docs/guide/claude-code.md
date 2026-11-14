# With Claude Code

Anything that reaches Claude's conversation stays there. Claude Code sends it again on every turn, saves it in the session file, and copies it into every subagent. The only fix is to keep it out.

## Install the mod

The `redact` mod sends everything that enters the conversation through redact before Claude reads it. When Claude uses a placeholder in a command, the mod puts the real value back.

::: warning One redactor at a time
Before you install, turn off any other redacting mod, such as `transcript-redactor`. With two mods, the other one masks first. Its placeholders reach Claude, and redact cannot put the real value back.
:::

1. Install the binary. See [Getting started](./getting-started).
2. Check that Claude Code can find it:

   ```sh
   redact scan --help
   ```

3. In Claude Code, install the mod:

   ```
   /plugin install redact --marketplace Drewtopia/redact
   ```

4. Answer `y` to add the marketplace, then pick a scope.

Your [config](../reference/config) applies as it does in a pipe: the same packs, `me`, `env`, `allow`, and overrides. The mod runs redact in the session's folder, so `dir` overrides and `env_files` follow the project you are in.

## What it covers

| Where text enters | What the mod does |
| :- | :- |
| Your prompt, and context a hook adds to it | Hides each part before Claude Code sends it |
| Every tool result: Bash, Read, Grep, MCP tools, and subagent answers | Hides each part before Claude reads it. See [Tool results](#tool-results) |
| CLAUDE.md and the context on the first message | Hides each part |
| `@`-mentioned files | Refuses a file that holds something to hide, and points Claude to the Read tool, whose result is hidden |
| A subagent's task | Hides each part. A workflow agent whose prompt holds something to hide is not started |

### Tool results

Before Claude reads a tool result, the mod also:

- Hides object keys, not only values.
- Reads each field with its name, so `password: …` is hidden even when the value alone looks plain.
- Withholds a result whose secret sits in a number, because a number cannot hold a placeholder.

The mod passes a Bash or PowerShell command's own text to redact as `--command`, through `REDACT_COMMAND`. A `command` [override](../reference/config#overrides) then applies to that command's output alone.

## Placeholders going back in

When Claude writes a placeholder into a command or a file, the mod swaps it back for the real value. So `curl -H "x-api-key: [SECRET-9692fb16]"` still works. Three rules keep that safe.

### Only local tools

Bash, PowerShell, Write, Edit, MultiEdit, NotebookEdit, Read, Glob, and Grep get real values. Agent, WebFetch, WebSearch, and MCP tools never do. To change the list, use the `restoreTools` setting.

### Not into git history or a pull request

These commands keep their placeholders: `git commit`, `git tag`, `gh pr`, `gh issue`, `gh api`, `glab mr`, and `az repos`. A commit message or an issue body cannot carry the value off the machine.

::: warning A file still gets the real value
Write puts the real value into a file, and a later `git add` and `git commit` would publish it. The [pre-commit check](./agents#git-and-ci) catches that.
:::

### No shell code

The mod does not put a value into a Bash or PowerShell command when the value holds spaces, quotes, `$`, or other shell characters. It refuses the call instead, and tells Claude to write the value to a file and read it from there. A person's name with a space in it is such a value.

When a tool prints a value the mod handed it, that value comes back hidden, even where no rule would find it.

## When redact cannot run

The mod fails closed. It withholds the text instead of passing it on raw when the redact binary:

- is missing
- is too old
- exits with an error, such as a pack that will not load

A toast says why. If `redact` is not on Claude Code's `PATH`, set the `binary` setting to its full path.

## Settings

Claude Code asks for these settings when you install the mod. To change them later, open the `/plugin` menu.

| Setting | Default | What it does |
| :- | :- | :- |
| `binary` | `redact` | The redact command to run |
| `restoreTools` | `Bash,PowerShell,Write,Edit,MultiEdit,NotebookEdit,Read,Glob,Grep` | Tools that get the real value behind a placeholder |
| `notify` | on | A count on the tool row and a toast on a prompt when something is hidden |

## Without the mod: a hook

A plain [PostToolUse hook](https://code.claude.com/docs/en/hooks) can mask Bash output with only redact and `jq`. It covers less than the mod:

- It cannot rewrite your prompt.
- It puts no real value back into commands.
- The session file on disk keeps the original output.

1. Save this as `~/.claude/hooks/redact-bash.sh` and make it executable:

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

2. Add the hook to `~/.claude/settings.json`:

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

Without the mod or the hook, run the command, pipe it through redact, and paste the result:

```sh
gh issue view 1234 | redact
```

## Two placeholders, one value

The mod keeps one placeholder per value for the whole session. A pipe works differently. The same value gets the same placeholder within one run, and a new one in the next run. To keep placeholders the same across runs, set a key:

```sh
export REDACT_KEY=$(openssl rand -hex 32)
```

See [How it works](../reference/how-it-works).
