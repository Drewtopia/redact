# With other agents

redact reads stdin and writes stdout, so anything that can run a command can use it. Claude Code has a mod that covers the most. See [With Claude Code](./claude-code).

## Codex CLI

Codex [hooks](https://developers.openai.com/codex/hooks) cannot edit a tool's output in place. A `PostToolUse` hook that answers `decision: "block"` replaces the result with its own `reason`, though. The hook below returns the masked output as that reason, and passes clean output through untouched.

1. Save this as `~/.codex/hooks/redact.sh` and make it executable:

   ```sh
   #!/bin/sh
   # PostToolUse hook for Codex: swaps the tool result for its masked text.
   raw=$(jq -r '.tool_response | if type == "string" then . else tojson end') || exit 2
   masked=$(printf '%s' "$raw" | redact) || { echo 'redact failed, so this output was withheld' >&2; exit 2; }
   [ "$raw" = "$masked" ] && exit 0
   jq -n --arg r "$masked" '{decision: "block", reason: $r}'
   ```

2. Add the hook to `~/.codex/config.toml`:

   ```toml
   [[hooks.PostToolUse]]
   matcher = "^Bash$"

   [[hooks.PostToolUse.hooks]]
   type = "command"
   command = "~/.codex/hooks/redact.sh"
   ```

3. In Codex, run `/hooks` once to trust the hook.

The hook has limits:

- Codex hooks cannot rewrite your prompt.
- Nothing puts a real value back into a later command, so placeholders in commands stay placeholders.
- A tool result that is not plain text is masked as JSON, so Codex sees it as one JSON string.

## Chat windows

To paste masked output into a chat window, pipe it into the clipboard:

```sh
gh pr view 42 | redact | pbcopy
```

On Linux, use `wl-copy` or `xclip -selection clipboard`. On Windows and WSL, use `clip.exe`.

To mask what is already on the clipboard on macOS:

```sh
pbpaste | redact | pbcopy
```

## Git and CI

`redact scan --json` prints `[]` when it finds nothing, so `jq -e` can turn it into a check. The check below fails when a line that the staged change adds holds anything redact would hide. `grep '^+'` keeps only the added lines, so a commit that removes a leaked value still goes through.

```sh
git diff --cached -U0 | grep '^+' | redact scan --json | jq -e 'length == 0' > /dev/null
```

Put the check in `.git/hooks/pre-commit`. You can also run it in CI against a log or an artifact before you upload it.

To see which rule fired, run it again with `--explain`. It never prints the value:

```sh
git diff --cached -U0 | grep '^+' | redact scan --explain > /dev/null
```

## Any other tool

Every tool works the same way. Send the text through `redact` before the model reads it.

If a tool needs to put real values back, use `redact scan --json`. It returns byte spans and labels, never the values, and you keep the placeholder map yourself. The [Claude Code mod](https://github.com/Drewtopia/redact/tree/main/claude-plugin) is a worked example.
