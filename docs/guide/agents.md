# With other agents

redact reads stdin and writes stdout, so anything that can run a command can use it. For Claude Code, see [With Claude Code](./claude-code): it has a mod that covers the most.

## Codex CLI

Codex [hooks](https://developers.openai.com/codex/hooks) cannot edit a tool's output in place, but a `PostToolUse` hook that answers `decision: "block"` replaces the result with its own `reason`. This hook hands back the masked output as that reason, and passes clean output through untouched.

Save it as `~/.codex/hooks/redact.sh` and make it executable:

```sh
#!/bin/sh
# PostToolUse hook for Codex: swaps the tool result for its masked text.
raw=$(jq -r '.tool_response | if type == "string" then . else tojson end') || exit 2
masked=$(printf '%s' "$raw" | redact) || { echo 'redact failed, so this output was withheld' >&2; exit 2; }
[ "$raw" = "$masked" ] && exit 0
jq -n --arg r "$masked" '{decision: "block", reason: $r}'
```

Then add it to `~/.codex/config.toml`:

```toml
[[hooks.PostToolUse]]
matcher = "^Bash$"

[[hooks.PostToolUse.hooks]]
type = "command"
command = "~/.codex/hooks/redact.sh"
```

Run `/hooks` in Codex once to trust it.

Limits: Codex hooks cannot rewrite your prompt, and nothing puts a real value back into a later command, so Claude-style placeholders in commands stay placeholders. A tool result that is not plain text is masked as JSON, so Codex sees it as one JSON string.

## Chat windows

Pipe into the clipboard, then paste:

```sh
gh pr view 42 | redact | pbcopy
```

On Linux use `wl-copy` or `xclip -selection clipboard`; on Windows and WSL, `clip.exe`. To mask what is already on the clipboard, on macOS:

```sh
pbpaste | redact | pbcopy
```

## Git and CI

`redact scan --json` prints `[]` when it finds nothing, so `jq -e` turns it into a check. This fails when a line the staged change adds holds anything redact would hide; `grep '^+'` keeps only added lines, so a commit that removes a leaked value still goes through:

```sh
git diff --cached -U0 | grep '^+' | redact scan --json | jq -e 'length == 0' > /dev/null
```

Put it in `.git/hooks/pre-commit`, or run it in CI against a log or an artifact before it is uploaded. Add `--explain` to a second run to see which rule fired, never the value:

```sh
git diff --cached -U0 | grep '^+' | redact scan --explain > /dev/null
```

## Any other tool

The pattern is the same everywhere: send the text through `redact` before the model reads it. Where a tool needs to put real values back, use `redact scan --json`, which returns byte spans and labels, never the values, and keep the placeholder map yourself. The [Claude Code mod](https://github.com/Drewtopia/redact/tree/main/claude-plugin) is a worked example.
