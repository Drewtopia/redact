# Codex CLI

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
