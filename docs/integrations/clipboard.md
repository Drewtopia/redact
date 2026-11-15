# Chat windows

To paste masked output into a chat window, pipe it into the clipboard:

```sh
gh pr view 42 | redact | pbcopy
```

On Linux, use `wl-copy` or `xclip -selection clipboard`. On Windows and WSL, use `clip.exe`.

To mask what is already on the clipboard on macOS:

```sh
pbpaste | redact | pbcopy
```
