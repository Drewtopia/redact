# Hiding yourself

Your GitHub username sits in plain URLs such as `github.com/<you>/project`, in git remotes, and in git config. No rule can tell that it is you. To hide it, turn on `me`:

```toml
# ~/.config/redact/config.toml
me = true
```

When redact starts, it asks git for your `user.name` and `user.email`, both in the repo you run it from and globally. A work email set by an `includeIf` counts when you run redact inside that repo. redact also reads your GitHub logins from gh's `hosts.yml`. It hides each of them everywhere:

| What | Placeholder |
| :- | :- |
| Your git name | `[ME-NAME-…]` |
| Your git emails | `[ME-EMAIL-…]` |
| Your GitHub logins | `[ME-GITHUB-…]` |

You have nothing to keep in sync. If you change your git name, redact follows. A value that is not set is skipped.

`redact config ls` lists what redact found, by kind and count only:

```text
12  me      git config, gh hosts.yml      2 name, 2 email, 1 github  <- ~/.config/redact/config.toml
```

::: tip The cost
Your own repositories then read as `github.com/[ME-GITHUB-…]/project`. In Claude Code, the redact mod restores placeholders in commands, so `gh` and `git` still get the real value.
:::
