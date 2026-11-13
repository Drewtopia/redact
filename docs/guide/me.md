# Hiding yourself

Your own GitHub username sits in plain URLs (`github.com/<you>/project`), git remotes and config, where no rule can tell it is you. Tell redact to find out:

```toml
# ~/.config/redact/config.toml
me = true
```

At start, redact asks git for your `user.name` and `user.email`, in the repo you run it from and globally (a work email set by an `includeIf` counts when you run redact inside that repo), and reads your GitHub logins from gh's `hosts.yml`. They are hidden everywhere:

| What | Placeholder |
| :- | :- |
| Your git name | `[ME-NAME-…]` |
| Your git emails | `[ME-EMAIL-…]` |
| Your GitHub logins | `[ME-GITHUB-…]` |

There is nothing to keep in sync: change your git name and redact follows. What is not set is skipped. `redact config ls` lists what was found, by kind and count only:

```text
 5  me      git config, gh hosts.yml   2 name, 2 email, 1 github
```

::: tip The cost
Your own repositories then read as `github.com/[ME-GITHUB-…]/project`. Inside a Claude Code mod that restores placeholders in commands, `gh` and `git` still get the real value.
:::
