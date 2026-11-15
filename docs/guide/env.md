# Hide environment variables

Secrets often reach a command as environment variables, set by your shell profile, a secrets manager, a task runner, or CI. redact does not need to know what set them. Name the variables, and redact hides their values wherever they appear:

```toml
# ~/.config/redact/config.toml
env = ["ACME_*", "*_TOKEN", "DATABASE_URL"]
```

redact skips entries that would hide ordinary text everywhere: entries under 3 characters, lines that start with `#`, and settings such as numbers, `true` and `development`. The settings are the same ones listed in [What is skipped](./dotenv#what-is-skipped).

`*` matches any run of characters, anywhere in the name. `redact config ls` lists an exact name that is not set, so you can spot a missing value.

redact reads the variables from its own environment. If a tool sets them only for the commands it runs, run redact under that tool too. For examples, see [fnox](../integrations/fnox) and [mise](../integrations/mise).

## Names stay out of placeholders

Each value hides as `[ENV-VALUE-…]`. The variable's name stays out of the placeholder, as a name such as `ACME_ORG` can say whose value it is. `redact scan --explain` still names the variable. A variable can hold a list, one entry per line.

## Leave a value visible

Variables can also say what not to hide. `allow` takes `$NAME`, so your organisation's name stays visible and links that contain it still work. The config file itself names nothing:

```toml
allow = ["$ACME_ORG"]
```
