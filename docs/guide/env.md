# Hide environment variables

Secrets often reach a command as environment variables, set by your shell profile, a secrets manager, a task runner, or CI. redact does not need to know what set them. Name the variables, and redact hides their values wherever they appear:

```toml
# ~/.config/redact/config.toml
env = ["ACME_*", "*_TOKEN", "DATABASE_URL"]
```

`*` matches any run of characters, anywhere in the name. `redact config ls` lists an exact name that is not set, so you can spot a missing value.

redact reads the variables from its own environment. If a tool sets them only for the commands it runs, run redact under that tool too. For examples, see [fnox](../integrations/fnox) and [mise](../integrations/mise).

## Each variable is a label

A variable's name becomes the label of its placeholder. For example, redact hides the value of `ACME_ORG` as `[ACME-ORG-…]`. A variable can hold a list, one entry per line.

## Leave a value visible

Variables can also say what not to hide. `allow` takes `$NAME`, so your organisation's name stays visible and links that contain it still work. The config file itself names nothing:

```toml
allow = ["$ACME_ORG"]
```
