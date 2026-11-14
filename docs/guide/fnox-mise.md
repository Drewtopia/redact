# With fnox and mise

redact does not read fnox's or mise's files. fnox and mise set environment variables, and redact hides the values of the variables you name:

```toml
# ~/.config/redact/config.toml
env = ["ACME_*", "*_TOKEN", "DATABASE_URL"]
```

`*` matches any run of characters, anywhere in the name. `redact config ls` lists an exact name that is not set, so you can spot a missing value.

To install redact itself with mise, see [Getting started](./getting-started).

## fnox

Run redact under `fnox exec`, so fnox sets the variables first:

```sh
kubectl get pods -o yaml | fnox exec -- redact
```

fnox has its own `fnox exec --redact`, which replaces fnox's values with `[REDACTED]` in a command's output. redact also hides shapes such as tokens and people, and gives each value a labelled placeholder. You can use both together.

## mise

Inside a project, `mise exec` sets the variables in the project's `[env]`:

```sh
mise exec -- sh -c 'docker compose logs | redact'
```

## Both

To use fnox and mise together, nest the commands:

```sh
fnox exec -- mise exec -- sh -c 'docker compose logs | redact'
```

## Each variable is a label

A variable's name becomes the label of its placeholder. For example, redact hides the value of `ACME_ORG` as `[ACME-ORG-…]`. A variable can hold a list, one entry per line.

## Leave a value visible

Variables can also say what not to hide. `allow` takes `$NAME`, so your organisation's name stays visible and links that contain it still work. The config file itself names nothing:

```toml
allow = ["$ACME_ORG"]
```
