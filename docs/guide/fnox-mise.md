# With fnox and mise

redact does not read fnox's or mise's files. They set environment variables; redact hides whatever the variables you name hold.

```toml
# ~/.config/redact/config.toml
env = ["ACME_*", "*_TOKEN", "DATABASE_URL"]
```

`*` matches any run of characters, anywhere in the name. An exact name that is not set is listed by `redact config ls`, so a missing value is easy to spot.

## fnox

Run redact under `fnox exec`, so the variables are set:

```sh
kubectl get pods -o yaml | fnox exec -- redact
```

fnox's own `fnox exec --redact` replaces fnox's values with `[REDACTED]` in a command's output. redact goes further (shapes such as tokens and people, labelled placeholders), and the two stack.

## mise

Inside a project, `mise exec` sets the project's `[env]`:

```sh
mise exec -- sh -c 'docker compose logs | redact'
```

## Both

```sh
fnox exec -- mise exec -- sh -c 'docker compose logs | redact'
```

## Each variable is a label

A variable's name becomes its placeholder's label: the value of `ACME_ORG` is hidden as `[ACME-ORG-…]`. A value can hold a list, one entry per line.

## Leave a value visible

The same variables can say what not to hide. `allow` takes `$NAME`, so your organisation's name shows (and links that contain it still work) while the config file names nothing:

```toml
allow = ["$ACME_ORG"]
```

## Install redact with mise

```sh
mise use -g github:Drewtopia/redact
```
