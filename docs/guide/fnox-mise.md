# With fnox and mise

redact does not read fnox's or mise's files. They set environment variables; redact hides whatever the variables you name hold.

```toml
# ~/.config/redact/config.toml
env = ["WORK_*", "*_TOKEN", "AZURE_ORGANISATION"]
```

`*` matches any run of characters, anywhere in the name. An exact name that is not set is listed by `redact config ls`, so a missing value is easy to spot.

## fnox

Run redact under `fnox exec`, so the variables are set:

```sh
az account show -o json | fnox exec -- redact
```

fnox's own `fnox exec --redact` replaces fnox's values with `[REDACTED]` in a command's output. redact goes further (shapes such as Azure IDs and people, labelled placeholders), and the two stack.

## mise

Inside a project, `mise exec` sets the project's `[env]`:

```sh
mise exec -- sh -c 'az repos list -o json | redact'
```

## Both

```sh
fnox exec -- mise exec -- sh -c 'az repos list -o json | redact'
```

## Each variable is a label

A variable's name becomes its placeholder's label: the value of `WORK_AZ_ORG` is hidden as `[WORK-AZ-ORG-…]`. A value can hold a list, one entry per line.

## Leave a value visible

The same variables can say what not to hide. `allow` takes `$NAME`, so your organisation's name shows (and Azure DevOps links still open) while the config file names nothing:

```toml
allow = ["$WORK_AZ_ORG"]
```

## Install redact with mise

```sh
mise use -g github:Drewtopia/redact
```
