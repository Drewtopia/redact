# Getting started

## Install

::: code-group

```sh [mise]
mise use -g github:Drewtopia/redact
```

```sh [cargo]
cargo install --git https://github.com/Drewtopia/redact
```

:::

Or download a binary for macOS, Linux or Windows from the [releases page](https://github.com/Drewtopia/redact/releases).

## Your first pipe

```sh
git log -1 | redact
```

```text
commit 4e1f0c2a9b7d
Author: [PERSON-9e6bf2c0] <[EMAIL-208f8db2]>

    Fix retry on the billing job
```

What stays visible is what says nothing about you: the commit hash, the message, field names. Anything with a name that says secret is hidden too:

```sh
env | redact
```

```text
BILLING_DB_PASSWORD=[SECRET-5e7ccdc3]
PORT=8080
```

## See what it did

`--explain` says on stderr which rule hid each part. It never prints the value.

```sh
git log -1 | redact scan --explain > /dev/null
```

```text
identity:git-person -> [PERSON-…]
identity:email -> [EMAIL-…]
```

## See what loaded

```sh
redact config ls
```

```text
 1  builtin azure                         40 rules
 2  builtin identity                      5 rules
 3  builtin kubernetes                    3 rules
 4  builtin docker                        2 rules
 5  builtin npm                           1 rules
 6  builtin http                          2 rules
 7  builtin gcp                           5 rules
 8  builtin credentials                   22 rules
 9  builtin pii                           12 rules, off
10  config  ~/.config/redact/config.toml  0 imports
```

`pii` (phone numbers, cards, IP addresses) starts switched off; `[packs] enable = ["pii"]` turns it on.

## Make it yours

```sh
redact config init
```

writes `~/.config/redact/config.toml` with a short config that is already on: it hides you, environment variables named like `*_TOKEN` or `*_PASSWORD`, and `.env` files. `--preset full` also turns on the `pii` pack; `--preset commented` writes every setting shown and switched off, to read and pick from: values to hide, values to leave visible, packs to turn on or off, and overrides for one machine, folder or command. See [Configuration](../reference/config).

## Next

- [With Claude Code](./claude-code): keep the transcript clean.
- [With fnox and mise](./fnox-mise): hide the values they hold.
- [Hiding yourself](./me): your git name and GitHub login.
- [Configuration](../reference/config): every setting.
