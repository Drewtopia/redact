# Getting started

In this tutorial we install redact, mask the output of two real commands, and write a config file. It takes about five minutes.

## Install redact

::: code-group

```sh [mise]
mise use -g github:Drewtopia/redact
```

```sh [cargo]
cargo install --git https://github.com/Drewtopia/redact
```

:::

You can also download a binary for macOS, Linux, or Windows from the [releases page](https://github.com/Drewtopia/redact/releases).

Check that it runs:

```sh
redact --version
```

You see `redact` and a version number.

## Mask your first command

```sh
git log -1 | redact
```

```text
commit 4e1f0c2a9b7d
Author: [PERSON-9e6bf2c0] <[EMAIL-208f8db2]>

    Fix retry on the billing job
```

Your name and email are now placeholders. The commit hash and the message stay visible, because they say nothing about you.

Now mask your environment. redact hides the value of any variable whose name says it is a secret, such as `PASSWORD`:

```sh
env | redact
```

```text
BILLING_DB_PASSWORD=[SECRET-5e7ccdc3]
PORT=8080
```

## See which rule hid each part

`--explain` prints each rule that fired to stderr. It never prints the value.

```sh
git log -1 | redact scan --explain > /dev/null
```

```text
identity:git-person -> [PERSON-…]
identity:email -> [EMAIL-…]
```

## See which packs loaded

```sh
redact config ls
```

```text
 1  builtin azure                         40 rules
 2  builtin identity                      5 rules
 …
 9  builtin pii                           12 rules, off
10  folder  ~/.config/redact/packs        missing
11  config  ~/.config/redact/config.toml  missing
```

The `pii` pack hides phone numbers, card numbers, and IP addresses. It starts switched off. To turn it on, see [Packs](../reference/config#packs).

A file redact looks for and does not find is listed as `missing`. You have no config file yet, so the last line says `missing`.

## Set up your shell

To get tab completion and the `redacted <command>` wrapper, add this line to `~/.zshrc`:

```sh
eval "$(redact init zsh)"
```

For bash, fish, PowerShell, and elvish, run `redact init --help`.

## Write a starter config

```sh
redact config init
```

redact writes `~/.config/redact/config.toml` with its settings switched on. It hides your git name and email, environment variables named like `*_TOKEN` or `*_PASSWORD`, and the values in `.env` files. For the other starter files, see [Start one](../reference/config#start-one).

Run `redact config ls` again. Your config file is no longer `missing`, and the lines after it show what it loads.

## Next

- [With Claude Code](./claude-code): keep the transcript clean.
- [With fnox and mise](./fnox-mise): hide the values they hold.
- [Hiding yourself](./me): your git name and GitHub login.
- [Configuration](../reference/config): every setting.
