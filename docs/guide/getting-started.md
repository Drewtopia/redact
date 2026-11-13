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
az account show -o json | redact
```

```json
{
  "environmentName": "AzureCloud",
  "id": "[SUBSCRIPTION-ID-3f1a9c2e]",
  "name": "[SUBSCRIPTION-NAME-77b0e1d4]",
  "tenantDisplayName": "[TENANT-NAME-a91c0f3b]",
  "tenantId": "[TENANT-ID-5d2e8a10]",
  "user": { "name": "[USER-0c2c9128]", "type": "user" }
}
```

What stays visible is what says nothing about you: `AzureCloud`, field names, public IDs Microsoft documents.

## See what it did

`--explain` says on stderr which rule hid each part. It never prints the value.

```sh
az repos list -o json | redact scan --explain > /dev/null
```

```text
azure:ado-org -> [ORG-…]
azure:ado-project-url -> [PROJECT-…]
azure:repo-record -> [REPO-…]
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

writes `~/.config/redact/config.toml` with every setting shown and switched off. Remove the `#` from the ones you want: values to hide, values to leave visible, packs to turn on or off, and overrides for one machine, folder or command. See [Configuration](../reference/config).

## Next

- [With Claude Code](./claude-code): keep the transcript clean.
- [With fnox and mise](./fnox-mise): hide the values they hold.
- [Hiding yourself](./me): your git name and GitHub login.
- [Configuration](../reference/config): every setting.
