# redact

Keep secrets, names, and sensitive information out of what AI sees. Pipe any output through `redact` and the parts that say who you are, who you work for or how to get in (tenant and subscription IDs, people, hosts, project names, tokens) come back as placeholders, so you can hand it to Claude, Codex or a chat window without giving those away.

```console
$ az account show -o json | redact
{
  "environmentName": "AzureCloud",
  "id": "[SUBSCRIPTION-ID-3f1a9c2e]",
  "name": "[SUBSCRIPTION-NAME-77b0e1d4]",
  "tenantDisplayName": "[TENANT-NAME-a91c0f3b]",
  "tenantId": "[TENANT-ID-5d2e8a10]",
  "user": { "name": "[USER-0c2c9128]", "type": "user" }
}
```

Each hidden part becomes a labelled placeholder. The same value gets the same placeholder within a run, so the text still makes sense: you can tell one person or project from another without seeing who they are.

## Install

```sh
mise use -g github:Drewtopia/redact
```

Or download a binary for macOS, Linux or Windows from [Releases](https://github.com/Drewtopia/redact/releases), or build it: `cargo install --git https://github.com/Drewtopia/redact`.

## Use

| Command | What it does |
| :- | :- |
| `<command> \| redact` | Masks stdin (same as `redact scan`) |
| `redact scan --explain` | Also says on stderr which rule hid each part, never the value |
| `redact scan --json` | Prints the parts to hide as byte spans instead of masked text |
| `redact packs` | Lists the rules that load |
| `redact config ls` | Lists every file that loads, in order, and what imported it |
| `redact --env-file .env` | Also hides every value in that dotenv file |
| `redact completions zsh` | Prints a shell completion script (bash, zsh, fish, powershell, elvish) |

Exit codes: 0 done, 2 bad usage, 3 a pack would not load or the scan failed. A file that will not load stops redact rather than being skipped: a redactor that quietly skips a rule hides less than you think.

## What it hides

The built-in `azure` pack finds things by where they sit, so you do not list them:

- **IDs beside their names:** tenant, subscription, app, object and identity GUIDs. A bare GUID (a request id) stays visible.
- **People:** names, emails, phones, job details and IDs in Azure DevOps and Microsoft Graph identity records, then the same name anywhere else in the text.
- **Your own hosts:** the `<name>` in `<name>.azurewebsites.net`, `<name>.crm11.dynamics.com`, `<name>.vault.azure.net` and other tenant hosts. Public hosts such as `portal.azure.com` stay visible.
- **Azure DevOps:** org, project and repo names from URLs, work items and `az devops` / `az repos` output.
- **`az account`:** tenant name, subscription name and the signed-in user.

Values Microsoft documents publicly (well-known app and role IDs, `AzureCloud`) are never hidden.

## Config

`~/.config/redact/config.toml` (`%APPDATA%\redact\config.toml` on Windows; `-c` or `REDACT_CONFIG` for another file):

```toml
# Hide the values these environment variables hold. `*` matches anything.
env = ["WORK_*", "*_TOKEN"]

# Hide every value in these dotenv files, relative to where redact runs.
env_files = [".env", ".env.local", ".env.keys"]

# More packs (.toml), word lists (.txt) or folders of them, relative to this file.
import = ["~/work/customers.txt", "packs"]
```

`env` is how redact works with [fnox](https://github.com/jdx/fnox), [mise](https://mise.jdx.dev) or anything else that sets variables, without reading their files: `fnox exec -- redact`.

`env_files` hides each value in a dotenv file, as [`dotenvx run`](https://dotenvx.com) does, including dotenvx's `.env.keys`. It skips empty values, `encrypted:` values, `DOTENV_PUBLIC_KEY*`, and settings that would wreck ordinary text if hidden everywhere: numbers, `true`/`false`, `localhost`, `development` and the like. A file that is not there is listed by `redact config ls`; `--env-file <path>` makes a missing file an error.

A word list is one word or phrase per line; `#` starts a note. The file name is the label, so `customers.txt` hides each line as `[CUSTOMERS-…]`. Every `.toml` and `.txt` in `~/.config/redact/packs/` loads too.

## Packs

A pack is a TOML file of rules. Each rule's `regex` finds a spot and `secretGroup` is the capture group to hide:

```toml
schema_version = 1
id = "acme"
keywords = ["customerid"]   # the pack only runs when one of these appears

[[rules]]
id = "customer-id"
regex = '''"customerId"\s*:\s*"(C-[0-9]{6})"'''
secretGroup = 1
label = "CUSTOMER-ID"
```

| Field | What it does |
| :- | :- |
| `secretGroup` | The capture group to hide; 0, the default, is the whole match |
| `label` | What the placeholder says; defaults to the rule id |
| `within` | Run the rule only inside a JSON record (the text between braces) that matches this regex |
| `remember` | `"distinctive"`: also hide the value everywhere else when it reads as a name (a space, `-`, `_`, `.`, a digit or an inner capital); `"any"`: any capitalised or 5+ character value |
| `keywords` | On a rule: run it only when one of these appears |
| `allow` | On a pack: values never to hide |

Regexes use the Rust [`regex`](https://docs.rs/regex) syntax, which runs in linear time and has no lookaround.

## Placeholders

A placeholder is `[LABEL-` + the first 8 hex characters of HMAC-SHA256(key, value) + `]`. Without `REDACT_KEY` the key is 32 random bytes made fresh for each run, so runs cannot be linked. Set `REDACT_KEY` (16+ characters, e.g. `openssl rand -hex 32`) for the same placeholder across runs in one session. Either way a placeholder cannot be worked back to its value without the key, and two values never share one.

## Licence

MIT or Apache-2.0, at your option.
