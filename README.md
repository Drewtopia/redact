# redact

> [!WARNING]
> **Work in progress.** redact hides a lot, but not everything, and it will miss things. Check its output before you share anything that matters, and do not rely on it as your only safeguard. Found a leak? Please [open an issue](https://github.com/Drewtopia/redact/issues) naming the command and the field, never the value.

Keep secrets, names, and sensitive information out of what AI sees. Pipe any output through `redact` and the parts that say who you are, who you work for or how to get in (tokens, passwords, people, emails, internal hosts and IDs) come back as placeholders, so you can hand it to Claude, Codex or a chat window without giving those away.

```console
$ { git log -1; env | grep BILLING; curl -sv https://api.example.com/v1/jobs; } 2>&1 | redact
commit 4e1f0c2a9b7d
Author: [PERSON-9e6bf2c0] <[EMAIL-208f8db2]>

    Fix retry on the billing job

BILLING_DB_PASSWORD=[SECRET-5e7ccdc3]
> x-api-key: [SECRET-9692fb16]
```

Each hidden part becomes a labelled placeholder. The same value gets the same placeholder within a run, so the text still makes sense: you can tell one person or secret from another without seeing who they are.

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
| `redact packs` | Lists the rules that load, and the packs switched off |
| `redact config ls` | Lists every file that loads, in order, what imported it, and each override that applied |
| `redact config init` | Writes a starter config with every setting switched off |
| `redact --command "gh pr view"` | Names the command whose output this is, for `command` overrides |
| `redact --env-file .env` | Also hides every value in that dotenv file |
| `redact completions zsh` | Prints a shell completion script (bash, zsh, fish, powershell, elvish) |

Exit codes: 0 done, 2 bad usage, 3 a pack would not load or the scan failed. A file that will not load stops redact rather than being skipped: a redactor that quietly skips a rule hides less than you think.

## With AI agents

**Claude Code:** the `redact` mod runs every prompt, tool result, CLAUDE.md and subagent task through redact before Claude reads it, and puts the real value back when Claude uses a placeholder in a local command. With the binary installed, type this in Claude Code:

```
/plugin install redact --marketplace Drewtopia/redact
```

**Codex CLI, plain Claude Code hooks, chat windows, git and CI:** see [With other agents](https://drewtopia.github.io/redact/guide/agents) and [With Claude Code](https://drewtopia.github.io/redact/guide/claude-code).

## What it hides

The built-in `credentials` pack hides credentials wherever they appear:

- **On sight:** JWTs, bearer tokens, GitHub, GitLab, Anthropic, OpenAI, Groq, xAI, AWS, Slack, Stripe (webhook secrets too), Google and Azure keys, PEM private key blocks, the password in `scheme://user:password@host`, and random 24+ character tokens with no prefix.
- **By name:** the value of anything named as a secret: `TOKEN=`, `"password":`, `client_secret:`, `API_KEY=`, `*_PAT=`, `Authorization:` and the like.
- **Environment dumps:** the value on each `NAME=value` line of `env`, `mise env` or a `.env` file, except settings such as numbers, `true` and `development`.

The built-in `identity` pack hides who people are, outside any one service:

- **Emails**, anywhere. Service addresses such as `git@github.com` stay visible.
- **git:** the names in `Author:`, `Commit:`, `Co-authored-by:` and similar lines, and `user.name` in `git config -l`.
- **GitHub:** the login, name, company, location and bio of a user record (`gh api user`), then the login everywhere else, URLs included.

Built-in packs for common tools:

- **`kubernetes`:** the values of a Secret's `data:` (`kubectl get secret -o yaml` or `-o json`), and client keys in a kubeconfig.
- **`docker`:** registry logins in `~/.docker/config.json`, and secret-named entries in `docker inspect`'s `Env` list.
- **`npm`:** `_authToken`, `_password` and `_auth` in `.npmrc`, for any registry.
- **`http`:** `Cookie` and `Set-Cookie` values and API key headers such as `x-api-key`, as `curl -v` prints them.
- **`gcp`:** `ya29.` access tokens, and project IDs in key files, resource paths and `--project`.
- **`pii`, off by default:** phone numbers, card numbers and IBANs that pass their checksums, IP and MAC addresses, US Social Security and UK National Insurance numbers. Turn it on with `[packs] enable = ["pii"]`.

- **`azure`:** tenant, subscription and identity IDs beside their names, people in Azure DevOps and Microsoft Graph records, your own Azure hosts, and Azure DevOps org, project and repo names. Public values Microsoft documents stay visible. See [the azure pack](https://drewtopia.github.io/redact/packs/azure).

Rules find things by where they sit (the value after `password=`, the name in an `Author:` line), so you do not list them. Every pack's rules: [drewtopia.github.io/redact/packs](https://drewtopia.github.io/redact/packs/).

## Config

`~/.config/redact/config.toml` (`%APPDATA%\redact\config.toml` on Windows; `-c` or `REDACT_CONFIG` for another file):

```toml
# Hide the values these environment variables hold. `*` matches anything.
env = ["ACME_*", "*_TOKEN"]

# Hide every value in these dotenv files, relative to where redact runs.
env_files = [".env", ".env.local", ".env.keys"]

# More packs (.toml), word lists (.txt) or folders of them, relative to this file.
import = ["customers.txt", "packs"]

# Hide who you are: your git name and email, and your GitHub login.
me = true

# Never hidden, in any case. `$NAME` reads an environment variable.
allow = ["$ACME_ORG"]

[packs]
enable = ["pii"]     # phone numbers, cards, IBANs, IPs: off by default

# Settings for one machine, folder (`dir`) or command (`--command`).
[[override]]
host = "work-laptop"
env_files = ["~/work/.env"]
```

`redact config init` writes a starter file with every setting switched off. The [config reference](https://drewtopia.github.io/redact/reference/config) covers each one.

`me` asks git for your `user.name` and `user.email` (in the repo you run it from, and globally: a work email set by an `includeIf` counts when you run redact inside that repo) and reads your GitHub logins from gh's `hosts.yml`. They are hidden everywhere as `[ME-NAME-…]`, `[ME-EMAIL-…]` and `[ME-GITHUB-…]`, so your username stops showing in GitHub URLs and remotes. Nothing to keep in sync: change your git name and redact follows.

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
| `default` | On a pack: `false` starts it switched off |
| `check` | On a rule: `"luhn"` or `"iban"`, hide a value only when it passes that checksum |

Regexes use the Rust [`regex`](https://docs.rs/regex) syntax, which runs in linear time and has no lookaround.

## Placeholders

A placeholder is `[LABEL-` + the first 8 hex characters of HMAC-SHA256(key, value) + `]`. Without `REDACT_KEY` the key is 32 random bytes made fresh for each run, so runs cannot be linked. Set `REDACT_KEY` (16+ characters, e.g. `openssl rand -hex 32`) for the same placeholder across runs in one session. Either way a placeholder cannot be worked back to its value without the key, and two values never share one.

## Docs

The full guide, every pack's rules and the CLI reference: **[drewtopia.github.io/redact](https://drewtopia.github.io/redact/)**. The pack and CLI pages are generated from the code (`REDACT_BLESS=1 cargo test`), and a test fails when they drift.

## Prior art and thanks

redact draws on rule packs from [dcg](https://github.com/Dicklesworthstone/destructive_command_guard), config imports and output masking from [fnox](https://github.com/jdx/fnox), layered config from [mise](https://mise.jdx.dev) and [worktrunk](https://github.com/max-sixty/worktrunk), `.env` hiding from [dotenvx](https://dotenvx.com), and rule field names from [gitleaks](https://github.com/gitleaks/gitleaks).

Several credential patterns are adapted from Ray Amjad's [transcript-redactor](https://github.com/ray-amjad/claude-code-mods). The Claude Code mod's event wiring follows it too. A small dotenv escape helper also closely matches fnox's implementation. Their MIT copyright and licence notices are retained in [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY). See [Prior art and thanks](docs/reference/thanks.md) for the details. Thank you to their authors.

## Licence

MIT or Apache-2.0, at your option. Third-party portions retain the notices in [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY).
