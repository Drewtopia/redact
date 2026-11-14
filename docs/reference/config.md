# Configuration

redact runs with no config at all: the built-in packs load on their own. A config file adds your own values, leaves others visible, picks packs, and changes settings by machine, folder or command.

## Where it lives

| System | Path |
| :- | :- |
| Linux, macOS | `~/.config/redact/config.toml` (or `$XDG_CONFIG_HOME/redact/config.toml`) |
| Windows | `%APPDATA%\redact\config.toml` |

`-c <path>` or `REDACT_CONFIG` uses another file instead of your config and your `packs/` folder, so a project or a test can run with only what it names.

## Start one

```sh
redact config init
```

writes a starter file. `--preset` picks which:

| Preset | What it holds |
| :- | :- |
| `minimal` (default) | `me`, secret-named environment variables, `.env` files: on |
| `full` | the same plus `.env.keys` and the `pii` pack: on |
| `commented` | every setting shown and switched off |

`--print` shows it without writing; `--force` replaces a file that is already there.

## A full example

```toml
# Hide the values these environment variables hold. `*` matches anything.
env = ["ACME_*", "*_TOKEN", "DATABASE_URL"]

# Hide every value in these dotenv files, relative to where redact runs.
env_files = [".env", ".env.local", ".env.keys"]

# More packs (.toml), word lists (.txt) or folders of them, relative to this file.
import = ["~/work/customers.txt", "packs"]

# Hide who you are: your git name and email, and your GitHub login.
me = true

# Never hidden, in any case. `$NAME` reads an environment variable.
allow = ["Contoso", "$ACME_ORG"]

[packs]
enable = ["pii"]     # packs that start switched off
disable = ["gcp"]    # packs you do not want

# On the work laptop only: hide the values in the work .env as well.
[[override]]
host = "work-laptop"
env_files = ["~/work/.env"]

# For `gh pr` output: the people are already in the PR, so leave them.
[[override]]
command = "gh pr *"
[override.packs]
disable = ["identity"]
```

## Settings

| Setting | What it does | Guide |
| :- | :- | :- |
| `env` | Names of environment variables whose values to hide. Exact names, or patterns with `*` | [fnox and mise](../guide/fnox-mise) |
| `env_files` | Dotenv files whose values to hide, relative to where redact runs | [.env files](../guide/dotenv) |
| `import` | Packs, word lists, folders and other config files to load, relative to this file (for a symlinked config, the file it points to). `~/` is your home folder | [Packs](../packs/) |
| `me` | Hide your git `user.name` and `user.email` and your GitHub logins | [Hiding yourself](../guide/me) |
| `allow` | Values never to hide, matched in any case. `$NAME` reads one from an environment variable | [Allow](#allow) |
| `[packs]` | `enable` and `disable` lists of pack ids | [Packs](#packs) |
| `[[override]]` | Settings for one machine, folder or command | [Overrides](#overrides) |

An unknown setting is an error, so a typo such as `imports` is caught rather than ignored.

## Allow

`allow` leaves a value visible even when a rule or a word list would hide it: your own organisation's name, so links that contain it still work, or a public product name a word list catches. It allows the value itself, never what sits next to it.

`$NAME` reads the value from an environment variable, so the config file itself names nothing:

```toml
allow = ["$ACME_ORG"]
```

A variable that is not set allows nothing, and `redact config ls` lists it as not set.

## Packs

Every pack is on unless it says `default = false`, as [`pii`](../packs/pii) does. `[packs]` changes that:

```toml
[packs]
enable = ["pii"]
disable = ["gcp"]
```

`disable` wins over `enable`. A name that is no pack is an error that lists the packs there are. `redact packs` shows switched-off packs too, marked `off`.

## Overrides

An `[[override]]` applies its settings only when every condition it gives matches. Each condition is a glob, `*` matching anything:

| Condition | Matches |
| :- | :- |
| `host` | The machine's name, in any case (`COMPUTERNAME` on Windows, `HOSTNAME` or the `hostname` command elsewhere) |
| `dir` | The folder redact runs in, and every folder below it. `~/` is your home folder |
| `command` | The command named by `--command` or `REDACT_COMMAND` |

An override with no condition always applies. It may set `env`, `env_files`, `allow` and `[override.packs]`; each adds to what came before. Overrides apply in file order, after the settings above them, and `redact config ls` lists each one that applied and why.

redact cannot see the command whose output it reads, so a hook or alias that knows it passes it on:

```sh
gh pr view 42 | redact scan --command "gh pr view 42"
```

## Load order

1. The built-in packs: `azure`, `identity`, `kubernetes`, `docker`, `npm`, `http`, `gcp`, `credentials`, `pii` (off).
2. Every `.toml` and `.txt` in `~/.config/redact/packs/`.
3. The config file, and everything it imports, in order; then each override that applies.
4. `--file` and `--env-file` from the command line.

`[packs]` choices apply last, to every pack from 1 to 4. `--only-files` skips 1 to 3; `-c` replaces 2 and 3. `redact config ls` prints what loaded, in this order, and what imported each file.

## Environment variables

| Variable | What it does |
| :- | :- |
| `REDACT_CONFIG` | Use this config file, as `-c` does |
| `REDACT_COMMAND` | The command whose output is being read, as `--command` does |
| `REDACT_KEY` | Key for placeholder tags, so the same value gets the same tag across runs. 16+ characters. See [How it works](./how-it-works) |
