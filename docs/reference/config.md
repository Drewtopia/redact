# Configuration

redact needs no config file. Without one, the built-in packs load on their own. A config file can add values to hide, leave values visible, pick packs, and change settings for one machine, folder, or command.

## Where it lives

| System | Path |
| :- | :- |
| Linux, macOS | `~/.config/redact/config.toml`, or `$XDG_CONFIG_HOME/redact/config.toml` |
| Windows | `%APPDATA%\redact\config.toml` |

`-c <path>` or `REDACT_CONFIG` replaces both your config file and your `packs/` folder. A project or a test then runs with only what that file names.

## Start one

`redact config init` writes a starter file. `--preset` picks which one:

| Preset | What it holds |
| :- | :- |
| `minimal` (default) | `me`, secret-named environment variables, and `.env` files, switched on |
| `full` | Everything in `minimal`, plus `.env.keys` and the `pii` pack |
| `commented` | Every setting, shown and switched off |

`--print` prints the file instead of writing it. `--force` replaces a file that is already there.

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
| `env` | Names of environment variables whose values to hide. Exact names, or patterns with `*` | [Environment variables](../guide/env) |
| `env_files` | Dotenv files whose values to hide, relative to where redact runs | [.env files](../guide/dotenv) |
| `import` | Packs, word lists, folders, and other config files to load, relative to this file. `~/` is your home folder | [Packs](../packs/) |
| `me` | Hide your git `user.name` and `user.email`, and your GitHub logins | [Hide yourself](../guide/me) |
| `allow` | Values never to hide, matched in any case. `$NAME` reads one from an environment variable | [Allow](#allow) |
| `[packs]` | `enable` and `disable` lists of pack ids. `disable` also takes one rule as `pack:rule` | [Packs](#packs) |
| `[labels]` | What placeholders say: a `style`, renames of a label, and `[labels.<pack>]` renames of a rule or word list | [Labels](#labels) |
| `[[override]]` | Settings for one machine, folder, or command | [Overrides](#overrides) |

In a symlinked config, an `import` path is relative to the file the link points to.

An unknown setting is an error, so redact reports a typo such as `imports` instead of ignoring it.

## Allow

`allow` leaves a value visible even when a rule or a word list would hide it. Typical values are your own organisation's name, so links that contain it still work, and a public product name that a word list catches. `allow` covers the value itself, never the text next to it.

`$NAME` reads the value from an environment variable, so the config file itself names nothing:

```toml
allow = ["$ACME_ORG"]
```

A variable that is not set allows nothing. `redact config ls` lists it as not set.

## Packs

Every pack is on unless it says `default = false`, as [`pii`](../packs/pii) does. `[packs]` changes that:

```toml
[packs]
enable = ["pii"]
disable = ["gcp"]
```

`disable` also switches off a single rule, named `pack:rule` as `redact scan --explain` prints it, for example `pii:ipv4`. The rest of the pack keeps running. `redact packs` lists each pack's rules.

`disable` wins over `enable`. A name that matches no pack and no `pack:rule` is an error, and the error lists the packs that exist. `redact packs` also shows switched-off packs, marked `off`.

## Labels

A placeholder's label says what kind of thing it hides, such as `[SECRET-…]` or `[PERSON-…]`. [Labels](../packs/#labels) lists them. `[labels]` changes what they say. Leave it out and nothing changes.

```toml
[labels]
style = "generic"              # every placeholder is [HIDDEN-…]
HIDDEN = "REDACTED"            # ...or rather [REDACTED-…]

[labels.credentials]           # except GitHub tokens
github-token = "GH-TOKEN"

[labels.words]                 # and the customers.txt list
customers = "CUSTOMER"
```

| Key | What it does |
| :- | :- |
| `style` | The label each placeholder starts from. `"kind"`, the default, is the rule's own label. `"rule"` is the rule id (`[GITHUB-TOKEN-…]`), or a word list's file name or a variable's name. `"generic"` is `HIDDEN` |
| A label | Renames that label, as the style gives it: `SECRET = "CREDENTIAL"` |
| `[labels.<pack>]` | Renames one rule in that pack, by the id `redact packs` lists: `github-token = "GH-TOKEN"`. Under `[labels]`, `credentials.github-token = "GH-TOKEN"` is the same key. `redact scan --explain` adds the label it had before, as `(was SECRET)` |
| `[labels.words]` | Renames one word list, `env` variable, or dotenv key: `customers = "CUSTOMER"`, `ACME_ORG = "ORG"`. Word lists, `env` and `env_files` are the `words` pack, so no pack can take that id |

The most specific key wins: a rule or word list in a pack's table, then a label, then the style. Keys match in any case.

A label is letters and digits, starts with a letter, may join words with one `-` or `_` (`GH-TOKEN`), and is not `LITERAL`, which the Claude Code mod keeps for itself. Anything else is an error. In `"rule"` style, a rule id or file name that does not fit is folded to fit: `v1.2_key` becomes `V1-2-KEY`. So is a key that names no label the style gives and no rule, and the error lists the labels that exist. A `[labels.words]` key that matches nothing is not an error, as a variable can be set on one machine and not another.

`"rule"` style and `[labels.words]` renames put a name in every placeholder. A file name such as `acme-customers.txt` can say what the list hides, so use them only for names you are happy for the model to see.

`redact scan --explain` shows each label `[labels]` changed with the one it had before:

```text
credentials:github-token -> [GH-TOKEN-…] (was SECRET)
p:VALUE -> [HIDDEN-…] (was ID)
```

A rule id, pack id or list name that holds something being hidden reads `VALUE`, as `p:VALUE` does here, so `--explain` never prints the value. The label before still shows, and reads `VALUE` too if it holds the value.

## Overrides

An `[[override]]` applies its settings only when every condition it gives matches. Each condition is a glob, in which `*` matches anything:

| Condition | Matches |
| :- | :- |
| `host` | The machine's name, in any case. redact reads `COMPUTERNAME` on Windows, and `HOSTNAME` or the `hostname` command elsewhere |
| `dir` | The folder redact runs in, and every folder below it. `~/` is your home folder |
| `command` | The command named by `--command` or `REDACT_COMMAND` |

An override with no condition always applies. An override can set `env`, `env_files`, `allow`, `[override.packs]`, and `[override.labels]`, and each one adds to the settings before it. In `[override.labels]`, a key replaces the same key set before it. Overrides apply in file order, after the top-level settings. `redact config ls` lists each override that applied, and why.

redact cannot see the command whose output it reads. A hook or an alias that knows the command passes it on:

```sh
gh pr view 42 | redact scan --command "gh pr view 42"
```

## Load order

1. The built-in packs: `azure`, `identity`, `kubernetes`, `docker`, `npm`, `http`, `gcp`, `credentials`, and `pii`, which is off.
2. Every `.toml` and `.txt` in `~/.config/redact/packs/`.
3. The config file and everything it imports, in order, then each override that applies.
4. `--file` and `--env-file` from the command line.

`[packs]` choices apply last, to the packs from all four steps. Each pack id loads once: a second pack with an id already loaded, or a pack file named twice, stops the load with an error naming both (see [Pick a pack id](../packs/writing#pick-a-pack-id)). Two flags change the order:

- `--only-files` skips steps 1 to 3.
- `-c` replaces steps 2 and 3.

`redact config ls` prints what loaded, in this order, and what imported each file. It lists a packs folder or a config file that is not there as `missing`. With `--json`, it prints one object per file, with the fields `kind`, `path`, `detail`, `via`, and `found`.

## Environment variables

| Variable | What it does |
| :- | :- |
| `REDACT_CONFIG` | Use this config file, as `-c` does |
| `REDACT_COMMAND` | The command whose output is being read, as `--command` does |
| `REDACT_KEY` | Key for placeholder tags, so the same value gets the same tag across runs. At least 16 characters. See [How it works](./how-it-works) |
