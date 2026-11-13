# Configuration

redact runs with no config at all: the built-in packs load on their own. A config file adds your own.

## Where it lives

| System | Path |
| :- | :- |
| Linux, macOS | `~/.config/redact/config.toml` (or `$XDG_CONFIG_HOME/redact/config.toml`) |
| Windows | `%APPDATA%\redact\config.toml` |

`-c <path>` or `REDACT_CONFIG` uses another file instead.

## A full example

```toml
# Hide the values these environment variables hold. `*` matches anything.
env = ["WORK_*", "*_TOKEN", "AZURE_ORGANISATION"]

# Hide every value in these dotenv files, relative to where redact runs.
env_files = [".env", ".env.local", ".env.keys"]

# More packs (.toml), word lists (.txt) or folders of them, relative to this file.
import = ["~/work/customers.txt", "packs"]

# Hide who you are: your git name and email, and your GitHub login.
me = true
```

## Settings

| Setting | What it does | Guide |
| :- | :- | :- |
| `env` | Names of environment variables whose values to hide. Exact names, or patterns with `*` | [fnox and mise](../guide/fnox-mise) |
| `env_files` | Dotenv files whose values to hide, relative to where redact runs | [.env files](../guide/dotenv) |
| `import` | Packs, word lists, folders and other config files to load, relative to this file. `~/` is your home folder | [Packs](../packs/) |
| `me` | Hide your git `user.name` and `user.email` and your GitHub logins | [Hiding yourself](../guide/me) |

An unknown setting is an error, so a typo such as `imports` is caught rather than ignored.

## Load order

1. The built-in packs: `azure`, `identity`, `credentials`.
2. Every `.toml` and `.txt` in `~/.config/redact/packs/`.
3. The config file, and everything it imports, in order.
4. `--file` and `--env-file` from the command line.

`--only-files` skips 1 to 3. `redact config ls` prints what loaded, in this order, and what imported each file.

## Environment variables

| Variable | What it does |
| :- | :- |
| `REDACT_CONFIG` | Use this config file |
| `REDACT_KEY` | Key for placeholder tags, so the same value gets the same tag across runs. 16+ characters. See [How it works](./how-it-works) |
