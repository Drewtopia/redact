# With .env files

```toml
# ~/.config/redact/config.toml
env_files = [".env", ".env.local", ".env.keys"]
```

Each value in those files is hidden, as `dotenvx run` does for its own output, including dotenvx's private keys in `.env.keys`. A relative path is relative to where redact runs, so `.env` means the current project's. A file that is not there is listed by `redact config ls`, not an error.

For one file, on the command line (a missing file is then an error):

```sh
some-command | redact --env-file apps/web/.env.local
```

## What is skipped

Hiding a value everywhere is only safe if the value is not an ordinary word. These are left alone:

- empty values
- numbers, and `true`, `false`, `yes`, `no`, `on`, `off`
- settings such as `localhost`, `development`, `production`, `debug`
- `encrypted:` values (ciphertext gives nothing away) and `DOTENV_PUBLIC_KEY*`

Each key becomes a label: `API_TOKEN=…` is hidden as `[API-TOKEN-…]`.

## A .env that is not loaded

`cat apps/web/.env.local | redact`, run from somewhere else, still hides the values: the `credentials` pack hides the value on every `NAME=value` line of an environment dump. See [credentials](../packs/credentials).
