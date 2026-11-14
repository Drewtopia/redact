# With .env files

To hide every value in your dotenv files, list them in your config:

```toml
# ~/.config/redact/config.toml
env_files = [".env", ".env.local", ".env.keys"]
```

redact hides each value in those files, as `dotenvx run` does for its own output. That includes the dotenvx private keys in `.env.keys`.

A relative path is relative to where redact runs, so `.env` means the current project's `.env`. If a file is not there, `redact config ls` lists it, and redact carries on.

Each key becomes the label of its placeholder. For example, redact hides the value of `API_TOKEN` as `[API-TOKEN-…]`.

To hide one file from the command line, use `--env-file`. A missing file is then an error:

```sh
some-command | redact --env-file apps/web/.env.local
```

## What is skipped

redact hides each value everywhere it appears, so an ordinary word would be hidden all through the text. redact leaves these values alone:

- empty values
- numbers, and `true`, `false`, `yes`, `no`, `on`, `off`
- settings such as `localhost`, `development`, `production`, `debug`
- `encrypted:` values, since ciphertext gives nothing away
- `DOTENV_PUBLIC_KEY*`

## A .env that is not loaded

`cat apps/web/.env.local | redact` still hides the values, even when you run it from another folder. The `credentials` pack hides the value on every `NAME=value` line of an environment dump. See [credentials](../packs/credentials).
