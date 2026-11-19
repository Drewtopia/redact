# Hide .env files

To hide every value in your dotenv files, list them in your config:

```toml
# ~/.config/redact/config.toml
env_files = [".env", ".env.local", ".env.keys"]
```

redact reads those files itself and hides each value, whatever tool uses them. That includes the private keys that dotenvx keeps in `.env.keys`.

A relative path is relative to where redact runs, so `.env` means the current project's `.env`. If a file is not there, `redact config ls` lists it, and redact carries on.

Each value hides as `[ENV-VALUE-…]`. The key stays out of the placeholder, as a key such as `ACME_API_TOKEN` can say whose value it is. `redact scan --explain` still names the key.

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

`cat apps/web/.env.local | redact` hides only the values whose name says secret, such as `*_TOKEN`, `*_PASSWORD` or `*_KEY`, and values shaped like a known token. To hide every value in the file, list it in `env_files`. See [credentials](../packs/credentials).
