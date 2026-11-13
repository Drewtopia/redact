# Limits

::: warning Work in progress
redact will miss things. Check its output before you share anything that matters. Found a leak? [Open an issue](https://github.com/Drewtopia/redact/issues) naming the command and the field, never the value.
:::

## What it misses

- **Free text.** A customer named in a work item's title, a pipeline's name or a commit message is hidden only if it is in a word list, an environment variable you named, or a `.env` file. No rule can tell a customer's name from any other word.
- **Shapes no pack knows.** A service redact has no pack for shows its IDs and names. The built-in packs cover Azure, people and credentials.
- **Values without a name or shape.** A password printed on its own, with nothing like `password=` beside it, looks like any other word.
- **Transformed values.** A key that has been base64-encoded, reversed or split across lines is not recognised.
- **Case beyond ASCII.** Word matching ignores case for ASCII letters only: `ÄBC` does not match `äbc`.

## What it is not

- **Not a sandbox.** It changes text. It does not stop a program, or an AI agent, from reading a file, or sending a value somewhere.
- **Not a secret scanner for repositories.** For finding secrets committed to git, use [gitleaks](https://github.com/gitleaks/gitleaks).

## What stays visible on purpose

- Bare GUIDs, such as request IDs. Only a GUID beside a name that says what it is (`tenantId`) is hidden.
- Public values Microsoft documents: well-known app and role IDs, `AzureCloud`, `portal.azure.com`.
- Settings in `.env` files: numbers, `true`, `localhost`, `development`.
- Service addresses such as `git@github.com`.
