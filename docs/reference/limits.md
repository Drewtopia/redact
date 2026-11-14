# Limits

::: warning Work in progress
redact will miss things. Check its output before you share anything that matters. Found a leak? [Open an issue](https://github.com/Drewtopia/redact/issues) naming the command and the field, never the value.
:::

## What it misses

- **Free text.** A customer named in an issue title, a log line or a commit message is hidden only if it is in a word list, an environment variable you named, or a `.env` file. No rule can tell a customer's name from any other word.
- **Shapes no pack knows.** A service redact has no pack for shows its IDs and names. The built-in packs cover Azure, people, credentials, Kubernetes, Docker, npm, HTTP headers and Google Cloud, and personal data once `pii` is on.
- **Values without a name or shape.** A password printed on its own, with nothing like `password=` beside it, looks like any other word.
- **Transformed values.** A key that has been base64-encoded, reversed or split across lines is not recognised.
- **Case beyond ASCII.** Word matching ignores case for ASCII letters only: `ÄBC` does not match `äbc`.
- **Very short values.** To avoid hiding ordinary words everywhere, some values are skipped when short: word-list entries under 3 characters, `.env` values under 4, and values named as secrets under 6 (`password: Ab3$x` shows). A short secret needs a word list, or a longer secret.
- **Over-hiding in YAML.** A `password: |` block hides every indented line after it, which can take in the next key when that key is indented too.
- **Over-hiding with `pii` on.** Any four dotted numbers read as an IP address, so a version such as `1.2.3.4` is hidden; so is any number shaped like a phone number.
- **PDFs named with `@` in Claude Code.** The mod cannot read a PDF's text, so an `@`-mentioned PDF goes to Claude unscanned. Images too, since they reach Claude as pictures.
- **An `allow` added mid-session in Claude Code.** The mod keeps hiding a value it hid earlier in the session, wherever it turns up. Start a new session for the `allow` to take effect.
- **Random tokens with no prefix.** The `random-token` rule hides 24+ letters and digits that mix lower case, capitals and digits and score above 3.6 bits of entropy a character. It misses a token joined to a symbol (`key_…`, a path, a URL, base64 with `+` or `/`, a JSON `\n` escape), a token alone on a 64- or 76-character line (it reads as wrapped base64), and a few random tokens that happen to read as a camelCase name. It can hide a long camelCase name with two-letter words and digits, such as `convertUtf8ToUtf16StringBuffer`.
- **Over-hiding on command lines.** `PGPASSWORD=secret psql -h db -U admin` on one line hides everything after the `=`, command included, since a dump line and a command line look the same.

## What it is not

- **Not a sandbox.** It changes text. It does not stop a program, or an AI agent, from reading a file, or sending a value somewhere.
- **Not a secret scanner for repositories.** For finding secrets committed to git, use [gitleaks](https://github.com/gitleaks/gitleaks).

## What stays visible on purpose

- Bare GUIDs, such as request IDs. Only a GUID beside a name that says what it is (`tenantId`) is hidden.
- Public values a pack knows, such as the app IDs and hosts Microsoft documents for Azure.
- Settings in `.env` files: numbers, `true`, `localhost`, `development`.
- Service addresses such as `git@github.com`.
