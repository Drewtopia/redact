# Limits

::: warning Work in progress
redact will miss things. Check its output before you share anything that matters. Found a leak? [Open an issue](https://github.com/Drewtopia/redact/issues) naming the command and the field, never the value.
:::

## What it misses

- **Free text.** A customer named in an issue title, a log line, or a commit message is hidden only if it is in a word list, an environment variable you named, or a `.env` file. No rule can tell a customer's name from any other word.
- **Shapes no pack knows.** redact shows the IDs and names of a service it has no pack for. The built-in packs cover Azure, people, credentials, Kubernetes, Docker, npm, HTTP headers, and Google Cloud, plus personal data once `pii` is on.
- **Values without a name or shape.** A password printed on its own, with nothing like `password=` beside it, looks like any other word.
- **Transformed values.** redact does not recognise a key that is base64-encoded, reversed, or split across lines.
- **Case beyond ASCII.** Word matching ignores case for ASCII letters only, so `ÄBC` does not match `äbc`.
- **Very short values.** To avoid hiding ordinary words everywhere, redact skips word-list entries under 3 characters, `.env` values under 4, and values named as secrets under 6. So `password: Ab3$x` shows. To hide a short secret, add it to a word list.

## What it hides too much

- **YAML blocks.** A `password: |` block hides every indented line after it. That can take in the next key when that key is indented too.
- **Numbers, with `pii` on.** Any four dotted numbers read as an IP address, so a version such as `1.2.3.4` is hidden. Any number shaped like a phone number is hidden too.
- **Command lines.** `PGPASSWORD=secret psql -h db -U admin` on one line hides everything after the `=`, command included, because a dump line and a command line look the same.

## What the Claude Code mod misses

- **PDFs named with `@`.** The mod cannot read a PDF's text, so an `@`-mentioned PDF goes to Claude unscanned. Images also go unscanned, because they reach Claude as pictures.
- **An `allow` added mid-session.** The mod keeps hiding a value it hid earlier in the session, wherever it turns up. Start a new session for the `allow` to take effect.

## What it is not

- **Not a sandbox.** It changes text. It does not stop a program or an AI agent from reading a file or sending a value somewhere.
- **Not a secret scanner for repositories.** To find secrets committed to git, use [gitleaks](https://github.com/gitleaks/gitleaks).

## What stays visible on purpose

- Bare GUIDs, such as request IDs. redact hides a GUID only beside a name that says what it is, such as `tenantId`.
- Public values a pack knows, such as the app IDs and hosts Microsoft documents for Azure.
- Settings in `.env` files: numbers, `true`, `localhost`, and `development`.
- Service addresses such as `git@github.com`.
- Email addresses at `example.com`, `example.org`, and `example.net`, which RFC 2606 keeps for documentation.
- Values already hidden: a mask such as `********`, a marker such as `[REDACTED]`, and redact's own tags. Redacting redacted text changes nothing.
