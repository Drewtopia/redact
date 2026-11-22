# Limits

::: warning Work in progress
redact will miss things. Check its output before you share anything that matters. Found a leak? [Open an issue](https://github.com/Drewtopia/redact/issues) naming the command and the field, never the value.
:::

## What it misses

- **Free text.** A customer named in an issue title, a log line, or a commit message is hidden only if it is in a word list, an environment variable you named, or a `.env` file. No rule can tell a customer's name from any other word.
- **Shapes no pack knows.** redact shows the IDs and names of a service it has no pack for. The built-in packs cover Azure, people, credentials, Kubernetes, Docker, npm, HTTP headers, and Google Cloud, plus personal data once `pii` is on.
- **Values without a name or shape.** A password printed on its own, with nothing like `password=` beside it, looks like any other word.
- **Environment values under an ordinary name.** In `env`, `mise env` or `.env` text piped to redact, a `NAME=value` line is hidden only when the name says secret, such as `GITHUB_TOKEN`, `DB_PASSWORD` or `SIGNING_KEY`, or when the value has a known token shape. So `DEPLOY_HOOK=https://hooks.example.test/x` shows. To hide such a value, name the variable in `env` or list the file in `env_files`.
- **Transformed values.** redact does not recognise a key that is base64-encoded, reversed, or split across lines.
- **Case beyond ASCII.** Word matching ignores case for ASCII letters only, so `ÄBC` does not match `äbc`.
- **Very short values.** To avoid hiding ordinary words everywhere, redact skips word-list entries under 3 characters, `.env` values under 4, and values named as secrets under 6. So `password: Ab3$x` shows. To hide a short secret, add it to a word list.
- **Personal data without a clue word.** With `pii` on, redact shows a phone number, SSN, or National Insurance number when no clue word sits on its line or the line before. Examples are the rows of a table under a `Phone` header, or `M: 07700 900123` in a signature.
- **Random tokens with no prefix.** The `random-token` rule hides 24 or more letters and digits that mix lower case, capitals, and digits, and score above 3.6 bits of entropy a character. It misses a token joined to a symbol (`key_…`, a path, a URL, base64 with `+` or `/`, a JSON `\n` escape). It misses a token alone on a 64- or 76-character line, because that reads as wrapped base64. It also misses a few random tokens that happen to read as a camelCase name: about 1 in 150 of 24 characters, fewer when longer.

- **Overrides for a removed folder, in Claude Code.** When a session's folder is removed while it runs, the mod runs redact from the nearest folder above it, so an `[[override]]` whose `dir` is the removed folder no longer applies there.

## What it hides too much

- **YAML blocks.** A `password: |` block hides every indented line after it. That can take in the next key when that key is indented too.
- **Numbers, with `pii` on.** Any four dotted numbers read as an IP address, so a version such as `1.2.3.4` is hidden. A phone-shaped number, a `123-45-6789`, and a `QQ 12 34 56 C` are hidden only beside a clue word, on the same line or the line before. Clue words include `phone`, `tel`, `mobile`, `ssn`, and `nino`; the full lists are the `context` fields in `packs/pii.toml`. So an order number on the line after `phone: …` is hidden too, and so is any phone-shaped number within 100 bytes of `"phone"` in one-line JSON.
- **camelCase names, with `random-token`.** The rule can hide a camelCase name made mostly of one- and two-letter parts and digits, where words of 3 or more letters cover under 70% of it.
- **Kubernetes Secrets in YAML.** `kubectl get secret -o yaml` hides every indented value that looks like base64, so a `name:` or label under `metadata:` made of 8 or more letters and digits, such as `sample12`, is hidden as well as `data:`. The JSON form (`-o json`) hides `data` alone.
- **Command lines.** `PGPASSWORD=secret psql -h db -U admin` on one line hides everything after the `=`, command included, because a dump line and a command line look the same.

## In integrations

Each integration has limits of its own. See [Claude Code](../integrations/claude-code#what-it-misses) and [Codex CLI](../integrations/codex).

## What it is not

- **Not a sandbox.** It changes text. It does not stop a program or an AI agent from reading a file or sending a value somewhere.
- **Not a secret scanner for repositories.** To find secrets committed to git, use [gitleaks](https://github.com/gitleaks/gitleaks).

## What stays visible on purpose

- Bare GUIDs, such as request IDs. redact hides a GUID only beside a name that says what it is, such as `tenantId`.
- Public values a pack knows, such as the app IDs and hosts Microsoft documents for Azure.
- Settings in `.env` files: numbers, `true`, `localhost`, and `development`.
- Service addresses such as `git@github.com`.
- An AI agent's own attribution: the address of an AI tool on [commit-check](https://github.com/commit-check/commit-check)'s list of known AI tool signatures, GitHub's `noreply@` address, and the name before one of them in a `Co-authored-by:` or `Author:` line, as well as an AI tool's GitHub App name, such as `cursor[bot]`. A bare name never counts, since Devin or Jules can be a person. A person's GitHub noreply address, `<id>+<login>@users.noreply.github.com`, holds their login, so it and their name stay hidden, and so does another bot's name.
- Email addresses at `example.com`, `example.org`, and `example.net`, which RFC 2606 keeps for documentation.
- Values already hidden: a mask such as `********`, a marker such as `[REDACTED]`, and redact's own tags. Redacting redacted text changes nothing.
