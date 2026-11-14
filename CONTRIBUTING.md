# Contributing

Thank you for helping. The most useful thing you can send is a rule for a tool whose output redact does not mask yet, with a test.

## Never paste a real value

Issues, PRs and tests are public. Build every example from made-up values with the real shape: same prefix, length and characters. A way around the Claude Code mod goes to a [private report](SECURITY.md), not an issue.

## Set up

```sh
cargo test                       # the scanner, the packs and the generated docs
claude plugin test claude-plugin # the Claude Code mod (needs Claude Code, no account)
```

CI also runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`.

## Add a rule

1. Pick the pack in `packs/` the tool belongs to (`azure.toml`, `http.toml`, ...), or start a new one with the same header.
2. Add a `[[rules]]` entry. `regex` finds it, `secretGroup` is the capture group to hide, `label` names the placeholder (`[API-KEY-…]`), and `keywords` let redact skip the regex when none of them appear:

   ```toml
   [[rules]]
   id = "key-header"
   description = "API key headers: x-api-key, api-key, ..."
   regex = '''(?im)^[ \t]*(?:x-api-key|api-key)[ \t]*:[ \t]*(.+?)[ \t]*$'''
   secretGroup = 1
   label = "API-KEY"
   keywords = ["-key", "api-key"]
   ```

3. Add a test in `src/scan.rs` that masks a made-up sample and checks the value is gone and the text around it stays.
4. Run `REDACT_BLESS=1 cargo test`. It rewrites the generated pages under `docs/packs/` and `docs/reference/cli.md`, and a test fails until you do.

`redact scan --explain` shows which `pack:rule` hid each part, which helps while writing the regex.

## Pull requests

- One change per PR, titled as a [Conventional Commit](https://www.conventionalcommits.org/) (`feat(packs): ...`, `fix(scan): ...`).
- Fill in the template. A PR that changes `src/`, `packs/` or `claude-plugin/` needs a docs change too, or the `no-docs` label with a reason.
- Issues labelled `good first issue` are a good start; `ready-for-human` ones are specified and free to take.
