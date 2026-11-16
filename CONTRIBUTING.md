# Contributing

Thank you for helping. The most useful thing you can send is a rule for a tool whose output redact does not mask yet, with a test.

## Never paste a real value

Issues, PRs and tests are public. Build every example from made-up values with the real shape: same prefix, length and characters. A way around the Claude Code mod goes to a [private report](SECURITY.md), not an issue.

## Set up

The git hooks in `lefthook.yml` run the format check and a secret scan on each commit, check each commit message against `commit-check.toml`, and run clippy and the tests before a push. `mise install` fetches the tools they use:

```sh
mise install && lefthook install # the git hooks
cargo test                       # the scanner, the packs and the generated docs
claude plugin test claude-plugin # the Claude Code mod (needs Claude Code, no account)
cargo build                      # build the real scanner for the integration tests
node --experimental-strip-types --test claude-plugin/tests/integration.test.mjs # Node 24
```

Every worktree of the repo shares one set of hooks, read from the `lefthook.yml` of the checkout you commit in, so run `lefthook install` from a checkout that has the file. To try one hook without installing them, run `lefthook run <hook> --no-auto-install`; plain `lefthook run` installs them.

CI also runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`, and builds the docs (`cd docs && npm ci && npx vitepress build`), which fails on a dead link.

## Add a rule

1. Pick the pack in `packs/` the tool belongs to (`azure.toml`, `http.toml`, ...), or start a new one with the same header.
2. Add a `[[rules]]` entry. `regex` finds it, `secretGroup` is the capture group to hide, `label` names the placeholder (`[SECRET-…]`, one of the kinds in [Labels](docs/packs/index.md#labels)), and `keywords` let redact skip the regex when none of them appear:

   ```toml
   [[rules]]
   id = "key-header"
   description = "API key headers: x-api-key, api-key, ..."
   regex = '''(?im)^[ \t]*(?:x-api-key|api-key)[ \t]*:[ \t]*(.+?)[ \t]*$'''
   secretGroup = 1
   label = "SECRET"
   keywords = ["-key", "api-key"]
   ```

3. Add `[[rules.tests]]` under the rule: made-up samples with `expect`, the values the rule hides, plus one it must leave alone (`expect = []`) where a lookalike exists. If the rule finds a value on sight, make one test's input the bare value, so it is also tried in quotes, JSON, YAML and after a literal `\n`; if it only finds values beside a name, set `matrix = false`. See [Rule tests](docs/packs/writing.md#rule-tests).
4. Run `REDACT_BLESS=1 cargo test`. It rewrites the generated pages under `docs/packs/` and `docs/reference/cli.md`, and a test fails until you do.

`redact scan --explain` shows which `pack:rule` hid each part, which helps while writing the regex.

## Pull requests

- One change per PR, titled as a [Conventional Commit](https://www.conventionalcommits.org/) (`feat(packs): ...`, `fix(scan): ...`). A check fails a title that doesn't parse.
- PRs are squash-merged, so the title becomes the commit that sets the next version and its changelog line.
- Fill in the template. A PR that changes `src/`, `packs/` or `claude-plugin/` needs a docs change too, or the `no-docs` label with a reason.
- Issues labelled `good first issue` are a good start; `ready-for-human` ones are specified and free to take.

## Versions and releases

One version covers the `redact` binary and the Claude Code mod. [release-please](https://github.com/googleapis/release-please) keeps a release PR open that bumps `Cargo.toml`, `Cargo.lock` and `claude-plugin/.claude-plugin/plugin.json` and adds to `CHANGELOG.md`. Merging that PR makes the release.

The PR title's type sets the bump. While the version is 0.x:

| Title | Bump | Changelog |
| --- | --- | --- |
| `feat!:` or `fix!:` (breaking) | 0.2.0 → 0.3.0 | yes |
| `feat:` | 0.2.0 → 0.2.1 | Features |
| `fix:`, `perf:` | 0.2.0 → 0.2.1 | Bug Fixes, Performance |
| `docs:`, `test:`, `ci:`, `chore:`, `refactor:`, `build:`, `style:` | none | no |

A change is breaking, and gets the `!`, when it:

1. Changes the placeholder format `[LABEL-xxxxxxxx]`.
2. Changes the shape of `redact scan --json`.
3. Renames or removes a config key, or makes a config that used to load fail.
4. Renames or removes a CLI command or flag, or changes what an exit code means.
5. Renames or removes a mod setting (`binary`, `restoreTools`, `notify`).
6. Hides less: removes or narrows a rule, or switches a pack off by default.
7. Renames a pack or rule id, since a user's `disable = ["pack:rule"]` then fails.

Hiding more is a `feat:`.
