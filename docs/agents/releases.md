# Releases

redact releases through release-please and the shared `drewtopia-release` App. How to make a release, retry a failed build or fix the App: the `release` skill. This page is only what differs in redact.

- **One version for two things.** release-please bumps `Cargo.toml`, `Cargo.lock`, `claude-plugin/.claude-plugin/plugin.json` and the `MOD_VERSION` line in `claude-plugin/hooks/redact.ts` together (`extra-files` in `release-please-config.json`). `release.yml` fails a tag that doesn't match both.
- **0.x rules.** `feat!:` bumps the middle number; `feat:` and `fix:` bump the last. What counts as breaking is in `CONTRIBUTING.md`.
- **Releases start as drafts.** mise's version mirror caches a published release's file list, so a release published before all six platforms' files are attached breaks installs. `release.yml` publishes only after every upload.
- **Tags stay `vX.Y.Z`** (`include-component-in-tag: false`), which is what `mise use github:Drewtopia/redact` matches.
- **Release PRs get `no-docs`**, since they touch `claude-plugin/` but change only `CHANGELOG.md` for readers.
- **The build** is `release.yml`, called by `release-please.yml`. [#53](https://github.com/Drewtopia/redact/issues/53) plans to replace it with dist.
