# What dist would change in redact's release build

Research for [#21](https://github.com/Drewtopia/redact/issues/21). Checked 2026-11-14 against dist 0.34.0 and mise v2026.11.8.

## Short answer

dist can replace all of `.github/workflows/release.yml` and keep mise working. The asset names lose the version (`redact-v0.2.0-x86_64-unknown-linux-musl.tar.gz` becomes `redact-x86_64-unknown-linux-musl.tar.xz`). mise does not need the version in the name, because it picks an asset by OS and CPU. Releases still only go public once every binary is attached. dist does not need crates.io. Homebrew needs a separate tap repo plus a token, but only if you want `brew install` to work.

Watch out for three things:

1. `publish = false` in `Cargo.toml` hides redact from dist. You have to add `dist = true`.
2. `dist init --yes` adds two `-gnu` Linux targets on its own.
3. `release.yml` becomes a generated file. Hand edits make dist report an error.

## How this was checked

- Read the docs at `axodotdev.github.io/cargo-dist`. The `opensource.axo.dev` domain named in the ticket no longer resolves (DNS `ENOTFOUND`), and the repo's homepage field now points at the GitHub Pages site.
- Read dist's own generated workflow and `dist-workspace.toml`, and `init.rs`, in [axodotdev/cargo-dist](https://github.com/axodotdev/cargo-dist). The repo is not archived, and v0.34.0 was released 2026-11-02.
- Read mise's github backend docs and source at tag v2026.11.8.
- Ran dist 0.34.0 against a scratch copy of `origin/main`: `dist init`, then `dist generate`, then `dist plan`. Nothing was committed from that run. dist itself was installed with `mise x github:axodotdev/cargo-dist@0.34.0`, which means mise installed a release that dist built, using dist's naming.

## 1. What dist replaces in release.yml

The current workflow ([.github/workflows/release.yml](../.github/workflows/release.yml)) has four parts:

| Today | With dist |
|---|---|
| `create-release`: checks that the tag matches the Cargo.toml version, then makes a draft release with `taiki-e/create-gh-release-action` | The `plan` job runs `dist plan`/`dist host --steps=create`. A tag that matches no package version fails. `--tag v9.9.9` gave "This workspace doesn't have anything for dist to Release! … --tag=v0.2.0 will Announce: redact" (scratch run). |
| `upload-assets`: a 6-target matrix running `taiki-e/upload-rust-binary-action` | `build-local-artifacts`, a matrix generated from `targets`, plus `build-global-artifacts`, which builds the installers, `sha256.sum` and the source tarball |
| `publish-release`: `gh release edit --draft=false` | The `host` job creates the release in one `gh release create … artifacts/*` call, after every build has succeeded |
| (none) | `announce`, and optional `publish-homebrew-formula`/npm jobs |

The generated file is 296 lines. It uses only `actions/checkout`, `actions/upload-artifact` and `actions/download-artifact`, so no taiki-e actions remain. It installs dist with `curl … cargo-dist-installer.sh | sh` and Rust with `rustup` (scratch run, generated `release.yml:67`, `:127`).

Things that change:

- **The file is generated.** "Since 0.3.0, dist considers any edits or out of date information in release.yml an error". You can opt out with `allow-dirty = ["ci"]`, but the docs warn against it ([customizing CI](https://axodotdev.github.io/cargo-dist/book/ci/customizing.html)). Customise through config instead. Custom jobs go in `plan-jobs`, `build-local-artifacts-jobs`, `host-jobs`, `publish-jobs` and `post-announce-jobs`, written as reusable workflows (same page). The tag check and the comments explaining why the workflow drafts first both disappear from the file.
- **Pins.** The default output pins actions by major tag (`actions/checkout@v6`), but today's workflow pins by SHA. dist's own config does SHA pinning through `[dist.github-action-commits]`, for example `"actions/checkout" = "3d3c…" # v7.0.1` ([dist-workspace.toml](https://github.com/axodotdev/cargo-dist/blob/v0.34.0/dist-workspace.toml)).
- **Permissions.** The generated file sets `permissions: contents: write` for the whole workflow. Today it is `contents: read` at the top, with write granted per job. The jobs that hold write access run unpinned `curl | sh` installs.
- **New `pull_request:` trigger.** `pr-run-mode` defaults to `"plan"`, so every PR runs `dist plan`. Use `pr-run-mode = "skip"` to drop it ([config reference](https://axodotdev.github.io/cargo-dist/book/reference/config.html)).
- **Tag glob.** The tag pattern widens from `v[0-9]+.[0-9]+.[0-9]+*` to `'**[0-9]+.[0-9]+.[0-9]+*'`.

## 2. Does mise's `github:` backend still find the assets?

Yes. The scratch `dist plan` for v0.2.0 with the six targets listed:

```
redact-aarch64-apple-darwin.tar.xz        + .tar.xz.sha256
redact-aarch64-pc-windows-msvc.zip        + .zip.sha256
redact-aarch64-unknown-linux-musl.tar.xz  + .tar.xz.sha256
redact-x86_64-apple-darwin.tar.xz         + .tar.xz.sha256
redact-x86_64-pc-windows-msvc.zip         + .zip.sha256
redact-x86_64-unknown-linux-musl.tar.xz   + .tar.xz.sha256
redact-installer.sh, redact-installer.ps1, sha256.sum, source.tar.gz(.sha256)
```

Each archive holds `redact` plus `LICENSE-APACHE`, `LICENSE-MIT`, `LICENSE-THIRD-PARTY` and `README.md`, through dist's auto-includes ([archives](https://axodotdev.github.io/cargo-dist/book/artifacts/archives.html)). That keeps the licence files today's `include:` adds.

Why mise still works:

- **Picking the asset.** mise does not match a name template. It scores assets on OS, CPU architecture and libc (glibc/musl, MSVC on Windows) and rewards archive formats it extracts well. Checksum and signature files are penalised, and a tie goes to the shortest name ([mise github backend](https://mise.jdx.dev/dev-tools/backends/github.html)). The version in the asset name was never needed. In the source, `score_format_preferences` ranks "zstd over xz over other tarballs" ([asset_matcher.rs](https://github.com/jdx/mise/blob/v2026.11.8/src/backend/asset_matcher.rs), around line 606), so `.tar.xz` scores higher than today's `.tar.gz`.
- **Checksums.** `find_checksum_for` tries `<asset><ext>` and `<asset minus archive suffix><ext>` for `.sha256` and its variants, then falls back to patterns like `sha256sums.txt`/`checksums.txt` ([asset_matcher.rs](https://github.com/jdx/mise/blob/v2026.11.8/src/backend/asset_matcher.rs), around lines 911–1070). So it matches both today's `redact-v0.2.0-<triple>.sha256` and dist's `redact-<triple>.tar.xz.sha256`. mise also verifies against the SHA-256 digest that GitHub's API reports for every asset, and against artifact attestations when a release has them ([docs](https://mise.jdx.dev/dev-tools/backends/github.html)).
- **Seen working.** `mise x github:axodotdev/cargo-dist@0.34.0` installed and ran `cargo-dist 0.34.0` on Linux. That release uses exactly this layout: `cargo-dist-<triple>.tar.xz` with `.tar.xz.sha256` beside it ([release assets](https://github.com/axodotdev/cargo-dist/releases/tag/v0.34.0)). Windows `.zip` selection was not run, only inferred from the same scoring.
- **Old releases.** v0.1.0 and v0.2.0 keep their old names. mise picks an asset per release, so mixed naming across versions is fine.
- **This repo's docs.** No page in the README, `docs/` or `claude-plugin/` mentions asset file names or `asset_pattern`. They only say `mise use -g github:Drewtopia/redact` (README.md:24, docs/guide/getting-started.md:8, docs/guide/fnox-mise.md:51, claude-plugin/hooks/redact.ts:16), and that command keeps working.

## 3. Draft-then-publish and the six targets

**Draft-then-publish is kept, by a different route.** dist creates no release at the start. The `host` job runs only when `plan` and every build succeeded, then runs `gh release create "$TAG" … artifacts/*` ([dist's release.yml](https://github.com/axodotdev/cargo-dist/blob/v0.34.0/.github/workflows/release.yml), `host` job). The gh CLI itself handles the draft. "When you attach assets, gh release create creates a draft release, uploads" them, then publishes. If an upload fails it deletes the draft (`draftWhileUploading`/`cleanupDraftRelease` in [cli/cli create.go](https://github.com/cli/cli/blob/trunk/pkg/cmd/release/create/create.go), around lines 117 and 501–562). So mise's version mirror never sees a published release with only some of its assets, which is the reason today's workflow drafts first. If you want an explicit draft job anyway, set `create-release = false`: dist then "will assume a draft Github Release for the current git tag already exists" and "at the end of a successful publish it will undraft" it ([customizing CI](https://axodotdev.github.io/cargo-dist/book/ci/customizing.html)).

**The six targets are kept, but you must list them.** `dist init --yes` with the six `-t` flags still wrote eight targets, adding `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. Set `targets` by hand. Runners chosen by `dist plan` in the scratch run:

| Target | Runner | How it builds |
|---|---|---|
| x86_64-unknown-linux-musl | ubuntu-22.04 | native, `apt-get install musl-tools` |
| aarch64-unknown-linux-musl | ubuntu-22.04-arm | native arm, musl-tools |
| x86_64-apple-darwin | macos-15-intel | native |
| aarch64-apple-darwin | macos-15 | native |
| x86_64-pc-windows-msvc | windows-2022 | native |
| aarch64-pc-windows-msvc | ubuntu-22.04 | cross-built with `cargo-xwin` (pip-installed) |

Today aarch64 Windows builds on `windows-latest`. Use `github-custom-runners` to put it on the native `windows-11-arm` runner ([customizing CI](https://axodotdev.github.io/cargo-dist/book/ci/customizing.html)). dist builds with the `[profile.dist]` it adds, and `rust-toolchain.toml` (1.99.1) still applies. Neither was test-built in CI here.

## 4. Config dist adds

`dist init` on a new Rust project writes `dist-workspace.toml`, not `[workspace.metadata.dist]`: "Migrations and newly-initted setups always use dist-workspace.toml" ([init.rs](https://github.com/axodotdev/cargo-dist/blob/v0.34.0/cargo-dist/src/init.rs), around line 331). The Rust quickstart page still says Cargo.toml, but that page is out of date. The scratch run gives, after trimming the targets:

```toml
# dist-workspace.toml
[workspace]
members = ["cargo:."]

[dist]
cargo-dist-version = "0.34.0"
ci = "github"
installers = ["shell", "powershell"]
targets = ["aarch64-apple-darwin", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
           "x86_64-apple-darwin", "x86_64-unknown-linux-musl", "x86_64-pc-windows-msvc"]
install-path = "CARGO_HOME"
install-updater = false
```

```toml
# Cargo.toml additions
[profile.dist]
inherits = "release"
lto = "thin"

[package.metadata.dist]
dist = true   # required: see below
```

**`publish = false` hides redact.** Before `dist = true` was added, `dist generate` failed with "This workspace doesn't have anything for dist to Release! … `publish = false` could be hiding them and adding "dist = true" to [package.metadata.dist] in your Cargo.toml may help" (scratch run). The troubleshooting page says the same: "dist assumes you don't want to release `publish = false` packages" ([troubleshooting](https://axodotdev.github.io/cargo-dist/book/troubleshooting.html)). Keep `publish = false`, since the name `redact` is taken on crates.io, and add `dist = true`.

Likely extras to keep today's behaviour: `pr-run-mode = "skip"`, `[dist.github-action-commits]` SHA pins, and `github-custom-runners` for aarch64 Windows. `install-path = "CARGO_HOME"` is where the curl|sh and PowerShell installers put the binary (`~/.cargo/bin`).

## 5. Does it need crates.io?

No. The Rust quickstart lists "publish to crates.io (optional)" as one step of the example flow ([quickstart](https://axodotdev.github.io/cargo-dist/book/quickstart/rust.html)). dist builds from the git checkout. None of the generated jobs touch crates.io unless you add a custom publish job, as dist's own repo does with `./publish-crates`.

## 6. Does Homebrew need a separate tap repo?

To make `brew install` work, yes. Publishing "requires you to create your own Homebrew tap", meaning a repo named `homebrew-tap` (here `Drewtopia/homebrew-tap`). You also set `tap = "Drewtopia/homebrew-tap"`, `publish-jobs = ["homebrew"]`, and a personal access token with `repo` scope stored as the `HOMEBREW_TAP_TOKEN` secret ([Homebrew installer](https://axodotdev.github.io/cargo-dist/book/installers/homebrew.html)). Without a tap, the scratch `dist plan` with `installers = [..., "homebrew"]` still produced a `redact.rb` formula as a release asset, with no warning. But no tap repo means nothing for `brew` to find. The shell and PowerShell installers need nothing extra: they are plain release assets that download from GitHub Releases.

## Open points not checked here

- No real CI run. Builds on the musl and `cargo-xwin` paths were planned but not compiled.
- Windows asset selection in mise was inferred from source, not run on Windows.
