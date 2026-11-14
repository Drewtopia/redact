# Prior art and thanks

redact draws on the projects below. Thank you to their authors. [Third-party notices](#third-party-notices) covers the credential patterns adapted from transcript-redactor and the code that overlaps with fnox.

| Project | Contribution |
| :- | :- |
| [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) | Rule packs with a keyword pre-check, community packs on top of built-in ones, and refusing a pack that will not load. dcg guards the commands an agent runs; redact guards the text it reads |
| [transcript-redactor](https://github.com/ray-amjad/claude-code-mods) by Ray Amjad | The idea of stable placeholders, and adapted credential patterns for Entra client secrets, Azure storage keys and SAS signatures. The Claude Code mod's event wiring and its guards on restored values. MIT notice retained below |
| [fnox](https://github.com/jdx/fnox) | Config imports resolved beside the file that names them, and `fnox exec --redact` masking values in output. The dotenv escape helper also closely matches fnox's implementation. MIT notice retained below |
| [mise](https://mise.jdx.dev) | Layered config files and a command that lists which ones loaded |
| [worktrunk](https://github.com/max-sixty/worktrunk) | Config layers merged in a fixed order, and typos in config reported rather than ignored |
| [dotenvx](https://dotenvx.com) | Hiding every value in a `.env` file, `.env.keys` included |
| [gitleaks](https://github.com/gitleaks/gitleaks) | The `regex`, `keywords` and `secretGroup` field names of its rule files |

The docs are built with [VitePress](https://vitepress.dev).

## Third-party notices

`packs/credentials.toml` adapts credential patterns from [transcript-redactor's detector](https://github.com/ray-amjad/claude-code-mods/blob/467b20300d8ec56e24fb0534befb4d1f51dc6b92/plugins/transcript-redactor/hooks/detect.ts), version 0.4.1, by Ray Amjad.

The `unescape` helper in `src/pack.rs` closely matches [fnox's `unescape_double_quoted` helper](https://github.com/jdx/fnox/blob/cb634672672d3ad031ddefef832d32b407dd55ad/crates/fnox-core/src/providers/onepassword.rs#L657). Similarity alone does not establish that it was copied. The fnox MIT notice is retained conservatively for this overlap.

The complete copyright and licence notices are in [LICENSE-THIRD-PARTY](https://github.com/Drewtopia/redact/blob/main/LICENSE-THIRD-PARTY), which is also included in release archives. These notices accompany the project's own MIT and Apache-2.0 licences.
