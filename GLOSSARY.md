# Glossary

Words this project uses with one meaning. Code, docs and issues use them this way.

- **Placeholder** (also **tag**): what a hidden value becomes, `[LABEL-<8 hex>]`, such as `[SECRET-a1b2c3d4]`. The hex comes from an HMAC of the value, so the same value gets the same placeholder within a run, or across runs that share `REDACT_KEY`. `src/label.rs` owns the shape.
- **Label**: the word in a placeholder that says what kind of thing is hidden. Letters and digits, words joined by `-`. Never a name that could say whose value it is.
- **Kind**: the label a rule gives before `[labels]` changes it. `--explain` shows it as `(was …)`.
- **Literal**: a placeholder the Claude Code mod mints, `[LITERAL-…]`, for placeholder text read back from a file. It restores to that text, never to a value. No other label may be `LITERAL`.
- **Pack**: a set of rules in one TOML file, built in or your own, switched on and off as a whole or rule by rule.
- **Rule**: one regex in a pack, with what to hide (`secretGroup`), its label, and the checks that keep it from firing on the wrong text.
- **Word list**: words or phrases to hide wherever they appear: a `.txt` file, an `env` variable's value, or a dotenv value. In `[labels]` and `--explain` they are the `words` pack.
- **Span**: one part of a text to hide, as byte offsets, with the label, pack and rule that found it. It never holds the value, so `--json` output is safe to log.
