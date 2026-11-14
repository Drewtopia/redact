# How could gitleaks, Betterleaks and fnox plug into redact?

Research for [#31](https://github.com/Drewtopia/redact/issues/31), done on 2026-11-14. It feeds the design ticket [#32](https://github.com/Drewtopia/redact/issues/32).

## Answer

- **Betterleaks** is the successor to gitleaks, by the same author (Zachary Rice). It is a new codebase, not a fork: the repository started on 2026-02-03 and does not hold gitleaks' history. gitleaks is now frozen ("feature complete … security patches only") and points to Betterleaks. Both are MIT. Betterleaks is very active. v1.10.1 is the stable release, and v2 is at release candidate 8, both out this week.
- **Rule files.** gitleaks' v8 format is close to redact's pack format. redact already borrows its `regex`, `secretGroup` and `keywords` names. All 222 rules in gitleaks' default config compile under Rust's `regex` crate. Betterleaks v1 still reads the gitleaks fields. Betterleaks v2 does not: it rejects `entropy`, `allowlists` and `secretGroup`, and moves that logic into [Expr](https://expr-lang.org) expressions, which redact cannot run. Reading a gitleaks file needs a small loader plus two features redact lacks: an entropy threshold (130 of 222 rules use one) and gitleaks-style allowlists. It also has a measured trap. Compiled the way redact compiles today, the 222 regexes take about 2 s, but in ASCII mode they take 26 ms.
- **Running gitleaks as a backend** works through `gitleaks stdin`. A call took about 0.37 s here, whatever the input size. Its positions point at the whole regex match, not the secret, so redact should take the reported secret values and hide them as literal words, the way it hides `env` values. Betterleaks' latency was not measured.
- **fnox** fits redact as a source of values, not rules. Today `env = [...]` works only when the program that runs redact was itself started under `fnox exec` or a shell with fnox activated. fnox offers two direct ways in: `fnox env --json`, a subprocess that takes under 10 ms here with a warm cache, and the `fnox-client` crate, which asks the fnox daemon over a socket and never calls a provider.
- **Other tools' plugins.** trufflehog compiles its detectors into the binary and offers YAML "custom detectors" (regex, keywords, entropy, excluded words). detect-secrets loads Python classes from a file path. dcg loads YAML packs from `custom_paths` globs and validates them with `dcg pack validate`. redact's packs are already the dcg model.

**Options for #32, ranked:**

1. **Read gitleaks v8 rule files as packs.** This is native Rust and costs no process per call. It needs a loader, ASCII-mode regexes, an entropy check, and allowlist translation. The format is frozen, so it is a stable target.
2. **Read fnox values directly.** Use `fnox env --json`, or later the `fnox-client` crate. Hide the values with the existing word-list path. This is small, because the hiding path already exists.
3. **Run gitleaks or Betterleaks as an opt-in backend.** Feed it stdin, read its JSON, and hide the secret values it reports. This gives full gitleaks or Betterleaks fidelity, including Betterleaks v2's Expr filters. The cost is about 0.4 s and one extra binary per call, and redact must handle the tool being missing or failing.

**First step:** teach `src/pack.rs` to load a gitleaks TOML (an `id`-less file with `[[rules]]`) into a `Pack`. Compile it in ASCII mode with its keywords. Entropy and allowlists can follow as separate issues.

## Sources

Every repository is pinned to the commit read on 2026-11-14.

| Tool | Repository and commit | Licence |
|---|---|---|
| Betterleaks v2 (`main`) | [betterleaks/betterleaks@`b4b1c44`](https://github.com/betterleaks/betterleaks/tree/b4b1c4455987636400ce693bd9d8a8e2cf375ed9) | [MIT, "Copyright (c) 2026 Zachary Rice"](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/LICENSE) |
| Betterleaks v1 (`v1.x`) | [betterleaks/betterleaks@`39d5bdc`](https://github.com/betterleaks/betterleaks/tree/39d5bdcf34db54e944facac5cf6e8b03db5e2b99) | MIT |
| gitleaks | [gitleaks/gitleaks@`5f6ec56`](https://github.com/gitleaks/gitleaks/tree/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c) (master head, 2026-10-23), binary 8.30.1 | MIT |
| fnox | [jdx/fnox@`a5cb156`](https://github.com/jdx/fnox/tree/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9), binary 1.48.0 | MIT |
| trufflehog | [trufflesecurity/trufflehog@`32e87f4`](https://github.com/trufflesecurity/trufflehog/tree/32e87f4f3854c181d808d6e95e61ba439bb43f61) | AGPL-3.0 |
| detect-secrets | [Yelp/detect-secrets@`5e14193`](https://github.com/Yelp/detect-secrets/tree/5e141933554a0b74e7341841f318be21e895339c) | Apache-2.0 |
| dcg | [Dicklesworthstone/destructive_command_guard@`acbe066`](https://github.com/Dicklesworthstone/destructive_command_guard/tree/acbe066587e27e0acee9611400fd073ac9af530f) | [MIT with an OpenAI/Anthropic rider](https://github.com/Dicklesworthstone/destructive_command_guard/blob/acbe066587e27e0acee9611400fd073ac9af530f/LICENSE) |
| redact | [`dd21093`](https://github.com/Drewtopia/redact/tree/dd21093a146dda98a7afb8a7a8b3829a5bced47d) (`origin/main`), binary 0.2.0 | MIT / Apache-2.0 |

All timings were taken on the WSL2 work machine, best of three runs, with `/usr/bin/time`. Every test input used made-up values only.

## 1. Betterleaks

- **What it is.** "A configurable, fast, and thorough secrets scanner. It is maintained by the folks who made Gitleaks, including the original author." ([README L7](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/README.md?plain=1#L7)). Aikido Security supports its development ([L10-11](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/README.md?plain=1#L10-L11)).
- **Relation to gitleaks: successor, not a fork.** gitleaks' README opens with this warning: "Gitleaks is feature complete. I'm not merging new features into Gitleaks. Future releases will be security patches only. I'm shifting my focus to Betterleaks" ([gitleaks README L11-12](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/README.md?plain=1#L11-L12)). The Betterleaks repository is not a GitHub fork (`fork: false`). It was created on 2026-02-03 and has 367 commits on `main`. A gitleaks commit (`cd52267`, quoted in gitleaks' README) returns HTTP 422 "No commit found" from the Betterleaks repository, so gitleaks' history was not carried over. The top contributor is `zricethezav`, gitleaks' author, with 284 commits.
- **Activity.** It has 2,983 stars. The last push was 2026-11-13. The latest stable release is v1.10.1 (2026-11-12) and the latest pre-release is v2.0.0-rc.8 (2026-11-13), per `gh release list`. `main` is v2 development, and v1 is maintained on the `v1.x` branch ([README L31-37](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/README.md?plain=1#L31-L37)).
- **Rule-file format.** It is TOML, like gitleaks: `[[rules]]` with `id`, `regex`, `keywords`, `path`, `valueGroup`, `specificity`, `filter`, `validate`, `analyze`, `revoke`, `components` and `tests` ([config.md L252-281](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/config.md?plain=1#L252-L281)). Filtering and validation are Expr programs ([README L199-208](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/README.md?plain=1#L199-L208)). The default config has 476 rules: 431 have a `filter`, 425 call `entropy(...)` inside one, 240 have `validate`, and 38 have `components`.
- **v1 compared with v2.** v1's loader still accepts gitleaks' fields: `secretGroup`, `entropy`, `allowlist`/`allowlists`, `required`, `tokenEfficiency` ([v1 config.go L52-78](https://github.com/betterleaks/betterleaks/blob/39d5bdcf34db54e944facac5cf6e8b03db5e2b99/config/config.go#L52-L78)). v2 says "Unknown TOML fields now fail loading". It replaces `allowlists` with `prefilter`/`filter`, `entropy = 3.5` with `filter = 'entropy(finding.secret) <= 3.5'`, `secretGroup` with `valueGroup`, and `[[rules.required]]` with `components` ([v2 migration L195-207](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/v2_migration.md?plain=1#L195-L207)). v2 also stopped auto-loading `.gitleaks.toml` and `.betterleaks.toml` from the target ([L181-193](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/v2_migration.md?plain=1#L181-L193)).
- **Go SDK.** `scan.New(cfg)` followed by `scanner.ScanString(...)` scans a string in-process ([README L158-192](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/README.md?plain=1#L158-L192)). That is no use to a Rust binary without cgo or a sidecar process.

## 2. Can redact read their rule files as they are?

### Feature by feature

| Feature | gitleaks v8 | Betterleaks v1 | Betterleaks v2 | redact pack today |
|---|---|---|---|---|
| `regex` | Go RE2 syntax | same | same (RE2 or Go stdlib) | Rust `regex` |
| capture group | `secretGroup`; 0 means "first non-empty group" | same | `valueGroup`, same rule | `secretGroup`; 0 means the whole match |
| `keywords` | yes | yes | yes | yes, per pack and per rule |
| entropy | `entropy = 3.5`; the finding is dropped when entropy `<=` the value | yes | inside a `filter` expression | none |
| allowlists | `[[rules.allowlists]]` / `[[allowlists]]`: `regexes` with `regexTarget` (secret, match or line), `stopwords` (substring of the secret), `paths`, `commits`, `condition` (AND/OR), `targetRules` | yes | `prefilter` / `filter` expressions | `allow` (exact value), `except` (one regex on the value) |
| path rules | `path = '…'` | yes | yes | none (redact scans text, not files) |
| composite rules | `[[rules.required]]` with `withinLines` / `withinColumns` | `required` and `components` | `components` | none (`within` is the nearest) |
| inheritance | `[extend] useDefault / path / disabledRules` | same | same, at most two levels | `import`, `[packs] disable` |
| validation | none | `validate` | `validate`, `analyze`, `revoke` | none (not wanted: redact must stay offline) |
| inline allow | `gitleaks:allow` on the line | `betterleaks:allow` / `gitleaks:allow` | same | none |

Sources for the table:

- gitleaks config reference: [README L238-392](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/README.md?plain=1#L238-L392). Composite rules: [L398-406](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/README.md?plain=1#L398-L406).
- The `secretGroup` default and the entropy check are in [detect.go L519-551](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/detect.go#L519-L551).
- redact's rule fields: [src/pack.rs L58-76](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L58-L76).

**How much of gitleaks' default config uses each feature** ([config/gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml), 222 rules, counted with `grep`):

| Feature | Rules |
|---|---|
| `keywords` | 221 |
| `entropy` | 130 |
| `[[rules.allowlists]]` | 13 |
| `path` | 9 |
| explicit `secretGroup` | 1 (the other 221 rely on gitleaks' "first non-empty group") |
| global `[allowlist]` | 1 |
| `[[rules.required]]` | 0 |
| lookaheads | 0 |

### Do the regexes compile in Rust?

I parsed each config with the `toml` crate and compiled every `regex` and `path` with `regex` 1.13.1, the version redact pins. The test program was a throwaway in a scratch folder.

| Config | `Regex::new` (redact today, Unicode on) | Same, size limit raised to 1 GB | ASCII mode (`regex::bytes`, `unicode(false)`) |
|---|---|---|---|
| gitleaks, 226 patterns | 223 compile. 3 exceed the 10 MiB size limit: `generic-api-key`, `pypi-upload-token`, `vault-batch-token`. 1.8 s | all compile, 2.1 s, 150 MB RSS | all compile, **26 ms**, 5 MB |
| Betterleaks v2, 480 patterns | 476 compile, 4 too big (adds `generic-password`). 1.4 s | all compile, 3.2 s, 430 MB | all compile, **65 ms**, 10 MB |

So the syntax is compatible, and the cost is Unicode.

- Go's `\d \s \w` are "all ASCII-only" ([Go regexp/syntax](https://pkg.go.dev/regexp/syntax), "Perl character classes (all ASCII-only)").
- Rust's are Unicode by default: `\d` is `\p{Nd}` and `\w` covers all of `\p{Alphabetic}` ([regex 1.13.1 docs](https://docs.rs/regex/1.13.1/regex/#perl-character-classes-unicode-friendly)).

Compiling in ASCII mode is therefore both faster and closer to how gitleaks matches.

- **The catch:** with `unicode(false)`, 13 gitleaks patterns are refused by the `&str` API ("pattern can match invalid UTF-8"). `regex::bytes` takes all of them.
- **What it means for redact:** redact's scanner works on `&str` ([src/scan.rs L125-186](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/scan.rs#L125-L186)). It would run imported rules on `text.as_bytes()`. The byte offsets are the same.

For scale, the whole installed `redact` 0.2.0 run on a 142 KB input takes 0.13 s.

### What a gitleaks-file loader in `src/pack.rs` would need

1. **Route the file.** Today a `.toml` file with a line starting `id` is treated as a pack and parsed as `PackFile` ([L927](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L927)). A gitleaks file has `id = …` inside its rules, so it goes there and fails:
   - `PackFile` requires `schema_version` and checks that it is 1 ([L1011-1015](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L1011-L1015)).
   - `deny_unknown_fields` rejects `title`, `entropy`, `allowlists`, `path` and `tags` ([L37](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L37), [L59](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L59)).

   The loader needs its own serde shape and a way to choose it: a top-level `[[rules]]` without `schema_version`, or a config key such as `gitleaks = ["…toml"]`.
2. **Make up the pack metadata.** The pack `id` can come from the file name. The `label` can come from the rule `id`, as `label_of` already does ([L1051](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L1051)).
3. **`secretGroup` 0 means "first non-empty group", per match.** redact's `group: usize` is fixed per rule, and 0 means the whole match ([src/scan.rs L157-171](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/scan.rs#L157-L171)). 221 of the 222 rules depend on this, so the loader needs a "first non-empty" mode, for example `Option<usize>`.
4. **Compile in ASCII mode and lazily.** Today `compile()` builds every `Regex` when the file loads ([L1018](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L1018)), and redact loads on every call. ASCII mode alone brings 222 rules to 26 ms. Compiling a rule only when its keywords hit (the check at [src/scan.rs L141](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/scan.rs#L141), with a `OnceLock` per rule) would cut that further.
5. **Entropy.** gitleaks computes Shannon entropy on the secret and drops the finding when it is `<=` the threshold ([detect.go L542-551](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/detect.go#L542-L551)). This is the same feature the entropy pack issue ([#18](https://github.com/Drewtopia/redact/issues/18)) needs.
6. **Allowlists.** These map onto redact as follows:
   - `regexes` with the default target, the secret: becomes `except`, but as a list.
   - `stopwords`: a new substring test on the value. redact's `allow` is exact match only.
   - `regexTarget = "match"` / `"line"`: needs the whole match or the line at check time.
   - `condition = "AND"`: only matters together with `paths` or `commits`.
   - `paths`, `commits`, path-only rules and `targetRules` on path lists: skip them. Tool output has no file path or commit. Say so in `redact packs` rather than dropping them silently.
7. **`[extend] useDefault`** means "gitleaks' built-in config", which redact does not ship. Either vendor `gitleaks.toml` (MIT: add its notice to `LICENSE-THIRD-PARTY`, as [#22](https://github.com/Drewtopia/redact/issues/22) already found) or report it as unsupported.
8. **Betterleaks v2 files cannot be loaded this way.** Their filters are Expr programs, and there is no Expr engine in Rust in redact's dependencies. A v2 file could be read for `regex`, `keywords` and `valueGroup` only, with every `filter` dropped. But 431 of its 476 rules have a filter, so it would hide far more than Betterleaks does.

## 3. Running gitleaks or Betterleaks on each tool result

**Reading text from stdin.**

- gitleaks: `cat some_file | gitleaks -v stdin` ([README L187-189](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/README.md?plain=1#L187-L189)).
- Betterleaks: `betterleaks stdin` reads "a plain byte stream" ([scanning.md L2086-2110](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/scanning.md?plain=1#L2086-L2110)).

**Output.**

- gitleaks: `-f json -r -` writes a JSON array of findings to stdout. Each finding has `RuleID`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Match`, `Secret`, `Entropy`, `Fingerprint` and more ([README L569-603](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/README.md?plain=1#L569-L603)). It can also write CSV, JUnit, SARIF or a Go template.
- Betterleaks v2: `--output -` writes `{"schema_version":"1","findings":[…],"scan":{…}}`, and `--jsonl` writes one envelope per finding plus a final `scan` record ([scanning.md L277-297](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/scanning.md?plain=1#L277-L297), [L357-364](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/scanning.md?plain=1#L357-L364)). The secret is in `match.value`. The position is `location.start_line` / `start_column` / `end_line` / `end_column`, "one-based lines and byte columns" ([finding.schema.json L99-120](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/schemas/finding.schema.json#L99-L120)).

**Byte offsets: neither tool reports where the secret is.**

- **gitleaks:** "the location in the finding will be the line/column numbers of the _match_ not the _secret_" ([detect.go L478-482](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/detect.go#L478-L482)).
- **Betterleaks:** "Locations cover full matches" ([config.md L265-267](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/config.md?plain=1#L265-L267)).
- **Both:** they give line and column, not a byte offset into the input.
- **My probe:** I gave gitleaks 8.30.1 a two-line input whose second line has a made-up `ghp_` token after 22 bytes of text. It reported `StartColumn: 24` where a one-based column would be 23. `Line` came back empty for stdin.

The robust way in is to ignore positions. Collect each finding's `Secret` (or `match.value`) and hide every occurrence as a literal word. redact already does this for `env` and `env_files` values ([src/pack.rs L436](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L436), `WordList`). Never pass `--redact` to the tool: it masks the values redact needs.

**Exit codes.**

- **gitleaks:** 0 means no leaks, "1 - leaks or error encountered", and 126 means an unknown flag ([README L620-628](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/README.md?plain=1#L620-L628)). Findings and errors share code 1, so call it with `--exit-code 0`. Then any nonzero code is an error. Measured: 1 with a finding, 0 with none.
- **Betterleaks v2:** "Scans return exit code `1` for findings by default; `--exit-code` changes that findings exit code" ([v2 migration L48-49](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/v2_migration.md?plain=1#L48-L49)). A failed scan is marked `"state": "incomplete"` in the report ([scanning.md L299-303](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/scanning.md?plain=1#L299-L303)). Check that field as well as the exit code.

**Speed per call (gitleaks 8.30.1, default config, `stdin --no-banner -f json -r - --exit-code 0`):**

| Input | Time | Memory |
|---|---|---|
| 113 bytes | 0.37 s | 60 MB RSS |
| 142 KB | 0.35-0.40 s | 62 MB |

The cost is almost all start-up and config compilation, paid on every call. Next to redact's own 0.13 s, a gitleaks backend roughly quadruples the time per tool result. That still fits inside a few-second hook budget.

Betterleaks was **not measured**: installing it was not permitted in this session. The v2 CLI defaults to RE2 through Wazero ([v2 migration L557-571](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/docs/v2_migration.md?plain=1#L557-L571)), and its default config has twice as many rules, so expect at least gitleaks' start-up cost. That is a guess, not a measurement. Scans are offline unless `-v`/`-a` is given or `BETTERLEAKS_VALIDATE`/`BETTERLEAKS_ANALYZE` is set ([README L66-68](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/README.md?plain=1#L66-L68)). A backend call should pass `--validate=false --analyze=false` explicitly, so a user's environment never makes redact contact a credential provider.

## 4. fnox

fnox is by jdx, the author of mise. It "reads `fnox.toml` from the current directory and its parents, resolves each secret through the provider it names, and hands the values to your shell or to the command you run" (`fnox --help`, 1.48.0). It is a Cargo workspace with a binary (`fnox`) and two library crates on crates.io, `fnox-core` and `fnox-client` ([Cargo.toml](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/Cargo.toml)).

How another tool reads fnox's values:

| Way | What it does | Fit for redact |
|---|---|---|
| `fnox exec -- cmd` | Runs `cmd` with the secrets set as environment variables ([exec.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/docs/cli/exec.md)). | This is what redact's `env = [...]` relies on today ([src/pack.rs L156-158](https://github.com/Drewtopia/redact/blob/dd21093a146dda98a7afb8a7a8b3829a5bced47d/src/pack.rs#L156-L158)). But a hook runs redact, not the user's shell, so the values are there only if Claude Code itself was started under `fnox exec` or from a shell with `fnox activate` loaded. I did not check this inheritance in this research. |
| `fnox get KEY` | Prints one value ([get.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/docs/cli/get.md)). | One process per key. Too slow and chatty for "hide all of them". |
| `fnox env --json` | Prints `{"schema":1,…,"set":{KEY:value},"files":{KEY:contents},"remove":[…],"missing":[…]}`: "the machine-readable counterpart of `fnox exec`, with key selection … and a versioned schema". It exits 1 with a JSON error document on failure, and 2 on argument errors. `--describe` lists keys without resolving anything ([reference/env-json.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/docs/reference/env-json.md)). | **The best CLI fit.** It is one call that gets every value, and took under 10 ms here with a warm cache (it was 0.00 s by `/usr/bin/time` in three runs). Hide both `set` values and `files` contents. Pass `--non-interactive` so a hook never prompts. |
| `fnox export` | Values as env, shell, JSON, YAML or TOML. | The fnox docs say to use `env --json` instead: `export` "drops missing keys silently and has no schema version" (same page). |
| `fnox-client` crate | "A read-only client for the fnox daemon … in one Unix-socket (Windows named-pipe) round trip and with no fnox process." "It never starts the daemon", "never causes a provider call", checks the socket's owner, and its `Debug` never prints a value ([crates/fnox-client/README.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/crates/fnox-client/README.md)). | **The fastest fit, as a later step.** No daemon gives `EnvOutcome::Absent`, so redact would fall back to `fnox env --json`. It is a new dependency (serde, serde_json, indexmap, blake3, libc / windows-sys). |
| `fnox-core` crate | "Provider library and core types for fnox." | Pulls in every provider SDK. Not worth it for redact. |

**How it compares with redact's settings.**

- `env = ["WORK_*"]` reads redact's own environment. It costs nothing, but works only when something upstream exported the values.
- `env_files` reads dotenv files from disk.

fnox values usually live encrypted in `fnox.toml` or in a remote store, so neither setting reaches them unless they were exported. A `fnox = true` setting (or `fnox = ["WORK_*"]`, reusing `env`'s globs) that calls `fnox env --json` would reach them directly. It would feed the same word-list path `env_words` uses.

**Overlap to know about.**

- **`fnox exec --redact`.** It already replaces secret values with `[REDACTED]` in a child command's piped stdout and stderr, using Aho-Corasick literal matching and skipping values shorter than 3 characters ([exec.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/docs/cli/exec.md), [src/redact.rs L1-24](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/src/redact.rs#L1-L24)). That covers a command fnox runs, not the tool results Claude Code reads.
- **`fnox scan --values`.** It reports files that contain a resolved secret's value ([scan.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/docs/cli/scan.md)).
- **`fnox mcp`.** It serves `get_secret`/`exec` to agents ([mcp.md](https://github.com/jdx/fnox/blob/a5cb1568b9d6d0feb60cf51bb0efa325e6082dd9/docs/cli/mcp.md)). That is the opposite job to redact.

## 5. How similar tools do plugins

- **trufflehog (AGPL-3.0).**
  - Detectors are Go types compiled into the binary. Each one implements `FromData(ctx, verify, data) ([]Result, error)`, `Keywords() []string` and `Type()` ([pkg/detectors/detectors.go L23-38](https://github.com/trufflesecurity/trufflehog/blob/32e87f4f3854c181d808d6e95e61ba439bb43f61/pkg/detectors/detectors.go#L23-L38)).
  - Without rebuilding, users get "Custom Regex Detectors (alpha)". This is YAML with `keywords`, named `regex` entries, entropy, regex and excluded-word filters, and an optional `verify` webhook ([README L857-878](https://github.com/trufflesecurity/trufflehog/blob/32e87f4f3854c181d808d6e95e61ba439bb43f61/README.md?plain=1#L857-L878)). Its own example borrows gitleaks' `generic-api-key` regex ([examples/generic.yml](https://github.com/trufflesecurity/trufflehog/blob/32e87f4f3854c181d808d6e95e61ba439bb43f61/examples/generic.yml)).
  - It reads stdin with `trufflehog stdin`. Exit codes: 0 clean, 1 error, 183 findings with `--fail` ([README L715-719](https://github.com/trufflesecurity/trufflehog/blob/32e87f4f3854c181d808d6e95e61ba439bb43f61/README.md?plain=1#L715-L719)).
  - AGPL rules out vendoring its code or detectors into redact. A subprocess is the only clean route.
- **detect-secrets (Apache-2.0).**
  - Plugins are Python classes extending `BasePlugin` (`secret_type`, `analyze_line`, optional `verify`), or `RegexBasedDetector` with a `denylist` of patterns ([docs/plugins.md L1-5](https://github.com/Yelp/detect-secrets/blob/5e141933554a0b74e7341841f318be21e895339c/docs/plugins.md?plain=1#L1-L5), [plugins/base.py L28-166](https://github.com/Yelp/detect-secrets/blob/5e141933554a0b74e7341841f318be21e895339c/detect_secrets/plugins/base.py#L28-L166)).
  - An outside plugin is loaded with `--plugin path/to/file.py`. The file path is recorded in the baseline's `plugins_used` ([plugins.md L70-110](https://github.com/Yelp/detect-secrets/blob/5e141933554a0b74e7341841f318be21e895339c/docs/plugins.md?plain=1#L70-L110)).
  - This is code plugins in the host language, which a static Rust binary cannot copy.
- **dcg.**
  - Built-in packs are compiled in. Custom packs are YAML files listed by glob: `[packs] custom_paths = ["~/.config/dcg/packs/*.yaml", ".dcg/packs/*.yaml"]` ([README L566-584](https://github.com/Dicklesworthstone/destructive_command_guard/blob/acbe066587e27e0acee9611400fd073ac9af530f/README.md?plain=1#L566-L584)).
  - Each pack has `schema_version: 1`, a namespaced `id`, `keywords`, `destructive_patterns` and `safe_patterns`. `dcg pack validate` checks a file before use ([docs/custom-packs.md L1-60](https://github.com/Dicklesworthstone/destructive_command_guard/blob/acbe066587e27e0acee9611400fd073ac9af530f/docs/custom-packs.md?plain=1#L1-L60)).
  - redact's packs already follow this shape: `schema_version = 1`, `id`, `keywords`, `allow`, files loaded through `import`, and on/off through `[packs]`.
  - dcg's licence carries a rider that restricts use by "Restricted Parties", which it defines to include OpenAI and Anthropic ([LICENSE L12-44](https://github.com/Dicklesworthstone/destructive_command_guard/blob/acbe066587e27e0acee9611400fd073ac9af530f/LICENSE#L12-L44)). redact takes only the design idea from dcg, no code.

**The pattern across them:** every tool keeps a fast native rule format and opens it to user data files (YAML or TOML). Only detect-secrets runs plugin code, and only because it is Python. None of them runs another scanner as a backend.

## Not checked

- Betterleaks' run time and memory per call: install not permitted.
- Whether Claude Code passes `fnox activate` variables through to hook processes.
- The ASCII-mode loader's match results against gitleaks' own on the same input. It compiles, but I did not compare findings.
- `fnox env --json` with a cold cache or a remote provider. Only a warm local profile was timed.
