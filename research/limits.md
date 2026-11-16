# Which of redact's limits can be lifted or narrowed?

Research done on 2026-11-16 against `origin/main` at `1141ad0`. It covers every limit listed in [docs/reference/limits.md](../docs/reference/limits.md), [docs/integrations/claude-code.md](../docs/integrations/claude-code.md) and [docs/integrations/codex.md](../docs/integrations/codex.md).

## Answer

Most engine limits are a trade between hiding too little and hiding too much. About half can be narrowed cheaply. Three are inherent: free text, values with no name or shape, and "not a sandbox". The integration limits have moved more than the docs say. Both hook APIs can now rewrite a tool's input before it runs: Claude Code with `updatedInput`, and Codex with `updatedInput` when it is paired with `permissionDecision: "allow"`. The Claude Code mod API also has a `session.append` event that sees every stored row, media blocks included. Neither hook API can rewrite a prompt yet.

One finding is a docs bug, not a design limit. The Claude Code page says every Read result is hidden, but a Read of a PDF or an image returns base64 bytes, which redact cannot read. So PDFs and images go unscanned through Read as well as through `@`. See [PDFs and images](#pdfs-and-images-mentioned-or-read).

**Five worth doing first**, ranked by how much each one fixes for the work it takes. Effort: XS means under an hour, S half a day, M one or two days, L a week.

1. **YAML blocks by indentation (S–M).** Cut a `password: |` block where its indentation ends, and make Kubernetes `secret-data-yaml` look only inside the `data:` and `stringData:` blocks. One helper removes two "hides too much" limits. See [YAML blocks](#yaml-blocks) and [Kubernetes Secrets in YAML](#kubernetes-secrets-in-yaml).
2. **PDFs in the Claude Code mod (XS docs fix, then M).** First fix the docs: Read of a PDF or an image is unscanned too. Then run `pdftotext` (poppler, which Claude Code already asks for) on `@`-mentioned and Read PDFs, and refuse a PDF whose text holds something to hide. See [PDFs and images](#pdfs-and-images-mentioned-or-read).
3. **Unicode case in word lists (S).** Send the few words that hold non-ASCII letters through a `(?i)` regex, which uses Unicode simple case folding. ASCII words stay on Aho-Corasick. See [Case beyond ASCII](#case-beyond-ascii).
4. **Quick wins in the plain hooks (XS each, S together).** In the Claude Code and Codex hooks, block a prompt that holds something to hide. Widen the Codex hook from `^Bash$` to MCP and other local tools, and pass an MCP result's text instead of one JSON string. See [Integrations](#integrations).
5. **Fewer false pii finds (S).** A `not-a-version` check for IPv4, so `v1.2.3.4` and `==1.2.3.4` stay visible. In one-line JSON, a clue word counts only as the same member's key, not anywhere within 100 bytes. A clue on the line before counts only when that line holds no number of its own. See [Numbers, with pii on](#numbers-with-pii-on).

**Not in the five, but next:**

- **Codex restore through `PreToolUse` `updatedInput` (M–L).** This is the biggest new capability. It is left out of the five because Codex applies `updatedInput` only with `permissionDecision: "allow"`, so every restored command skips Codex's approval prompt. A hook error also lets the tool run, and the value map has to live on disk. See [No real value back in Codex](#codex-nothing-puts-a-real-value-back).
- **`allow` added mid-session (S).** Hand the session's known values to the binary, so its word pass applies `allow` to them. See [allow added mid-session](#an-allow-added-mid-session).

## Limits and verdicts

| Limit | Verdict | Effort | Covered by |
| :- | :- | :- | :- |
| Free text | Accept | – | #33 (team word lists) |
| Shapes no pack knows | Narrow | – | #50, #51, #44, #46 |
| Values without a name or shape | Accept | – | – |
| Transformed values | Narrow (base64/hex) | M | #79, #78 |
| Case beyond ASCII | **Lift** | S | – |
| Very short values | Narrow (passwords only) | XS | – |
| Personal data without a clue word | Narrow (tables, signatures) | S–M | – |
| Random tokens with no prefix | Narrow | – | #56, #77 |
| YAML blocks hide too much | **Lift** | S | – |
| Numbers, with pii on | Narrow | S | #16 (per-rule allow) |
| camelCase names, with random-token | Accept | – | #56 (moves it to opt-in) |
| Kubernetes Secrets in YAML | **Lift** | S–M | – |
| Command lines | Accept | – | – |
| Not a sandbox, not a repo scanner | Inherent | – | – |
| PDFs and images (`@` and Read) | Narrow (PDF text); accept (images) | XS + M | – |
| `allow` added mid-session | **Lift** | S | – |
| Mod fails closed when redact cannot run | Accept | – | – |
| Plain Claude Code hook: no prompt rewrite | Narrow (block instead) | XS | – |
| Plain Claude Code hook: no restore | Accept (use the mod) | – | – |
| Plain Claude Code hook: session file keeps the raw output | Unverified | XS to check | – |
| Codex: no in-place edit | Accept (the docs' own method) | – | – |
| Codex: no prompt rewrite | Narrow (block instead) | XS | – |
| Codex: no restore | Lift, opt-in | M–L | – |
| Codex: non-text result is one JSON string | Narrow | XS | – |
| Codex: hook matches Bash only | **Lift** | XS | – |

## What it misses

### Free text

**Inherent.** No rule can tell a customer's name from any other word ([limits.md:10](../docs/reference/limits.md)). The way out is the user's own word lists, and a team can share them only once [#33](https://github.com/Drewtopia/redact/issues/33) (project `.redact.toml`) lands. Nothing to add.

### Shapes no pack knows

**Narrow. Covered by [#50](https://github.com/Drewtopia/redact/issues/50), [#51](https://github.com/Drewtopia/redact/issues/51), [#44](https://github.com/Drewtopia/redact/issues/44) and [#46](https://github.com/Drewtopia/redact/issues/46)**, with the gaps listed in `research/gitleaks-gaps.md` and `research/betterleaks-gaps.md` on their branches. The list will never be complete. Nothing to add.

### Values without a name or shape

**Inherent for a pipe.** A bare `hunter2` looks like any other word. The mod already narrows it in one place: a value it handed to a tool comes back hidden down to 4 characters, even bare ([vault.ts:84](../claude-plugin/hooks/vault.ts)). Accept.

### Transformed values

**Base64 and hex: covered by [#79](https://github.com/Drewtopia/redact/issues/79). A JWT with an `e30` payload: covered by [#78](https://github.com/Drewtopia/redact/issues/78).**

#79 asks that "ordinary base64 (a PEM certificate, a data URI image) stays as visible as today", but does not say how to tell the two apart. trufflehog has a cheap gate for that. Its base64 decoder takes runs of 20 or more base64 characters, decodes them, and keeps the result only when every decoded byte is ASCII ([base64.go:36-46](https://github.com/trufflesecurity/trufflehog/blob/db665f0c24c63a536220e0e4a3ec9b9dc250e6be/pkg/decoders/base64.go#L36-L46)). A DER certificate or a PNG decodes to binary, so it drops out before any rule runs. trufflehog also decodes UTF-16 and escaped Unicode (`ghp_…`) ([decoders.go](https://github.com/trufflesecurity/trufflehog/blob/db665f0c24c63a536220e0e4a3ec9b9dc250e6be/pkg/decoders/decoders.go#L8-L17)), which #79 does not mention. The escaped form matters for JSON output.

- **Reversed values:** accept. No scanner we checked decodes reversed text.
- **Values split across lines:** accept, except for wrapped base64, which #79's decoder can join.

### Case beyond ASCII

**Why:** the word pass uses Aho-Corasick with `ascii_case_insensitive(true)` ([scan.rs:384-401](../src/scan.rs)). The crate folds ASCII letters only, and its docs say that "it is unlikely that support for Unicode case folding will be added". They point to the `regex` crate instead ([AhoCorasickBuilder::ascii_case_insensitive](https://docs.rs/aho-corasick/1.1.3/aho_corasick/struct.AhoCorasickBuilder.html#method.ascii_case_insensitive)). The miss is real only where a non-ASCII letter changes case: `MÜLLER` against `Müller`, or `ÇELIK` against `Çelik`. `Müller` against `müller` already matches, because only the ASCII `M` changes.

**Lift.** Split the words in two. Words that are all ASCII stay on Aho-Corasick. The few that hold a non-ASCII letter go into one `RegexBuilder` alternation of escaped literals with `(?i)`. That regex "is Unicode-aware and uses simple case folding" ([regex 1.13.1 docs](https://docs.rs/regex/1.13.1/regex/index.html)). Keep the same word-edge test after each match.

**Cost:** the comment at [scan.rs:384-386](../src/scan.rs) records that a regex holding thousands of words grew past its size limit and took 25 s on 1 MB. Non-ASCII words are a small share of a word list, but give the second matcher a size limit and an error that names the cause, not a silent fallback. Simple case folding misses the multi-character folds (`ß` against `SS`). Say so in the docs.

### Very short values

**Why:** a word-list entry under 3 characters is dropped ([pack.rs:475](../src/pack.rs), [pack.rs:732](../src/pack.rs), [pack.rs:1031](../src/pack.rs)), and so is a `.env` value under 4 ([pack.rs:324](../src/pack.rs)). `named-secret` needs 6 characters: one plus `{5,}` ([credentials.toml:174](../packs/credentials.toml)).

**Narrow, for passwords only (XS).** A name that is literally `password`, `passwd` or `pwd` is a much stronger clue than `token` or `key`. Give that name its own rule with a 4-character minimum, and reuse the `is_setting` common-value list ([pack.rs:302-326](../src/pack.rs)) so `password: none` and `password: null` stay visible. Keep 6 for the other names, where `key: auto` or `token: none` are ordinary output.

**Cost:** a few more finds such as `password: test`. Accept the rest: word lists under 3 characters would hide `a`, `of` and `id` everywhere.

### Personal data without a clue word

**Why:** the phone, SSN and NINO rules carry `context` words ([pii.toml:20](../packs/pii.toml), [pii.toml:99](../packs/pii.toml), [pii.toml:107](../packs/pii.toml)). `clue_near` looks for one on the same line or the line before, within `CLUE_REACH = 100` bytes ([scan.rs:337-356](../src/scan.rs)). The clue is there to keep order numbers visible.

**Narrow (S–M), in two cases:**

- **Table columns.** When the line is a Markdown row (`|`-separated) or a CSV row, find the table's header line (the first row of the contiguous block). Count the clue as present when the header cell in the same column holds a clue word. The false-positive risk stays low, because the header has to say `Phone`. This needs code in `clue_near`, not a pack change.
- **Signatures.** Add a `phone-letter` rule, `(?m)^[ \t]*(?:M|T|Mob|Tel)[.:][ \t]*(\+?[0-9][0-9 ()-]{8,})`. A one-letter label at line start, followed by nine or more phone characters, is rarely anything else.

Accept the rest. Without a clue, a phone number is just a number.

### Random tokens with no prefix

**Mostly covered by [#56](https://github.com/Drewtopia/redact/issues/56).** That issue's character set takes `+`, `/`, `_`, `~` and `-`, so a token joined to `key_` or written as `+`/`/` base64 is no longer excluded the way `except = '[^A-Za-z0-9]'` excludes it today ([credentials.toml:309](../packs/credentials.toml)). **Tokens inside URLs are covered by [#77](https://github.com/Drewtopia/redact/issues/77).**

The lone 64- or 76-character line is a decision, not a gap: #56 says to keep skipping "a line that is only base64, 64 or 76 characters long". The rule's own regex matches that skip ([credentials.toml:301](../packs/credentials.toml)). The skip could be narrowed so it needs a block of two or more lines, or `=` padding. That would hide a real 64-character token standing alone, at the cost of hiding a one-line, 48-byte base64 blob. It contradicts #56's settled spec, so it is a question for that issue, not a change to make here.

The JSON `\n` escape (`\nAbc…`) misses because `random-token`'s start group refuses a backslash. The shape rules' start group, `(?:^|[^A-Za-z0-9_]|\\[nrt])`, accepts it, and [#74](https://github.com/Drewtopia/redact/issues/74) puts that group in one place. #56 should use it for the moved rule (XS). The camelCase misses are accepted: see [camelCase names](#camelcase-names-with-random-token).

## What it hides too much

### YAML blocks

**Why:** `named-secret-yaml-block` captures `(?:[ \t]+[^\n]*(?:\n|\z))+`, which means every indented line after `password: |` ([credentials.toml:210](../packs/credentials.toml)). A regex cannot compare one line's indentation with another's, because the `regex` crate has no backreferences ([regex docs](https://docs.rs/regex/1.13.1/regex/index.html)).

**Lift (S).** The YAML spec fixes where a block scalar ends. Its content indentation is set by the first non-empty line, or by an explicit indentation indicator, and the block ends at the first non-empty line indented less than that ([YAML 1.2.2 §8.1.1.1](https://yaml.org/spec/1.2.2/#8111-block-indentation-indicator)). Add a post-match step for this rule: measure the first content line's indentation, then cut the capture before the first non-empty line indented less. A pack can name it like the other checks, for example `check = "yaml-block"` beside `luhn`, `iban` and `not-a-name` ([pack.rs:1098](../src/pack.rs)). It trims a find instead of rejecting it, so the check code needs a small extension.

**Cost:** a few lines in the scan loop. Nothing hidden today becomes visible except the next key's lines.

### Numbers, with pii on

**Why:** `ipv4` takes any four dotted octets ([pii.toml:74](../packs/pii.toml)). The clue window reaches 100 bytes on the same line and the whole line before ([scan.rs:337-356](../src/scan.rs)).

**Narrow (S), in three changes:**

- **IPv4 versions.** Add a `not-a-version` check that looks at the bytes just before the match: `v`, `version`, `@`, `==`, `>=`, `~=`, or `^`. Also leave out the documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` ([RFC 5737 §3](https://www.rfc-editor.org/rfc/rfc5737#section-3)), in the same spirit as the `example.com` exception. Keep private ranges hidden: they map an internal network. A bare `1.2.3.4` with no prefix stays hidden. To show a known address, use per-rule `allow` from [#16](https://github.com/Drewtopia/redact/issues/16).
- **One-line JSON.** When a match sits inside a JSON string value, count a clue only when it is that member's own key. `phone-named` already handles `"phone": "…"` ([pii.toml:48-53](../packs/pii.toml)), so the change only stops the 100-byte window from reaching across members.
- **The line before.** Count a clue on the line before only when that line holds no phone-shaped number itself. That is the `Phone:` heading with the number below it. An order number after a `phone: …` line then stays visible.

**Cost:** each is a few lines in `clue_near` or a new check. The second needs to know the match is inside a JSON string. The JSON record walk that `within` uses ([scan.rs:170-200](../src/scan.rs)) already finds string boundaries.

### camelCase names, with random-token

**Accept.** The `not-a-name` check trades a 1-in-150 miss against this false positive ([pack.rs:1427](../src/pack.rs)). #56 moves the rule into an opt-in pack, so this stops affecting default users.

### Kubernetes Secrets in YAML

**Why:** `secret-data-yaml` runs on every indented `name: base64ish` line once `kind: Secret` appears anywhere in the text ([kubernetes.toml:8-14](../packs/kubernetes.toml)). The JSON form scopes itself with `withinKey = '^(?:data|stringData)$'` ([kubernetes.toml:16-22](../packs/kubernetes.toml)), but YAML has no equivalent.

**Lift (S–M).** A YAML block mapping's extent is set by indentation ([YAML 1.2.2 §8.2.2](https://yaml.org/spec/1.2.2/#822-block-mappings)), so the YAML-block helper above also finds the region under a top-level `data:` or `stringData:`. Expose it as a YAML counterpart of `withinKey`: `withinYamlKey = '^(?:data|stringData)$'`. Feed the regions into the same `segments` list that `within` and `withinKey` build ([scan.rs:186-206](../src/scan.rs)). The rule then runs only on those lines, and `metadata.name: sample12` stays visible.

**Cost:** one more segment source in the scan loop, and a docs entry in `docs/packs/writing.md`. Detection is lost only for a Secret whose `data:` is not a block mapping, such as a flow mapping `data: {a: b}`, which `kubectl` does not print.

### Command lines

**Accept.** `env-dump` takes everything after `NAME=` to the end of the line ([credentials.toml:187](../packs/credentials.toml)). `GREETING=hello world` in an `env` dump and `PGPASSWORD=secret psql …` cannot be told apart from the text alone. Cutting at the first space would show the second word of a value that holds a space. Hiding too much is the safe side here.

## What it is not

**Inherent: not a sandbox, and not a repo scanner** ([limits.md:38-41](../docs/reference/limits.md)). Both hook APIs say so themselves. Claude Code's `updatedToolOutput` "only changes what Claude sees" ([hooks.md](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)), and a Codex `PostToolUse` hook "can't undo side effects from a tool that already ran" ([Codex hooks](https://learn.chatgpt.com/docs/hooks)).

**What stays visible on purpose** is design, not a limit, and these sections leave it as it is.

## Integrations

### PDFs and images, mentioned or Read

**Why:** the mod's `prompt.mention` hook passes any path that matches `MEDIA_FILE` straight through ([redact.ts:63](../claude-plugin/hooks/redact.ts), [redact.ts:279-280](../claude-plugin/hooks/redact.ts)).

**A docs bug comes first (XS).** The coverage table says every Read result is hidden ([claude-code.md](../docs/integrations/claude-code.md), "What it covers"), and that is not true for media. The engine's tool types give a Read of a PDF as `{type: "pdf", file: {base64}}` and a Read of an image as `{type: "image", file: {base64}}`. A Read of PDF pages (`parts`) delivers the page images "solely as image blocks in the model-facing tool_result", and they are "absent on the emitted/persisted result" (`claude-code-tools/index.d.ts`, Read output, written by Claude Code 2.1.293). The mod's `walk` scans the base64 text, which no rule can read. For `parts`, there is nothing to scan at all. The "What it misses" section should say that a Read of a PDF or an image is unscanned too.

**PDFs: narrow (M).**

- poppler's `pdftotext` reads a PDF from stdin and writes its text to stdout: `pdftotext - -` ([pdftotext(1)](https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html)). Claude Code already asks users to install poppler for page-range reads ([tools-reference](https://code.claude.com/docs/en/tools-reference#read-tool)), so most users will have it.
- In `prompt.mention`, run `pdftotext` on the file through `$.process.run` and scan the text. Refuse the mention on any find, exactly as a text file is refused today ([redact.ts:279-296](../claude-plugin/hooks/redact.ts)).
- In `tool.call` for Read, do the same for a `pdf` result, and for the source PDF of a `parts` result (its `filePath`). Refuse on a find.
- When `pdftotext` is missing, a new `media` setting decides: `pass` (today's behaviour, and the default) or `deny`.
- A scanned PDF holds only images, so its text is empty and it passes unscanned. Say so.

The mod API's `session.append` event "fires once per row a conversation of this session keeps … before it is stored", and a rewrite is what "the model and the transcript file" read (`claude-code/index.d.ts:4319-4329`, Claude Code 2.1.293, EARLY ACCESS). Rows carry `image` and `document` blocks in Messages API form (`index.d.ts:614-650`). One hook there could check every PDF block whatever door it came in by: a pasted file, `@`, or Read. That would turn "narrow" into close to "lift" for PDFs. I have not probed it. Check that `document` blocks really reach `session.append` before building on it.

**Images: accept.** OCR (tesseract) is a large dependency, slow, and misses text in screenshots often enough that a clean result would mean little. Offer the same `media = "deny"` setting, so a sensitive repo can refuse images outright. `prompt.submit` lists pasted images in `e.attachments` (`index.d.ts:8975-9002`), so the mod can refuse those too.

### An allow added mid-session

**Why:** the mod keeps every value it hid in `byValue` for the session, and `hideKnown` hides it again wherever it turns up, without asking the binary ([vault.ts:84-94](../claude-plugin/hooks/vault.ts)). The binary's own word pass already skips allowed values ([scan.rs:397](../src/scan.rs)), but the mod's pass never sees `allow`.

**Lift (S).** Hand the known values to the binary, and let its Aho-Corasick word pass hide them. For example, a `--known` flag that reads a NUL-separated block at the head of stdin, never argv or the environment. The binary then applies the current `allow` to each value, and the mod's `includes()` loop, marked `shortcut:` at [vault.ts:83](../claude-plugin/hooks/vault.ts), goes away. `main.rs` has no subcommand that prints the allow list today ([main.rs:261-301](../src/main.rs)), and printing it would not tell the mod which value an `allow` glob covers. A `SessionStart` hook could register `~/.config/redact/config.toml` through `watchPaths` (absolute paths) for `FileChanged` ([hooks.md, SessionStart decision control](https://code.claude.com/docs/en/hooks#sessionstart-decision-control)), but imports and `env_files` would each need watching too. The binary already reads the config on every scan, so `--known` needs no trigger at all.

**Cost:** the stdin format changes, so the mod's minimum binary version goes up. The values travel over the same pipe as the text they are hidden in.

### The mod fails closed when redact cannot run

**Accept.** Withholding is the point ([redact.ts:10-13](../claude-plugin/hooks/redact.ts)). Bundling a binary in the mod would remove the "missing" case, but it adds a binary per platform, plus signing and release work. The `locate` fallback already covers the common PATH problem.

### Plain Claude Code hook: no prompt rewrite

**Still true.** A `UserPromptSubmit` hook supports `decision: "block"`, `reason`, `additionalContext`, `sessionTitle` and `suppressOriginalPrompt`. None of them replaces the prompt text ([hooks.md, UserPromptSubmit decision control](https://code.claude.com/docs/en/hooks#userpromptsubmit-decision-control)).

**Narrow (XS).** Add a second documented hook that runs `redact scan --json` on the prompt and blocks when the result is not `[]`, with `"suppressOriginalPrompt": true` so the block message does not repeat the text. The docs warn that the submitted text "can still appear in local files such as the session transcript and your prompt history" ([hooks.md, What a blocked prompt leaves behind](https://code.claude.com/docs/en/hooks#what-a-blocked-prompt-leaves-behind)). So the hook keeps the value from the model, not off disk. Say so.

### Plain Claude Code hook: no real value back

**Possible, but accept: point users to the mod.** `PreToolUse` `updatedInput` "replaces the entire input object" before the tool runs ([hooks.md, PreToolUse decision control](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)). A shell hook could restore placeholders from a map. The costs:

- The map of real values must persist on disk between hook processes.
- The hook has to copy the mod's shell-character, publish-command and (after [PR #84](https://github.com/Drewtopia/redact/pull/84)) host checks.
- In auto mode, an `updatedInput` with no `permissionDecision` can be denied, because the server reviewed the input Claude wrote ([hooks.md, PreToolUse updatedInput in auto mode](https://code.claude.com/docs/en/hooks#pretooluse-updatedinput-in-auto-mode)).

The mod already does all of this in memory.

The matcher could also widen past Bash (Read, Grep, MCP). The output must keep the tool's shape, though, and "a value that doesn't match the tool's output schema is ignored and the original output is used" ([hooks.md, PostToolUse decision control](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)). A jq `walk` that gets one tool's shape wrong would fail open without a word. Leave the plain hook on Bash.

### Plain Claude Code hook: the session file keeps the original output

**Unverified.** The hooks docs say telemetry "captures the original output before the hook runs" ([hooks.md, PostToolUse](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)). They do not say what the transcript file stores after `updatedToolOutput`. Check it (XS): run the hook, then `rg` the session's `transcript_path` for a test value. If the transcript holds the masked text, drop this bullet from [claude-code.md](../docs/integrations/claude-code.md).

### Codex: cannot edit output in place

**Accept, and keep the current method.** Codex says `updatedMCPToolOutput` and `suppressOutput` "are parsed but not supported yet". `decision: "block"` "replaces the tool result with that feedback", which is exactly what the documented hook does ([Codex hooks, PostToolUse](https://learn.chatgpt.com/docs/hooks)). Watch for `updatedMCPToolOutput` to ship.

### Codex: hook matches Bash only

**Lift (XS).** The documented matcher is `^Bash$` ([codex.md:20](../docs/integrations/codex.md)). Codex runs `PostToolUse` for shell commands, `exec_command`, `apply_patch`, MCP tools and other local function tools ([Codex hooks, Tool coverage](https://learn.chatgpt.com/docs/hooks)). Widen it to `^(Bash|mcp__.*)$` at least. MCP results (issue trackers, databases) are where most outside data comes in.

### Codex: a non-text result is one JSON string

**Narrow (XS).** For an MCP tool, `tool_response` is "the MCP call result" ([Codex hooks, PostToolUse](https://learn.chatgpt.com/docs/hooks)). An MCP result's text lives in `content[]` items of `type: "text"` ([MCP spec 2025-06-18, Tool result](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#tool-result)). Join those with jq, mask the text, and fall back to `tojson` only for other shapes. The model then reads text, not escaped JSON.

### Codex: no prompt rewrite

**Still true.** `UserPromptSubmit` takes `additionalContext` or `decision: "block"` ([Codex hooks, UserPromptSubmit](https://learn.chatgpt.com/docs/hooks)). Codex's own docs list "scan your team's prompts to block accidentally pasting API keys" as a use case. **Narrow (XS):** the same blocking hook as for Claude Code.

### Codex: nothing puts a real value back

**Lift, opt-in (M–L), with a security trade.** Codex now honours `PreToolUse` `updatedInput` for Bash, `apply_patch`, MCP and local tools. It applies it only "with `permissionDecision: "allow"`". `"ask"` is "parsed but not supported yet", and "a PreToolUse error, timeout, or malformed response can let the tool run" ([Codex hooks, PreToolUse](https://learn.chatgpt.com/docs/hooks)). So:

- Every command that gets a real value is auto-approved, which skips Codex's approval prompt for exactly the commands that carry secrets. Restore only for commands that Codex's own rules would have run without asking, or refuse when unsure.
- The placeholder map has to live on disk, keyed by `session_id`, mode 0600, under `$XDG_RUNTIME_DIR` where there is one, and removed at `SessionEnd`.
- A hook that crashes runs the command with placeholders in it. That fails safe for secrecy, but the command breaks.
- The shell-character, publish and host checks from [redact.ts](../claude-plugin/hooks/redact.ts) would need a second copy. Put them in the binary as `redact hook codex pre|post` rather than in shell and jq, so both integrations share one copy.

This is the largest gain for Codex users, and the largest design change in this list.

## Sources

Every web page was fetched on 2026-11-16.

- Claude Code hooks reference: [code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks), read as [hooks.md](https://code.claude.com/docs/en/hooks.md): UserPromptSubmit, PreToolUse and PostToolUse decision control, FileChanged.
- Claude Code tools reference, Read: [code.claude.com/docs/en/tools-reference](https://code.claude.com/docs/en/tools-reference) (images, PDFs, poppler).
- Claude Code mod API: `claude-code/index.d.ts` and `claude-code-tools/index.d.ts`, which the engine writes beside each loaded mod ("Written by Claude Code 2.1.293", marked EARLY ACCESS). Cited lines: `session.append` 4319-4329, ApiContentBlock 614-650, PromptSubmitAttachment 8975-9002, PromptMention 8725-8800, and the tools file's Read output union.
- Codex hooks: [developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks), which redirects (308) to [learn.chatgpt.com/docs/hooks](https://learn.chatgpt.com/docs/hooks).
- aho-corasick 1.1.x: [`AhoCorasickBuilder::ascii_case_insensitive`](https://docs.rs/aho-corasick/1.1.3/aho_corasick/struct.AhoCorasickBuilder.html#method.ascii_case_insensitive) (redact locks 1.1.5).
- regex 1.13.1: [crate docs](https://docs.rs/regex/1.13.1/regex/index.html), on Unicode simple case folding and on look-around and backreferences not being supported.
- YAML 1.2.2: [§8.1.1.1 block indentation indicator](https://yaml.org/spec/1.2.2/#8111-block-indentation-indicator) and [§8.2.2 block mappings](https://yaml.org/spec/1.2.2/#822-block-mappings).
- [RFC 5737 §3](https://www.rfc-editor.org/rfc/rfc5737#section-3): IPv4 address blocks reserved for documentation.
- [pdftotext(1), poppler-utils 22.12.0](https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html).
- MCP specification 2025-06-18: [tool results](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#tool-result).
- trufflehog at [`db665f0`](https://github.com/trufflesecurity/trufflehog/tree/db665f0c24c63a536220e0e4a3ec9b9dc250e6be/pkg/decoders): `decoders.go` and `base64.go`.
- redact at `1141ad0`: `src/scan.rs`, `src/pack.rs`, `src/main.rs`, `packs/*.toml`, `claude-plugin/hooks/redact.ts`, `claude-plugin/hooks/vault.ts`, and the docs pages linked above.
- Open work checked: issues [#16](https://github.com/Drewtopia/redact/issues/16), [#33](https://github.com/Drewtopia/redact/issues/33), [#44](https://github.com/Drewtopia/redact/issues/44), [#46](https://github.com/Drewtopia/redact/issues/46), [#50](https://github.com/Drewtopia/redact/issues/50), [#51](https://github.com/Drewtopia/redact/issues/51), [#56](https://github.com/Drewtopia/redact/issues/56), [#74](https://github.com/Drewtopia/redact/issues/74), [#75](https://github.com/Drewtopia/redact/issues/75), [#77](https://github.com/Drewtopia/redact/issues/77), [#78](https://github.com/Drewtopia/redact/issues/78), [#79](https://github.com/Drewtopia/redact/issues/79); PRs [#82](https://github.com/Drewtopia/redact/pull/82), [#84](https://github.com/Drewtopia/redact/pull/84).
