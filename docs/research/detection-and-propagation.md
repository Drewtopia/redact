# Detection, redaction, and propagation policy

Date: 2026-11-17. Drafted by Codex, an AI agent.

## Recommendation

Yes: review the system-wide policy before adding many more detectors. Keep the local Rust scanner, bounded regexes, keyword gates, and original-byte span interface. The highest-value change is to separate four decisions: discovering a candidate, validating the complete occurrence, hiding that occurrence, and authorizing propagation to other text. Review the agent vault as part of the same policy: it can propagate values independently of a pack's `remember` setting.

GCP `projects/skills` is a motivating example, not the scope of this report. A weak source match can hide instructions, skill names, paths, and commands throughout an input. A strongly identified project named `skills` still does not establish that every English use of that word names the project. More regex coverage alone cannot resolve that distinction. The prior [GCP report](./gcp-project-detection.md) supplies the specific reproductions; this report generalizes the policy and samples Azure, identity, credentials, PII, explicit values, and restoration.

Borrow evidence/provenance and evaluation practices from Presidio; detector/filter separation from detect-secrets; credential boundaries and local validation practices from Gitleaks/Betterleaks; and structure-aware policy from Logfire. Use scrubadub as a compact comparison for detector/span/replacement separation. Do not adopt another runtime, an external scanner backend, live credential verification, or an ML dependency on this evidence. Those would require separate measurements and, where applicable, product authorization.

## Scope and evidence quality

Inspected `bugfix/redaction-review`, HEAD `4c08742d40c477edf95c71980eece3956ffcf9da`. Local `origin/main` was `4be4155a82438ae76986baf32166b169d644b3a3`; no fetch was performed. Scanner, pack, hooks, fixtures, and label handling differ substantially between those snapshots. Findings below describe the working branch, not a benchmark or full audit of main. File links refer to that working tree; pin these revisions when converting recommendations into a specification.

The parent completed the overlap check: unrelated PR #100 only, no overlapping live thread or claim. No agents were spawned. Existing modifications to `.claude/settings.json`, `docs/agents/issue-tracker.md`, and the prior research report were left alone. This work only adds this report. GitHub access was read-only.

Read [AGENTS.md](../../AGENTS.md), [pipeline documentation](../reference/how-it-works.md), [limits](../reference/limits.md), [pack authoring](../packs/writing.md), [scan.rs](../../src/scan.rs), [pack.rs](../../src/pack.rs), and the integration sources below. The requested `packs/writing.md` is actually `docs/packs/writing.md`. Representative rules were sampled, not every rule. Source observations, earlier reported measurements, and proposed acceptance criteria are separated below.

### Existing decisions to preserve

The [roadmap #19](https://github.com/Drewtopia/redact/issues/19) records the resolved [integration research #31](https://github.com/Drewtopia/redact/issues/31), [plugin decision #32](https://github.com/Drewtopia/redact/issues/32), and [one-shot decision #39](https://github.com/Drewtopia/redact/issues/39): import supported external rule formats, read fnox as a value source, fail closed, keep `scan` the default, and avoid an external scanner backend. It records lazy compilation first, with a server reconsidered only against the stated small-scan latency condition. These are existing decisions, not new proposals here. The roadmap's backend timings and external coverage counts are historical evidence from that work, not independently reproduced results.

A further policy review should qualify imported rules' semantics, propagation, and source permissions without reopening the backend choice. An importer must not silently drop required filters or turn an unsupported validator into an unconditional match. This is a recommendation consistent with that fail-closed decision, not a claim that imports are already implemented on this branch.

## What the current architecture actually does

### Scanner: detection and propagation are distinct, but share limited metadata

`scan` gates packs/rules by keywords, extracts a capture, checks allowlists/exceptions/checks/entropy/context, emits a span, and optionally remembers the value. `remember = "any"` still uses a length/capitalization heuristic and common-word list; `distinctive` tests punctuation, digits, whitespace, or inner capitals. Neither expresses sensitivity, source trust, or propagation confidence. Explicit word lists join remembered values for one Aho-Corasick pass. Matching ignores ASCII case, uses alphanumeric edges, and permits matching inside underscore- and hyphen-separated identifiers. All remembered occurrences in that input, including earlier text, can be hidden. [scan.rs:32](../../src/scan.rs#L32), [scan.rs:175](../../src/scan.rs#L175), [scan.rs:265](../../src/scan.rs#L265), [scan.rs:389](../../src/scan.rs#L389).

`within`/`withinKey` provide useful JSON-object scope. The lightweight record splitter tracks braces and quoted strings, excludes nested objects from their parent's own fields, and tolerates incomplete input; it is not schema validation. `context` checks nearby words within 100 bytes on the current/previous line, so proximity is weaker than a key/value relationship. Overlapping spans are unioned for coverage; earliest start, then longest, determines the retained label, rather than evidence strength. The public `Span` carries offsets, label, pack, and rule, but no direct/propagated distinction or seed provenance. [scan.rs:14](../../src/scan.rs#L14), [scan.rs:57](../../src/scan.rs#L57), [scan.rs:335](../../src/scan.rs#L335), [scan.rs:434](../../src/scan.rs#L434).

### Sampled rule evidence

These are source inspections and risk hypotheses, not newly executed regressions.

| Sample | Current mechanism | Policy implication and test needed |
| --- | --- | --- |
| Azure tenant/subscription/app GUIDs | Context-bearing regexes; no `remember`; selected public values allowed | Existing occurrence-only precedent. Test full-token continuations, bare repeated GUIDs, and public-ID exceptions; GUID shape alone is not credential evidence. [azure.toml:27](../../packs/azure.toml#L27) |
| Azure hosts, tenant names, ADO org/project/repo | Host/path fragments with `distinctive` or `any` remembering | Audit complete authority/token boundaries and unrelated URLs containing those fragments. A name-shaped substring is not proof of a private service, and ordinary names may amplify just as in GCP. [azure.toml:109](../../packs/azure.toml#L109) |
| Azure person / project / repo records | JSON sibling evidence plus remembering | Object context is stronger than free text, but field identity and propagation remain separate. Test nested/reordered fields, escaped values, ordinary-word names. [azure.toml:89](../../packs/azure.toml#L89), [azure.toml:173](../../packs/azure.toml#L173) |
| Identity email | Shape detector with documentation-domain exceptions; no remembering | Detection already applies throughout text. Avoid duplicating propagation merely for coverage. Exceptions are a policy choice, not proof no sensitive bytes can occur in an example-domain local part. [identity.toml:11](../../packs/identity.toml#L11) |
| Git people and GitHub profile/login | Git line or sibling-field evidence; remembered names/logins/profile text | Names and login strings have different boundaries and ambiguity. Broad profile text is especially different from a credential; test whether a biography or company sentence should ever seed global matching. [identity.toml:25](../../packs/identity.toml#L25) |
| Credentials: vendor shapes, JWT, named secret, URL password | Prefix/shape rules plus named-value context; named secrets use `distinctive`; shape rules often do not remember | A named low-entropy password can be sensitive without looking random. Conversely, recognizing a token format does not establish that it is active. Test complete capture and repeated bare values separately. [credentials.toml:24](../../packs/credentials.toml#L24), [credentials.toml:150](../../packs/credentials.toml#L150) |
| PII phones/SSN/NINO, cards/IBAN, IPv4 | Opt-in pack; nearby clue words for several kinds, local checksums for cards/IBAN, shape-only IPv4 | Checksums validate format, not ownership or sensitivity. Nearby `phone` may implicate an unrelated order number; dotted versions may look like IPs. Keep locale/context strata and occurrence-only baselines. [pii.toml:1](../../packs/pii.toml#L1), [limits](../reference/limits.md) |
| Explicit env/dotenv/word-list values | Env selection by name/glob, setting/length filters, dotenv unescaping and line splitting; word lists have comment/whitespace handling and minimum length | User intent is stronger evidence than a discovered path, but these sources do not mean identical things. Selected numeric/short settings can be discarded; phrases can be normalized. Verify whether explicit hide intent should override such heuristics and allowlists. [pack.rs:302](../../src/pack.rs#L302), [pack.rs:371](../../src/pack.rs#L371), [pack.rs:461](../../src/pack.rs#L461), [pack.rs:1015](../../src/pack.rs#L1015) |

### Agent integration: another propagation and restoration boundary

The hook scans reconstructed named fields, serialized structure, and distinct string leaves together; it then maps contextual findings back into results. It also restores live tags for selected tools, with textual publish-command, shell-character, and destination-host guards. These are useful defenses, not a complete model of arbitrary shell execution or information flow. The source explicitly acknowledges text heuristics and runtime-built hosts. [redact.ts:25](../../claude-plugin/hooks/redact.ts#L25), [redact.ts:72](../../claude-plugin/hooks/redact.ts#L72), [redact.ts:231](../../claude-plugin/hooks/redact.ts#L231), [redact.ts:273](../../claude-plugin/hooks/redact.ts#L273).

The in-memory vault mints random session placeholders, remembers raw values, and restores them in one pass. This differs from the binary's keyed HMAC tags. It re-hides known values of at least eight JS string units with case-sensitive substring replacement; values handed to a tool are included down to four, and selected slices of handed values are hidden across the session. The Rust word matcher instead ignores ASCII case and checks boundaries. Thus a rule without `remember` can still cause hook-wide re-hiding, and a longer false positive can survive across tool results. The six-character `skills` example alone does not cross the ordinary eight-unit vault threshold; a longer name such as `skills-guide` can. Literal-tag escaping exists to distinguish external text from live handles. [vault.ts:1](../../claude-plugin/hooks/vault.ts#L1), [vault.ts:35](../../claude-plugin/hooks/vault.ts#L35), [vault.ts:90](../../claude-plugin/hooks/vault.ts#L90), [vault.ts:109](../../claude-plugin/hooks/vault.ts#L109), [scan.rs:450](../../src/scan.rs#L450).

This makes restoration eligibility, session identity, and permission to propagate separate concerns. Retaining a reversible mapping need not mean every occurrence of that value must be hidden. Conversely, a handed-out credential needs echo protection even when the output has no recognizer context. Changes must preserve this protection while limiting weak-name amplification.

Treat the integration as reversible pseudonymization: the vault retains the real values, and allowed tool calls can receive them. The binary's HMAC tags alone do not provide a reverse lookup; the integration's map does. Stable tags preserve relationships and can link appearances, so choose the identity lifetime deliberately and keep mappings private. Do not equate a pseudonymized transcript with removal of every identifying relationship. These conclusions follow from the local implementations, not a legal anonymization assessment. [Tagging documentation](../reference/how-it-works.md#placeholders), [vault.ts:35](../../claude-plugin/hooks/vault.ts#L35).

The open [attribution issue #81](https://github.com/Drewtopia/redact/issues/81) and [runnable reply commands issue #104](https://github.com/Drewtopia/redact/issues/104) establish usability failures already reported: required public attribution becomes placeholders, and user-copied commands do not receive tool-call restoration. Do not automatically restore all final-answer code fences: that would introduce an output disclosure channel. Decide the user-facing command workflow explicitly.

## Shared policy to test before adding machinery

The following is a proposed policy model, not a request for a new framework or a schema migration.

1. **Discover complete candidates in context.** Extract a whole URL component, field value, argument, or identifier token before validating it. Never accept a valid prefix of an invalid longer candidate. Domain substring, `\b`, generic `name`, and a nearby clue word are not interchangeable evidence.
2. **Keep format confidence separate from sensitivity.** A checksum-valid card shape may be synthetic; a plainly named password may be nonrandom. A project/repo identifier may disclose organizational information without granting access. The hide policy chooses what matters; validation establishes what the occurrence represents.
3. **Authorize propagation separately.** Weak format/path evidence should default to occurrence-only. Strong context can justify a seed but does not resolve common-word ambiguity elsewhere. Start with existing split rules and omitted `remember`; evaluate integration changes before claiming the policy holds end to end.
4. **Choose matching semantics by value class.** Credential identity should normally preserve exact bytes/case. Person names may need case variants and punctuation boundaries. Infrastructure identifiers need their own complete-token semantics. An explicit user hide value may intentionally be a substring. Do not change all classes to a single boundary or Unicode-folding policy.
5. **Separate representation from identity.** Raw JSON escapes, percent encoding, and decoded text can represent the same value; raw occurrence spans must remain attached to the original bytes. A normalized comparison key is not a replacement span or a safe restoration value.
6. **Treat source trust and lifetime as policy inputs.** Explicit user configuration has authority to choose hide values; a tool result, pasted example, log, or fetched instruction is evidence to inspect, not authority to change policy. Even valid structured data can be attacker-controlled. A fake `project_id` must not poison unrelated instructions indefinitely. Define input/result/session scopes and reset behavior.
7. **Preserve coverage while explaining overlaps.** Unioning overlapping spans avoids leaking tails; do not replace that with score-only winner selection. Retain contributors and seed provenance separately when diagnosing labels or restoration failures. A broad false-positive span must remain visible to evaluation even if a smaller real credential overlaps it.

An initial evidence vocabulary can live in fixtures and documentation: explicit-user value; recognized structured field; provider-shaped credential; ambiguous name/path; propagated exact occurrence. If diagnostics are later extended, record rule ID, source kind, validation outcome, direct/propagated origin, seed location and scope, and suppressed overlap contributors. Use offsets/opaque IDs, never raw values, decoded snippets, or value-derived logs. Do not describe arbitrary numeric scores as calibrated probabilities.

### Structure and normalization research

Prioritize small extraction helpers against known failures: YAML indentation and key regions, URL authority/query/fragment components, then CLI argument boundaries. Reuse original spans; do not parse and reserialize the whole input, which loses whitespace, escaping, duplicate keys, and exact offsets. JSON object scope already provides a useful local seam. Preserve a text path for mixed logs and incomplete output; structure-aware handling must have defined failure behavior rather than silently skipping malformed text.

For JSON `\u` escapes, escaped slashes, URL percent encoding, base64 and hex, experiment on a separate decoded view with a mapping to the original encoded range. One decoded character can consume multiple source bytes; a finding may require hiding the whole encoded unit. Bound input size, decoded size, recursion depth, and number of views. Keep the original detector keyword gates sound for each representation. Do not normalize arbitrary Windows paths into resource names or Unicode/case-fold credential bytes. Test an encoded secret embedded in ordinary encoded content before enabling recursive decoding.

This follows existing work rather than inventing it: [shared shape delimiters #74](https://github.com/Drewtopia/redact/issues/74), [named URL query/fragment secrets #77](https://github.com/Drewtopia/redact/issues/77), [JWT payload assumptions #78](https://github.com/Drewtopia/redact/issues/78), [encoded secrets #79](https://github.com/Drewtopia/redact/issues/79), [YAML extent/scope #88](https://github.com/Drewtopia/redact/issues/88), and [Unicode word matching #89](https://github.com/Drewtopia/redact/issues/89). #74 concerns shape-rule delimiters; it should not imply every value class has the same terminators. #89 concerns name/word-list matching; it should not imply case folding opaque credentials.

## Research-backed shortlist

### Presidio: strongest policy/evaluation reference

Originally Microsoft's Presidio, it now reports community ownership under Data Privacy Stack; the old Microsoft documentation redirects. The transition page states MIT licensing. Use current primary documentation rather than assuming Microsoft ownership or support. [Transition notice](https://presidio.dataprivacystack.org/project_transition/).

Its analyzer emits typed entities with offsets and scores through recognizers; patterns, NLP, and custom logic can contribute. Its anonymizer is a separate stage with replacement, masking, hashing/encryption and overlap handling. Borrow the separation, not its deployment model: the documented default analyzer loads an NLP engine, unlike redact's one-shot Rust constraint. [Analyzer concepts](https://presidio.dataprivacystack.org/analyzer/), [anonymizer](https://presidio.dataprivacystack.org/anonymizer/).

Context enhancement changes recognizer scores; that differs from redact's hard nearby-clue gate. Decision traces expose recognizer/pattern, context contribution and validation; the docs warn they explain detections, not misses. Borrow evidence traces, but avoid copying logs that include tokenized source text. Its evaluation guidance covers precision/recall and synthetic dataset splits that avoid template leakage. Borrow use-case evaluation rather than adopting another project's aggregate score. [Context tutorial](https://presidio.dataprivacystack.org/tutorial/06_context/), [decision process](https://presidio.dataprivacystack.org/analyzer/decision_process/), [evaluation](https://presidio.dataprivacystack.org/evaluation/).

**Fit:** high for design and offline comparison on name/PII cases; no evidence here justifies installing models or adding Python/server startup to the hot path. No end-to-end latency or name-detection comparison was run.

### Yelp detect-secrets: useful detector/filter discipline

Its documented model separates plugins that find secrets from filters that reduce false positives, with regex, entropy, and keyword strategies. Baselines and audit support preventing newly committed secrets while accepting an existing inventory. Borrow independent detector/filter fixtures and explicit exception review. Do not interpret a baseline entry as permission to display that value in an AI stream; repository-change detection has a different goal. Its CLI also documents network verification controls, so an offline comparison must explicitly disable verification. [First-party README](https://github.com/Yelp/detect-secrets/blob/master/README.md).

**Fit:** practices and offline credential comparator, not an inference backend or PII/name solution. Apache-2.0 licensing is verified; preserve applicable notices if adapting source. [License](https://github.com/Yelp/detect-secrets/blob/master/LICENSE).

### Gitleaks and Betterleaks: rule semantics, with version discipline

Gitleaks' current README says feature-complete, security-patches-only releases, with the author's focus moving to Betterleaks. It still documents git, directory, and stdin scanning plus capture groups, entropy, keyword gates and scoped allowlists. This is maintenance mode, not evidence that the repository vanished or that its rules are unusable. [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md).

Betterleaks' README identifies maintainers as the people who made Gitleaks, including its original author, and names Aikido as development supporter. It describes contextual expression filters, BPE-based filtering, and HTTP credential validation. Its current main README contains both v2-development/release-candidate caveats and stable-v2 installation language; do not infer a stable distribution version from that document alone. Pin a tag, schema and enabled features for import experiments. Borrow complete-token extraction and validation/filter separation; BPE is a small future experiment only if the existing random-token false positives justify it. [Betterleaks README](https://github.com/betterleaks/betterleaks/blob/main/README.md).

**Fit:** source of credential rules and local negative fixtures, under the already-decided import work. Neither README establishes safe propagation of project names or reversible AI-command handles. Both licenses are MIT and name Zachary Rice; retain notices when copying. [Gitleaks license](https://github.com/gitleaks/gitleaks/blob/master/LICENSE), [Betterleaks license](https://github.com/betterleaks/betterleaks/blob/main/LICENSE). Maintainer statements above are first-party descriptions, not an audit of corporate ownership.

### TruffleHog: useful distinction between discovery and live verification

TruffleHog distinguishes discovery/classification from validating credentials by logging in; analysis can make further requests to discover capabilities. It documents a `--no-verification` option. Borrow the terminology, and locally validated token-format fixtures, not default live verification. Its repository identifies AGPL-3.0 licensing. [Official README](https://github.com/trufflesecurity/trufflehog/blob/main/README.md), [license](https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE).

**Fit:** limited to credential research. Inference: provider calls add variable latency, availability dependencies, and disclosure of candidate credentials/metadata to the target endpoint; an invalid or revoked credential can still need hiding. Do not gate redaction on successful authentication or query live services for this report. Source reuse requires a separate license compatibility review; conceptual comparison does not require importing its code.

### scrubadub: compact span and replacement comparison

Its `Scrubber` coordinates detectors and post-processors; `Filth` stores ranges, detector/document identity and replacement information. Borrow the explicit handoff from finding to replacement and compare overlap/provenance cases. Python string indexes are not redact's UTF-8 byte contract, so no direct offset substitution should be assumed. [Scrubber source](https://github.com/LeapBeyond/scrubadub/blob/master/scrubadub/scrubbers.py), [Filth source](https://github.com/LeapBeyond/scrubadub/blob/master/scrubadub/filth/base.py).

**Fit:** small offline PII/reference harness candidate; accuracy, release health and latency were not evaluated. Apache-2.0 license verified; no adoption or maintenance-strength claims are inferred from popularity. [License](https://github.com/LeapBeyond/scrubadub/blob/master/LICENSE).

### Pydantic Logfire scrubber: relevant structured telemetry practice

The SDK documents scrubbing before export, key/value patterns, and callbacks with structural paths for exceptions. It explicitly distinguishes templated fields from already-formatted message text; some URL and query attributes are treated as safe. Borrow path-scoped exceptions and tests for structure lost through formatting. Do not inherit its safe-key list into terminal text, where URL credentials and arbitrary messages are in scope. [Official scrubbing guide](https://pydantic.dev/docs/logfire/instrument/python/scrubbing/).

**Fit:** architectural reference, not a telemetry service proposal or a runtime dependency. No code reuse is proposed, and its full dependency/license inventory was not reviewed. This is the single additional local scrubbing implementation beyond the requested comparison set.

## Priorities and bounded experiments

### Borrow now

1. Document the four-stage policy and class-specific propagation rules. Inventory `remember` and vault seeding together, starting with ordinary-word names, profile text, and user-selected values. Verify that weak occurrences cannot become session-global seeds through another layer.
2. Add synthetic regressions to the existing issue work: full candidate boundaries, host/path lookalikes, ambiguous names, nested structure, explicit values, encoded input, and restored outputs. Use separate direct-detection and propagation assertions. No new production confidence engine is required for this step.
3. Preserve fail-closed scans, span coverage, literal-tag isolation and handed-value echo protection. Measure accidental withholding as a usability failure as well as testing leak prevention. Keep imported-rule filters explicit and versioned.

### Small experiments later

| Experiment | Question answered | Limit and decision evidence |
| --- | --- | --- |
| Propagation policy A/B | How much useful bare-value recall is lost when ambiguous names are occurrence-only? | Run scanner-only and multi-result vault replays; compare case-sensitive identifier matching and explicit-user values separately. Adopt only with per-class miss/amplification counts. |
| YAML/URL extraction helpers | Can strong structure reduce accidental redactions without reducing known secret coverage? | Extend #88/#77; original-byte spans, malformed-input tests and unchanged surrounding syntax. No whole-input reserialization. |
| Bounded decoding | Which escaped/encoded leaks can be caught without hiding ordinary encoded artifacts? | Extend #79, one representation/depth at a time, decoder limits and mapping tests; no recursive catch-all default. |
| Offline PII/name comparator | Does a recognizer improve specifically identified free-text misses enough to justify cost? | Presidio/scrubadub in a separate research harness with fixed versions; no network verification, no production dependency until measured. |
| Value-free evidence trace | Can every propagated false positive be traced to its seed and policy? | Synthetic cases only first; review metadata leaks and per-result overhead before changing public output. |

### Avoid

Avoid a larger common-word denylist as the main solution; treating entropy/checksums as proof of sensitivity; importing rule syntax while silently discarding semantics; global case folding of credentials; unbounded recursive decoding; live verification in the scan path; and automatic restoration of arbitrary answer code blocks. Avoid a speculative parser/ML rewrite before the small experiments establish a benefit. Keep command parsing claims bounded: parsing a visible argument list does not establish what an arbitrary shell script will execute.

## Synthetic corpus and measurement plan

This section proposes a benchmark; it reports no new performance or accuracy results.

Although the product protects terminal/AI information streams, the inspected scanner processes one complete input string and the hook batches texts into a process call. Do not assume incremental chunk detection. If transport chunking is introduced, add tokens split across chunks, delayed context, and bounded buffering to the acceptance matrix before claiming equivalent protection. [scan.rs:162](../../src/scan.rs#L162), [vault.ts:254](../../claude-plugin/hooks/vault.ts#L254).

Create versioned, deterministic fixtures with synthetic values only, plus a manifest containing source kind, value class, locale, pack configuration, direct sensitive byte ranges, permissible propagated ranges, forbidden benign ranges, expected restoration capability and scope. Annotation is policy-led, not generated from current detector output. Ambiguous cases have separately named policy variants rather than silently changing ground truth.

Start with 240 base scenarios: 40 credential, 40 person/profile/PII, 40 infrastructure identifier, 40 explicit env/dotenv/list, 40 benign instruction/code/path, and 40 integration/restoration scenarios. Apply applicable formatting/encoding variants rather than forcing every scenario into every syntax. Split by template family and value family into development and held-out sets; reserve 20% for held-out evaluation. Hand-review expected offsets and ambiguity labels. Generate all credential-shaped strings locally; never use published test keys that might be live or call a verification endpoint.

Required paired families:

- Azure names, GCP names, repos and GitHub logins that equal ordinary words (`skills`, `release`) or longer skill/path identifiers; include prose before and after the seed, case variants, underscores, hyphenated continuations, and a long benign document with one false seed.
- High-confidence contextual names paired with the same bare string in unrelated instructions. Include forged structured records from an untrusted tool, trusted user configuration, separate results in one session, and a new session. Scope is part of expected behavior.
- Credential-shaped tokens, low-entropy named passwords, references/masks, short and numeric explicitly selected values, setting-like env values, allow/hide conflicts, multiline dotenv values, literal `#`, punctuation and whitespace in word-list phrases.
- JSON nesting/reordering/duplicate keys, escaped keys/values, incomplete objects; YAML blocks, indentation indicators, siblings, flow maps; URLs with userinfo, fragments, percent escapes, lookalike hosts, IPv6 and query separators; quoted CLI arguments and mixed shell text. Mark unsupported forms explicitly.
- Phone/table context, numbers after unrelated clue words, card checksum positive/negative, dotted versions versus IPs; person names with non-ASCII case, composed/decomposed spelling, emoji preceding a hit, CRLF and multibyte characters around every span boundary.
- Overlapping URL/password/token/name findings and repeated substrings; live and literal placeholders, tool echo/full/slice/encoded output, vault reload, delegated live tags, allowed/disallowed restoration hosts, shell-active characters, public attribution, and user-copyable reply commands.

| Measurement | Definition / proposed acceptance |
| --- | --- |
| Misses | Per-class occurrence recall and fully covered sensitive-byte recall. Count partial captures as failures when any required bytes remain, even if a finding exists. No regressions on agreed credential positives. |
| Accidental redactions | Benign occurrences and benign bytes removed, per class/source/representation; include total withholding. Precision alone must not hide rare catastrophic instruction loss. |
| Propagation amplification | For each false seed, count additional benign occurrences/bytes hidden, maximum across the corpus, and persistence across later results. Report direct false positives separately. Proposed hard gate: weak seeds cause zero downstream hides under occurrence-only policy. |
| Syntax/tool usability | Parse validity where promised, unchanged delimiters/keys, exact restoration round trip, synthetic command argument equality, attribution preserved according to policy, and rate of unusable copyable commands. Do not execute synthetic network commands. A placeholder can preserve JSON parsing while still making a tool unusable. |
| Offsets | Every range slices the intended original UTF-8 bytes, lies on character boundaries and maps correctly through JS UTF-16, escapes and encoded views. Zero offset/syntax corruption tolerated in fixtures. |
| Explainability | Every propagated range references a seed and rule/source policy; overlap contributors remain attributable without exposing source values. |
| Latency/memory | Cold end-to-end startup/config/compile/scan and hook result latency separately; p50/p95 over 30 independent processes at 1 KB, 20 KB, 200 KB, 1 MB, plus 10 MB stress. Record machine/OS/build/profile, shim versus direct invocation, pack set, unique remembered values and peak RSS. Compare both revisions in isolated clean snapshots; do not attribute branch differences to one patch. |

First freeze current behavior on the synthetic corpus, then compare one policy change at a time. Run pack-isolated cases and default/all-enabled configurations to expose detector interactions. Add high-cardinality word lists, dense overlapping hits, many distinct emails, long lines and deep/incomplete structure to performance tests. Hook tests must distinguish scanner work from serialization, process launch, vault searches and slice matching. A provisional latency alert of more than 10% p95 regression can flag review, but it is not an established product SLA; use the existing #39 gate when considering a server.

### Observed results versus proposals

No new scanner run, third-party benchmark, or accuracy evaluation was performed for this report. The prior [GCP report's baseline](./gcp-project-detection.md#measured-baseline-supplied-by-the-parent) attributes exploratory probes to its parent: local paths seeded `skills`; malformed candidates yielded partial `fabrikam`; lookalike authorities matched; project numbers did not. Those observations motivate cross-class fixtures but establish no whole-system error rate.

The [current pipeline documentation](../reference/how-it-works.md) reports about 1.3 s for 9 MB nested JSON and 0.9 s/150 MB for 15 MB email-dense text on one laptop. [#39](https://github.com/Drewtopia/redact/issues/39) records a different version/platform's startup/setup measurements. Neither is a controlled comparison with the proposed architecture or an external tool. Preserve these as historical baselines with their limitations, not acceptance thresholds or fresh measurements.

## Product decisions still required

These cannot be settled by regex research alone; no implementation or approval is requested in this report.

- Which infrastructure/person/profile classes should be hidden by default, and is bare free-text name discovery a product goal? Private organizational context and active credentials have different costs of misses and accidental hides.
- When a valid name is also an ordinary word, is bare-occurrence recall worth instruction/command loss? Should weak direct occurrences remain visible, or be hidden only at their source?
- Does explicit hide intent override length/setting filters and allowlists? Are exact bytes, case-insensitive names and intentional substrings distinct user choices?
- Which sources may seed input-, result-, or session-wide matching? Does a value merely retained for restoration qualify, and how are poisoning/reset/expiry handled?
- How should users receive runnable commands containing private paths? A local reveal/copy operation, a marked non-runnable example, and a public restored answer have different disclosure properties. Resolve #104 together with #81 rather than silently restoring fences.
- What accuracy/usability/latency budget is required per class and integration? The corpus can measure tradeoffs; it cannot choose them.

## Checks and limitations

Checked local source/docs and branch differences; read the linked roadmap and eight related issues without modifying them; consulted original project documentation/source and the licenses cited above. External links were accessed on the report date and mostly point to moving branches. Pin release/commit references before copying code or building a reproducible comparator. Upstream README assertions describe upstream projects; they are not independent performance evidence.

Some direct documentation/GitHub fetches failed; working canonical links or raw first-party source were used instead. No external project was installed, no credential was verified, and no real record was used. This is a sampled architecture/policy review, not proof of comprehensive protection, a full license audit, or a recommendation to replace the scanner. No code, issue, label, commit, release, or published artifact was changed.
