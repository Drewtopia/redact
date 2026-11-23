# GCP project detection: context, token boundaries, and propagation

Date: 2026-11-17. Drafted by Codex, an AI agent.

Research for [issue #109](https://github.com/Drewtopia/redact/issues/109). This is a research report and proposed acceptance matrix, not an implementation. All example identifiers and paths below are synthetic; no example project was looked up.

## Recommendation

Fix two independent sources of damage together: accepting `projects/<id>` inside an obvious filesystem path, and remembering a weak or partial match across the entire input. First tighten context and complete-token boundaries, and stop weak path matches from seeding propagation. Preserve explicit relative resource names as a separate, lower-confidence case. Follow up with verified Google URL/full-name context, stronger structured fields/commands, and project-number/legacy-ID coverage. These priorities are engineering recommendations based on the sources and observations below, not requirements imposed by Google.

Do not solve this only by adding `skills` to a denylist, requiring a hyphen/digit, or requiring another slash after the ID: those choices respectively leave the general cause, reject valid alphabetic IDs, or miss project-only resource names. Google's project syntax allows alphabetic IDs, and Pub/Sub explicitly documents `projects/{project-id}` as a request value. [Project constraints](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects), [Pub/Sub source: ListTopicsRequest](https://github.com/googleapis/googleapis/blob/master/google/pubsub/v1/pubsub.proto#L1013-L1021).

## Local state and evidence

The parent checked open PRs, branches, and live sessions before dispatch: no overlap; #109 unassigned. This researcher did not repeat those network/session checks or change GitHub state.

Inspected branch `bugfix/redaction-review`, HEAD `4c08742d40c477edf95c71980eece3956ffcf9da`; local `origin/main` ref `4be4155a82438ae76986baf32166b169d644b3a3`. No fetch was performed, so “origin/main” means that local snapshot. The GCP regexes and remember settings are identical between these refs. The branch removes 24 lines of pack-embedded fixtures/matrix settings; it also has substantial scanner/pack changes, so it is not equivalent to running main. `chosen_name`, `common_word`, and `distinctive` have the same relevant definitions on both refs. Observed using `git show`, `git diff`, and `git rev-parse`; current sources: [gcp.toml:15](../../packs/gcp.toml#L15), [scan.rs:32](../../src/scan.rs#L32). Existing unrelated worktree changes in `.claude/settings.json` and `docs/agents/issue-tracker.md` were left alone.

No established research directory was found in the inspected docs; the parent independently confirmed no notes convention on either ref. This report creates `docs/research/`.

Current behavior, from source:

- `project-path` accepts a leading non-ASCII-word character, including `/`, then `projects/`, a 6–30-character ID-shaped capture, and `\b`. It does not validate any preceding URL authority or filesystem prefix. `project-flag` also ends in `\b` and is not scoped to `gcloud`. The field regex has global `(?i)`, making the value case-insensitive too. All three use `remember = "any"`. [gcp.toml:15–39](../../packs/gcp.toml#L15).
- `any` is filtered, not unconditional: uppercase or at least five characters, excluding a fixed common-word list. `skills` is absent. `distinctive` instead looks for whitespace, punctuation such as `-_.`, digits, or an inner capital; it is not a cloud-confidence check and does not use that common-word filter. [scan.rs:32–55](../../src/scan.rs#L32).
- Matches are collected, then remembered values are matched throughout the same scan input, including earlier text. Propagation is ASCII-case-insensitive and permits punctuation/underscore boundaries; a remembered ID can also match within a larger hyphenated name. It is not a persistent cross-run project registry. [scan.rs:175](../../src/scan.rs#L175), [scan.rs:265](../../src/scan.rs#L265), [scan.rs:389–425](../../src/scan.rs#L389), [pipeline docs](../reference/how-it-works.md#one-pass).
- The existing pack schema already supplies per-rule remembering, `within`, `exceptMatch`, and `context`; new confidence infrastructure is not necessary to split strong and weak rules. `context` is only a proximity heuristic (up to 100 bytes on the line/previous line), not proof of a field, command, or host relationship. [pack schema](../../src/pack.rs#L58), [pack authoring](../packs/writing.md#fields), [scan.rs:335](../../src/scan.rs#L335).

### Measured baseline supplied by the parent

The parent reports `cargo build --offline` passed and `target/debug/redact` identified itself as 0.2.1 on this branch. Independent synthetic inputs were piped through:

```sh
target/debug/redact scan --only-files -f packs/gcp.toml --json
```

These are exploratory probes, not committed regression tests. This researcher did not rerun them. In rows mentioning propagation, the input also contained a standalone copy of the value.

| Input/context | Parent-observed result |
| --- | --- |
| `~/Developer/projects/skills`, followed by prose `skills` | Two `skills` matches |
| `/home/example/projects/skills`, `../projects/skills`, `C:/work/projects/skills` | Each seeds `skills` propagation |
| `C:\work\projects\skills` | No match |
| `projects/fabrikam-demo/locations/eu` plus prose `fabrikam-demo` | Two matches |
| `https://compute.googleapis.com/compute/v1/projects/fabrikam-demo/...` | Project matches |
| `https://compute.googleapis.com.example.org/projects/fabrikam-demo/...` | Project also matches; no host validation |
| `projects/123456789012/locations/eu` | No match |
| `projects/` followed by a 31-letter ID | No match |
| `projects/fabrikam-demo_invalid/locations/eu` | Captures `fabrikam`, not the complete token |
| `projects/fabrikam.demo/locations/eu` | Captures `fabrikam` |
| Strong legitimate match plus prose `FABRIKAM-DEMO` | Uppercase copy is also redacted |

The malformed-token cases are particularly important: shortening a greedy capture to end before an internal hyphen can satisfy `\b`, even when the full candidate fails. This describes observable matching semantics, not a claim that Rust's engine uses recursive backtracking. A no-match for one 31-letter example does not establish rejection of every overlong token; an overlong token with internal hyphens needs its own fixture. Rust defines `\b` using word characters, rather than GCP identifier delimiters. [Rust regex syntax](https://docs.rs/regex/1.13.1/regex/#syntax).

## What Google actually names

### Relative names, full names, and request URLs are different contexts

An AIP relative name has no leading slash and is scoped to an API; a full resource name adds `//` and the service name. A request URL adds HTTPS, version, and endpoint routing. A full name's service identity is distinct from its possible regional or mTLS endpoints. Thus `projects/fabrikam-demo/topics/events`, `//pubsub.googleapis.com/projects/fabrikam-demo/topics/events`, and `https://pubsub.googleapis.com/v1/projects/fabrikam-demo/topics/events` must not be treated as one interchangeable prefix grammar. [AIP-122: full resource names and resource URIs](https://google.aip.dev/122#full-resource-names).

Pub/Sub's schema defines both topic names and project-only request parents. Requiring a child collection would lose the latter. Requiring hosts everywhere would lose ordinary gRPC/JSON relative names. Conversely, `projects/skills` could be either a local relative directory or a resource reference: syntax alone cannot settle that. [Pub/Sub Topic and ListTopicsRequest](https://github.com/googleapis/googleapis/blob/master/google/pubsub/v1/pubsub.proto#L846-L878), [project request field](https://github.com/googleapis/googleapis/blob/master/google/pubsub/v1/pubsub.proto#L1013-L1021).

Request paths are service-specific. Compute uses `https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances`; Resource Manager uses `/v3/{name=projects/*}`. A generic “host then `/v1/projects/`” rule would lose supported shapes. [Compute REST reference](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/list#http-request), [Resource Manager source](https://github.com/googleapis/googleapis/blob/master/google/cloud/resourcemanager/v3/projects.proto#L34-L48).

### IDs, numbers, and legacy IDs

The current capture encodes modern project ID length/character rules: 6–30 lowercase ASCII letters/digits/hyphens, letter first, no trailing hyphen. It does not establish existence, uniqueness, or all creation restrictions. Avoid a detector denylist for restricted creation words: recognition of existing identifiers is a different task from validating a new project request. [Resource Manager project_id source](https://github.com/googleapis/googleapis/blob/master/google/cloud/resourcemanager/v3/projects.proto#L311-L317), [creation constraints](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects).

Project numbers are distinct, system-generated identifiers. Resource Manager v3's canonical project `name` uses a generated int64 number after `projects/`; `project_id` is a separate field. Supporting modern ID spelling alone therefore misses real project resource names. Do not assume a fixed 12-digit rule from examples; the consulted schema specifies int64, not exactly 12 digits. Prefer numeric support only in strong project context and avoid propagation into arbitrary numbers. [Resource Manager Project source](https://github.com/googleapis/googleapis/blob/master/google/cloud/resourcemanager/v3/projects.proto#L302-L317).

Legacy domain-scoped IDs contain a domain plus colon, such as `example.com:fabrikam-demo`; new domain-scoped projects cannot be created. Artifact Registry additionally documents a domain/project slash transformation for Docker digest references. That transformation is specific context, not permission to accept arbitrary colons or local drive paths. Add legacy coverage separately with whole-token validation and explicit fixtures; the consulted source does not establish a universal legacy length/escaping grammar for every API. [Artifact Registry: domain-scoped projects](https://docs.cloud.google.com/artifact-registry/docs/docker/names#domain-scoped_projects).

### Identifiers and privacy policy

Google warns against putting sensitive information in project IDs because references expose them. A project ID is therefore an identifier, not itself evidence of a bearer credential; project access still requires permissions. Redacting IDs can serve redact's infrastructure/privacy policy without giving them the same blanket propagation treatment as access tokens. Keep `PROJECT` distinct from `SECRET`. This policy conclusion is an inference from [Google's exposure warning](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects) and [GetProject's permission requirement](https://github.com/googleapis/googleapis/blob/master/google/cloud/resourcemanager/v3/projects.proto#L39-L43); it does not mean real IDs can never disclose sensitive context.

## Prioritized changes and tradeoffs

### P0: minimal issue fix, without a scanner redesign

1. **Require complete candidate boundaries in path and flag rules.** Use positive, context-appropriate terminators after the capture, outside `secretGroup`: resource separator `/`, end of value/input, or a recognized wrapper boundary. A flag value should end as an argument, not as an arbitrary punctuation fragment. Reject underscore, dot, percent escape, colon, trailing hyphen, uppercase extension, and overlength continuations rather than accepting an earlier valid prefix. JSON field values already have a closing quote, but scope case-insensitivity to the key instead of the entire value. Do not mechanically replace `\b` with a broad negated class: allowing dot as a terminator still accepts a malformed ID prefix. [Current rules](../../packs/gcp.toml#L18), [Rust syntax](https://docs.rs/regex/1.13.1/regex/#syntax).
2. **Stop accepting arbitrary slash-prefixed substrings.** A relative-name rule should start at an explicit token boundary, not inside `/home/.../projects/...`, `../projects/...`, `C:/...`, or an unrelated URL path. Preserve full names and Google URLs through explicit alternatives/rules, rather than relying on the permissive slash boundary. A rule that merely disallows `/` immediately before `projects` will break valid API URLs unless those alternatives are supplied. [Current rule](../../packs/gcp.toml#L27), [AIP naming distinctions](https://google.aip.dev/122#full-resource-names).
3. **Disable remembering for residual weak relative names by omitting `remember`.** This bounds damage for still-ambiguous strings such as standalone `projects/skills`. `distinctive` is a smaller mitigation for alphabetic words, but still propagates a false-positive directory named `client-work` or `build2026`. Use it only if that remaining risk is explicitly accepted. Keep strong structured rules separate so they can retain independently chosen propagation. [Remember defaults](../../src/pack.rs#L22), [current heuristics](../../src/scan.rs#L32).
4. **Preserve capture offsets and gating.** Rust regex has no general lookahead/lookbehind; match accepted trailing delimiters outside the secret group. The scanner resumes from the capture end, allowing delimiter reuse for adjacent matches. Ensure the pack/rule keyword prefilter admits every newly supported literal representation. Do not run a blanket path normalization/JSON unescape pass without mapping spans back to original bytes. [Rust regex overview](https://docs.rs/regex/1.13.1/regex/), [scanner iteration](../../src/scan.rs#L208), [keyword gates](../../src/scan.rs#L178).

A hotfix can omit new URL rules only by explicitly accepting a temporary recall regression. The recommended coherent small patch preserves the measured Compute URL positive while rejecting local paths and lookalike authorities. It need not inventory every Google API. Exactly which uncommon URL shapes to support remains follow-up work.

### P1: stronger context and controlled propagation

**Google URLs/full names:** validate the complete authority before extracting a project path. Prefer a parsed host check where a parser is already available; otherwise use narrow, bounded regex alternatives with negative fixtures. A substring containing `googleapis.com` is insufficient. Require exact hostname labels/end of authority, account deliberately for host case and port policy, and reject userinfo, unrelated schemes, malformed labels, and suffix lookalikes as confidence evidence. Never allow a rejected URI to fall through to an inner relative-name match. These are proposed acceptance rules, not a claim that every rejected URL is technically invalid.

For an initial bounded policy, accept documented service hosts ending at `.googleapis.com` and known service path forms; consider an allowlist for propagation. Domain membership alone neither proves the service exists nor validates its API grammar. Endpoint coverage must consider regional/multi-regional `.rep.googleapis.com` and private `.p.rep.googleapis.com` forms; one single-label service-host regex is incomplete. [Google endpoint overview](https://docs.cloud.google.com/docs/security/compliance/endpoints). Private Google Access also involves DNS configuration; do not try to infer a resource's identity from DNS resolution or make network calls while scanning. [Private Google Access documentation](https://docs.cloud.google.com/vpc/docs/configure-private-google-access).

**Fields:** keep explicit `project_id`/`projectId`/`quota_project_id`, with valid complete values; promote propagation confidence when object context is Google-specific. A service account key has `type: service_account` and `project_id`, while gcloud ADC can have `type: authorized_user` and `quota_project_id`. Requiring the former for every field would lose the latter. [Google key format](https://docs.cloud.google.com/iam/docs/keys-create-delete), [AIP-4113 credential file](https://google.aip.dev/auth/4113#credentials-generation). Generic `name`, `parent`, and `project` keys alone remain ambiguous; require a recognized Google resource shape or object context rather than treating the key as proof. Existing `within` matches an object's own fields, which is useful but must be checked with nesting and field-order fixtures. [Local record handling](../../src/scan.rs#L57).

**Commands:** anchor `--project` to an actual option token and require the complete value. For high confidence, associate it with a `gcloud` invocation, including quoted values and global flags before/after subcommands. A nearby word `gcloud` on a different command is weak evidence; do not present `context = ["gcloud"]` as shell parsing. Follow-ups can recognize `gcloud config set project`, `core/project` output, and `--billing-project`, all documented by Google. [gcloud global flags and project configuration](https://docs.cloud.google.com/sdk/gcloud/reference#--project). Preserve generic `--project` only as an explicitly weaker detector, since other tools use that option.

**Propagation policy:** implement confidence initially through separate rules, not a new scoring framework. Weak relative context: redact that occurrence only. Strong Google field/URL/command: retain current propagation for compatibility, or conservatively use `distinctive` for project IDs; numeric IDs: occurrence only. The latter conservative option leaves bare alphabetic project IDs visible elsewhere. Even a confirmed project called `skills` is still the ordinary English word elsewhere; confidence establishes identity at the source occurrence, not the meaning of every repetition. If propagation boundaries later become identifier-aware or case-sensitive, scope that work to project identifiers rather than changing all remembered names. Current underscore/hyphen and ASCII-case behavior has wider uses. [Word matcher](../../src/scan.rs#L389).

### P2: coverage extensions after the regression fix

Add project numbers and legacy domain IDs in strong contexts; add YAML/config and quoted CLI forms; consider JSON-escaped slashes. Audit pack-level and rule-level keywords whenever extending syntax: raw `projects\/` does not contain literal `projects/`. Native Windows `\` separators should not become cloud-resource separators. A JSON-encoded Windows path and an escaped forward-slash Google resource name need different treatment. These are proposed detector policies; no new encoding coverage was tested in this research. [Current keywords](../../packs/gcp.toml#L5), [keyword documentation](../packs/writing.md#pack).

## Proposed fixture matrix

This table is an acceptance proposal, **not observed results**, except where the baseline above separately reports the same example. Run GCP-only cases first, then the default pack set to distinguish overlapping detectors. Each propagation case should place prose copies both before and after its source, include two independent projects, and check exact captured bytes, original offsets, rule attribution, and unmodified surrounding text.

| Synthetic input or class | Proposed expectation / decision |
| --- | --- |
| `~/Developer/projects/skills` + `skills` | Neither occurrence redacted by the GCP pack |
| `/home/example/projects/client-work`, `../projects/skills`, `./projects/skills`, `C:/work/projects/skills`, UNC/mixed paths | No GCP project seed; include distinctive directory names |
| `C:\work\projects\skills` and its JSON string representation | No GCP project seed; preserve baseline native-Windows non-match |
| `projects/skills` + prose `skills` | Ambiguous: occurrence-only under retained weak rule; prose remains |
| `projects/fabrikam-demo/locations/eu` + bare ID | Preserve source match; weak rule alone does not propagate under proposed default |
| `projects/fabrikam-demo`, `"parent":"projects/fabrikam-demo"` | Preserve occurrence detection; project-only names are legitimate; generic key alone does not promote confidence |
| `//pubsub.googleapis.com/projects/fabrikam-demo/topics/events` | Full-name rule captures complete ID; propagation policy explicit |
| `https://compute.googleapis.com/compute/v1/projects/fabrikam-demo/zones/eu/instances` | Preserve documented API URL shape |
| `https://pubsub.googleapis.com/v1/projects/fabrikam-demo/topics/events` | API URL case; terminal ID, slash, query/action terminators tested separately |
| Documented regional/private endpoint hosts, uppercase host, optional port | Add under explicit host policy, not accidental fallback |
| `https://compute.googleapis.com.example.org/projects/fabrikam-demo/x` | No strong match and no inner-relative fallback |
| `https://compute.googleapis.com@example.org/projects/fabrikam-demo/x`, `https://example.org/googleapis.com/projects/fabrikam-demo/x` | No strong match or propagation |
| Non-Google URL with `/projects/skills`; malformed/empty host labels | No GCP inference from an inner path |
| `projects/fabrikam-demo_invalid/x`, `projects/fabrikam.demo/x`, `projects/fabrikam-demo-/x` | Reject entire malformed candidate; never capture a shorter prefix |
| 5/6/30/31-character IDs, overlong IDs with internal hyphens, digit-first, Unicode, uppercase extensions | Enforce full modern token shape; boundary lengths exercised explicitly |
| `projects/fabrikam%2Ddemo/x`, legacy `projects/example.com:fabrikam-demo/x` | Unsupported encoded/legacy candidates must not become partial modern-ID captures |
| `{"project_id":"skills"}` with/without service-account context | Occurrence match; independently assert chosen strong/weak propagation policy |
| `{"projectId":"FABRIKAM-DEMO"}` | Modern ID validator rejects uppercase value; key casing handled separately |
| Service account / authorized-user JSON, nested distractor fields, reordered fields | Preserve appropriate field detection; no sibling/child-object confidence borrowing |
| `gcloud run deploy --project=fabrikam-demo`, `--project fabrikam-demo`, quoted values | Complete argument captured; quoted coverage is a follow-up if omitted from fix |
| `tool --project skills`, `--project=fabrikam.demo`, `--project==fabrikam-demo`, `--projected=fabrikam-demo`, `prefix--project=fabrikam-demo` | Generic-tool case weak at most; malformed or non-option cases rejected |
| `projects/123456789012/locations/eu`, strong JSON project-number field | Follow-up captures number only in explicit project context; no global number propagation |
| Raw JSON `"name":"projects\/fabrikam-demo\/topics\/events"` | Explicit encoding coverage decision; keyword gate and original byte offsets checked |
| Literal `\nprojects/fabrikam-demo/x`, actual newline, quotes/backticks/brackets | Preserve intended text wrapper boundaries; no path-prefix bypass |
| Strong source plus `FABRIKAM-DEMO`, `fabrikam-demo_extra`, `fabrikam-demo-other` | Lock down case/identifier-boundary policy; current whole-word propagation is broader than identifier equality |
| Two adjacent resource names sharing punctuation/whitespace | Both matches found even with consumed suffix delimiters |

## Remaining ambiguity and limits

- A bare local relative path and an API-relative name can have identical bytes. No regex can infer intent from `projects/skills` alone. The proposed compromise preserves a direct match and bounds propagation; a stricter product choice would leave weak occurrences visible.
- Even an allowlisted host in a pasted string is evidence of format, not proof that a resource exists. Do not query live project registries, credentials, or DNS as part of detection.
- Rejecting punctuation after an ID prevents partial captures but may miss a valid resource mention ending a prose sentence. Prefer recognized wrappers or whole-candidate extraction; decide punctuation cases explicitly instead of letting `\b` decide accidentally.
- Field names and `gcloud` command text can appear in documentation, fixtures, or unrelated data. They improve confidence without proving secrecy. Strong propagation can still over-redact ordinary English.
- Endpoint allowlists trade coverage for precision and need maintenance; accepting every `.googleapis.com` label trades the other way. Private/custom endpoints and legacy encodings are not exhaustively catalogued here.
- Sources were read online on the report date. `googleapis` links point to moving `master`; pin source revisions before making an enduring compatibility specification. No third-party detector behavior is needed to establish the naming distinctions above.
- Checks by this researcher: read local agent/scanner/pack docs and relevant source; compared current branch with local `origin/main`; consulted linked primary sources; reviewed this report's scope and links. No tests or scanner probes were run by this researcher, and no code, issues, labels, commits, or releases were changed. Parent-provided probe evidence is attributed separately above.
