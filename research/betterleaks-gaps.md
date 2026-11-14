# Which Betterleaks v1.10.1 rules cover services redact's packs miss?

Research for [#48](https://github.com/Drewtopia/redact/issues/48), done on 2026-11-14. It repeats the method of [#22](https://github.com/Drewtopia/redact/issues/22) (gitleaks) against Betterleaks.

## Answer

Betterleaks v1.10.1 ships 466 rules. I made fake tokens from each rule's regex and fed them to redact built from `main` plus [PR #37](https://github.com/Drewtopia/redact/pull/37), with PR #37's `random-token` rule switched off.

- **Covered: 35.** redact hides the token wherever it appears. Examples: GitHub, the first GitLab PAT forms, OpenAI, Anthropic, Groq, Slack bot tokens, private keys, JWTs, Mongo URLs, Kubernetes Secret data.
- **Partly: 33.** redact hides some samples but not all. 5 of these are prefix rules that one small widening fixes: Stripe, xAI and three Slack forms. AWS is close to that: `AKIA` and `ASIA` are hidden, `A3T…`, `ABIA` and `ACCA` are not. The other 27 are vendor-name rules. They were hidden only when the sampled name happened to say key or token.
- **Missed: 397.** A missed token stays visible when it stands alone: a bare line, a log line, a neutral JSON field or a table row. Almost all of them are hidden once the value sits behind a name that says secret. With `export DEPLOY_TOKEN=…` and `{"api_key": "…"}`, 393 of the 397 were hidden by `env-dump` or `named-secret*`.
- **n/a: 1.** `pkcs12-file` matches file paths, not text.

How the 466 rules sort for building in, by the bar in [#26](https://github.com/Drewtopia/redact/issues/26):

| Class | Rules | What it means |
|---|---|---|
| Covered | 35 | Nothing to do |
| Partly, widen an existing rule | 5 | Stripe, xAI, Slack `xoxe-` / `xoxo-` forms (see [Widen existing rules](#widen-existing-rules)) |
| **Built in, top 30 families** | 99 | Distinctive fixed prefix or structure. Zero false hits on a 74 MB corpus (see [False hits](#false-hits)) |
| Built in, later | 69 | Same safety as above, but the services rarely show up in a developer's terminal |
| Import only | 239 | Needs a vendor-name keyword, an entropy check or an allowlist, or the prefix is too short or ordinary |
| Not a secret | 18 | Hostnames, client IDs and public keys (`*.jfrog.io`, `phc_` PostHog project keys, Supabase URLs) |
| n/a | 1 | `pkcs12-file` |

### Top 15 built-in candidates

Ranked by how often the token reaches a developer's terminal (CLI login output, CI logs, config files, `git remote -v`) and by how much redact lets through today. All are missed today unless the row says partly.

| # | Family | Betterleaks rules | Pack | Proposed rule id |
|---|---|---|---|---|
| 1 | npm access tokens (`npm_`) | 1 | `npm` | `npm-token` |
| 2 | GitLab tokens beyond `glpat-`: `glrt-`, `glcbt-`, `gldt-`, `glft-`, `glptt-`, `gloas-`, `glagent-`, `glimt-`, `glffct-`, `glsoat-`, `GR1348941`, `_gitlab_session=`, and the versioned `glpat-….01.…` form | 14 | `credentials` | widen `gitlab-token` |
| 3 | Slack and Microsoft Teams incoming webhook URLs (`hooks.slack.com/services/…`, `….webhook.office.com/webhookb2/…`), and Slack `xapp-`, `xoxe-`, `xoxc-`, `xoxd-` | 7 | `credentials` | `chat-webhook`, and widen `vendor-key` |
| 4 | AWS key ids `A3T…`, `ABIA`, `ACCA` (partly today), and Bedrock API keys (`ABSK…`) | 3 | `credentials` | widen `aws-key`, add `aws-bedrock-key` |
| 5 | Docker Hub `dckr_pat_` / `dckr_oat_`, Docker Swarm `SWMTKN-1-` / `SWMKEY-1-` | 4 | `credentials` | `dockerhub-token`, `docker-swarm-token` |
| 6 | PyPI upload tokens (`pypi-AgEIcHlwaS5vcmc…`) | 1 | `credentials` | `pypi-token` |
| 7 | HashiCorp Vault `hvs.` / `hvb.` and Terraform Cloud `….atlasv1.…` | 3 | `credentials` | `vault-token`, `terraform-token` |
| 8 | Hugging Face `hf_` / `api_org_` | 2 | `credentials` | `huggingface-token` |
| 9 | Tailscale `tskey-api-` (see [v1.10.1 against v2 main](#v1101-against-v2-main)) | 1 | `credentials` | `tailscale-key` |
| 10 | Grafana `glc_`, `glsa_`, `eyJrIjoi` | 3 | `credentials` | `grafana-token` |
| 11 | Vercel `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | 5 | `credentials` | `vercel-token` |
| 12 | Supabase `sbp_`, `sb_secret_` | 2 | `credentials` | `supabase-key` |
| 13 | DigitalOcean `dop_v1_`, `doo_v1_`, `dor_v1_` | 3 | `credentials` | `digitalocean-token` |
| 14 | Cloudflare `cfut_` / `cfat_` API tokens, Origin CA keys `v1.0-…` | 2 | `credentials` | `cloudflare-token` |
| 15 | Sentry `sntrys_` / `sntryu_` | 2 | `credentials` | `sentry-token` |

### Families 16 to 30

Also built-in candidates, in rank order. All go in `credentials`.

| # | Family | Rules | Proposed rule id |
|---|---|---|---|
| 16 | AI keys not yet in `ai-key`: Perplexity `pplx-`, NVIDIA `nvapi-`, Cerebras `csk-`, Replicate `r8_`, Together `tgp_v1_`, LlamaCloud `llx-`, LangSmith `lsv2_pt_` / `lsv2_sk_`, Pinecone `pcsk_`, Cartesia `sk_car_`, W&B `wandb_v1_`, Gemini `AQ.Ab8RN6` | 12 | widen `ai-key` |
| 17 | Atlassian `ATAT`, Bitbucket Data Center `BBDC-` | 2 | `atlassian-token` |
| 18 | SendGrid `SG.` | 1 | `sendgrid-key` |
| 19 | Databricks `dapi` | 1 | `databricks-token` |
| 20 | Shopify `shpat_`, `shpca_`, `shppa_`, `shpss_` | 4 | `shopify-token` |
| 21 | Buildkite `bkua_` / `bk??_`, CircleCI `CCIPAT_` | 3 | `ci-token` |
| 22 | 1Password `ops_eyJ…` and `A3-…` secret keys | 2 | `onepassword-key` |
| 23 | age `AGE-SECRET-KEY-1…` | 1 | `age-key` |
| 24 | Linear `lin_api_`, Notion `ntn_`, Postman `PMAK-` | 3 | `linear-key`, `notion-token`, `postman-key` |
| 25 | PlanetScale `pscale_tkn_` / `_oauth_` / `_pw_`, Neon `napi_` | 4 | `planetscale-token`, `neon-key` |
| 26 | Fly.io `FlyV1`, Heroku `HRKU-AA`, Render `rnd_`, Deno `ddp_`, Doppler `dp.pt.`, Pulumi `pul-` | 6 | `deploy-token` |
| 27 | RubyGems `rubygems_`, Clojars `CLOJARS_`, NuGet `oy2…` | 3 | `registry-token` |
| 28 | OpenShift `sha256~` | 1 | `openshift-token` |
| 29 | PostHog personal keys `phx_` (not `phc_`, which is public) | 1 | `posthog-key` |
| 30 | Elastic Cloud `essu_`, Datastax `AstraCS:` | 2 | `elastic-key`, `astra-token` |

The 69 "built in, later" rules are in the [per-rule table](#every-rule). Each is cheap to add if a user asks for it.

### Widen existing rules

These five are partly covered. Each fix is one change to a rule redact already has:

- **Stripe** (`vendor-key`): add `prod` to `(?:live|test)`, and accept 10 to 15 characters after the prefix. Betterleaks takes `(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}`. redact needs 16 or more.
- **xAI** (`ai-key`, added in PR #37): redact wants `xai-` + 80 or more letters and digits. Betterleaks takes 70 to 120 characters, with `_` and `-`. An 80-character key with a `-` in it was missed.
- **Slack** (`vendor-key`): `xox[abprs]-` misses `xoxe-` (user and refresh tokens) and `xoxo-` (legacy). Widen the class to `xox[abeoprs]-`.
- **AWS** (`aws-key`): add `A3T[A-Z0-9]`, `ABIA` and `ACCA` beside `AKIA|ASIA`. This is family 4.
- **GitLab** (`gitlab-token`, PR #37): the versioned routable form `glpat-….<2>.<9>` keeps its last 12 characters visible. Make the tail `(?:\.[0-9a-z]{2})?\.[0-9a-z]{9}`. This is part of family 2.

### Import only

These need what redact does not give a built-in rule: a vendor-name keyword, an entropy threshold, or an allowlist.

- **Vendor-keyword rules (222).** Examples are `heroku-api-key`, `netlify-access-token`, `cloudflare-api-key.1`, `new-relic-*`, `box-api-access-token`, `typeform-api-token` and `lob-api-key`. They match `<vendor name>` + `=` or `:` + a value of fixed length. With a name that says secret, redact already hides the value (`env-dump`, `named-secret*`). Ported as they are, they would fire on any line that mentions the vendor. Their keywords include ordinary words (`box`, `lob`, `woo`, `mid`, `linear`).
- **Short or common prefixes**: `twilio-api-key` (`SK` + 32 hex, no left boundary), `octopus-deploy-api-key` (`API-`), `clickhouse-cloud-api-secret-key` (`4b1d`), `artifactory-reference-token` (`cmVmd`, which is base64 for "ref"), `facebook-*`, the `EAAA` branch of `square-access-token`, `exoscale-api-key` (`EXO`), `brave-search-api-key` (`BSA`), `resend-api-key.1` (`re_`), `salesforce-access-token.1` (`00…!`), `tableau-personal-access-token.1` (no prefix).
- **`generic-api-key`, `generic-password`, `hashicorp-tf-password`, `curl-auth-header`**: redact's `named-secret*` rules already cover this ground, and they work from the name, not from how random the value looks.

Almost every Betterleaks rule carries a CEL `filter`. 263 rules use `entropy(…)` and 151 use `filter.entropy(…)`; the typical form is `entropy(finding["secret"]) <= 3.0`. For prefix rules this is a sanity check against placeholder values such as `npm_xxxxxxxx…`. The prefix still does the work. PR #37's per-rule `entropy` field can carry the same threshold if wanted. It is not needed to keep false hits down (see [False hits](#false-hits)).

### Two side findings

- **Entra client secrets may be missed by redact today.** redact's `entra-client-secret` expects 3 characters, a digit, **one more character**, then `Q~`. Betterleaks' `azure-ad-client-secret` and gitleaks expect 3 characters, a digit, then `Q~` straight away. A fake secret in the Betterleaks shape (`abc8Q~` + 34) was not hidden. redact's pattern came from transcript-redactor (see [`docs/reference/thanks.md`](https://github.com/Drewtopia/redact/blob/main/docs/reference/thanks.md)). Check it against a real secret from the Entra portal before changing either.
- **`random-token` (PR #37) changes the picture a lot.** With it on, 138 rules that the automatic probe scored as missed move to covered (24) or partly (114). It is being moved to an opt-in pack, so it is excluded from the counts above.

## v1.10.1 against v2 main

v2 main at [`b4b1c44`](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/config/betterleaks.toml) (2026-11-13) has 476 rules. Of the 465 rules both versions share, 338 have a different regex. 334 of those differ only in the trailing delimiter group: v2 adds `)` to `[\s;]`, so a token is also found before a closing parenthesis. That does not matter for redact, which does not need the delimiter group. Generated samples cross-match 100% for those rules.

Four rules changed in a way that matters:

- **`tailscale-api-key.1` (built-in candidate 9): it matters.** v1.10.1 takes `tskey-api-[A-Za-z0-9_-]{20,36}`. v2 takes `tskey-api-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}`, the real key layout. v2 also adds `tailscale-auth-key`, `tailscale-key`, `tailscale-oauth-client-secret`, `tailscale-scim-key` and `tailscale-webhook-secret` (`tskey-auth-`, `tskey-client-`, `tskey-scim-`, `tskey-webhook-`). Build the redact rule from v2's shapes, or as one rule on `tskey-(?:api|auth|client|scim|webhook)-k…CNTRL-…`. The v1.10.1 regex alone misses auth keys, which are the Tailscale secret most often pasted into a terminal.
- **`mapbox-api-token`**: v1.10.1 needs the word `mapbox` before `pk.…`. v2 drops the keyword and matches `pk.eyJ1Ijoi…`. `pk.` tokens are public, so this is not a candidate. v2 also adds `mapbox-secret-token` (`sk.eyJ1Ijoi…`), which would be a built-in candidate if redact pins to v2.
- **`generic-api-key`, `generic-password`**: reworked, still import only.

v2 also adds `cypress-record-key` (keyword rule, import only) and `labelbox-api-key` (`lbx_`, built in, later). It replaces `cloudflare-api-key` with `cloudflare-api-key.1` (keyword rule).

## False hits

I put all 99 rules of the top 30 families into a trial pack, using the v1.10.1 regexes as written. Then I ran it over 74 MB of ordinary text: the redact repo's full `git log -p`, and every `.rs`, `.md`, `.toml`, `.txt` and `.json` file in `~/.cargo/registry/src` (228 crates, with plenty of hex test vectors). **The pack matched nothing.** A token I planted at the end of the file was found, which shows the scan ran to the end. I did not run the "built in, later" or import-only rules over it.

## Regex compatibility

Betterleaks matches with RE2 ([`betterleaks/go-re2`](https://github.com/betterleaks/betterleaks/blob/v1.10.1/go.mod)). I loaded each of the 465 v1.10.1 regexes into redact as a one-rule pack. **463 compile as they are.** Two fail with "Compiled regex exceeds size limit": `pypi-upload-token` (`[\w-]{50,1000}`) and `vault-batch-token` (`[\w-]{138,300}`). Rust's `\w` is Unicode-aware, so a bounded repeat of it is large. Use `[A-Za-z0-9_-]{50,}` and `[A-Za-z0-9_-]{138,}`, which is also what the trial pack used.

## Licence and attribution

Betterleaks is [MIT-licensed](https://github.com/betterleaks/betterleaks/blob/v1.10.1/LICENSE), "Copyright (c) 2026 Zachary Rice". Its README says it is "maintained by the folks who made Gitleaks, including the original author". gitleaks is also MIT, "Copyright (c) 2019 Zachary Rice". `config/betterleaks.toml` is generated: its header says to change rules in `cmd/generate/config/` instead, so cite the Go rule files as the source.

MIT asks that the notice go with "all copies or substantial portions of the Software". The safe reading is that a set of copied regexes counts. Do what redact already does for transcript-redactor:

1. Add the Betterleaks MIT notice to [`LICENSE-THIRD-PARTY`](https://github.com/Drewtopia/redact/blob/main/LICENSE-THIRD-PARTY), which ships in release archives.
2. Add a Betterleaks row to [`docs/reference/thanks.md`](https://github.com/Drewtopia/redact/blob/main/docs/reference/thanks.md) for the vendor token patterns. Add a sentence under "Third-party notices" naming the packs that adapt them, linked to `cmd/generate/config/rules/` at tag v1.10.1 (commit `39d5bdc`).
3. Optional: put `# adapted from betterleaks <rule-id> (v1.10.1)` above each ported rule, so a later sync can diff it against upstream.

If a rule is ported from the gitleaks version instead, the gitleaks notice applies too. #22 already covers that.

## Sources and method

- **Betterleaks v1.10.1**: [`config/betterleaks.toml`](https://github.com/betterleaks/betterleaks/blob/v1.10.1/config/betterleaks.toml) at tag `v1.10.1`, commit [`39d5bdc`](https://github.com/betterleaks/betterleaks/commit/39d5bdcf34db54e944facac5cf6e8b03db5e2b99) (2026-11-06). The file has 466 rules. Fields: `regex`, `keywords`, `filter` (CEL), `validate`, `confidence`, `skipReport` (component-only rules), `components` (composite rules), and `secretGroup` on 3 rules.
- **Betterleaks v2 main**: [`config/betterleaks.toml` at `b4b1c44`](https://github.com/betterleaks/betterleaks/blob/b4b1c4455987636400ce693bd9d8a8e2cf375ed9/config/betterleaks.toml).
- **redact**: built from `git merge-tree --write-tree origin/main origin/feat/vendor-keys-entropy`, that is, `main` at `bcdcd34` plus PR #37 at `2115965`. No branch was changed. The config was `[packs] disable = ["credentials:random-token"]`. The same probe against PR #37's branch alone gave the same verdict for every rule.
- **Probe** ([`research/betterleaks-probe/`](betterleaks-probe/)): `probe.py` parses each regex with Python's regex parser and generates 8 random matches. Letters and digits are preferred, and the trailing delimiter is left off. It takes the secret as Betterleaks does (`secretGroup`, or else the first group that matched). Each sample goes through `redact scan --json` in six contexts:
  - shape contexts, carrying the full match: a bare line, a log line, `{"id": "…"}`, and a table row
  - named contexts, carrying only the secret: `export DEPLOY_TOKEN=…` and `{"api_key": "…"}`

  A secret counts as hidden when no run of more than 6 of its bytes is left outside redact's spans, so a visible `glpat-` prefix is fine. A rule is *covered* when every sample is hidden in every shape context, *missed* when none is, and *partly* otherwise.
- **Hand checks** (`hand.py`): composite matches, where Betterleaks' secret is a whole URL or JSON object, were scored by the part that is secret. These are Mongo URLs, GCP service-account JSON, gcloud ADC JSON, Service Bus connection strings, Sidekiq URLs, Kubernetes Secret YAML, GitLab reply-by-email addresses and Teams webhooks. JWTs were also tested with a real `eyJ…` header. `report.py` records the overrides.
- **v1 against v2** (`diff.py`): cross-matches 40 generated secrets per rule in each direction, and compares the regexes with the delimiter group removed.
- **Classes**: `report.py` assigns them. "Built in" families are chosen by hand in `candidates.py`. Import-only and not-a-secret rules are listed by hand in `report.py`. The rest are sorted by whether the regex needs a vendor keyword before the value.

To rerun: fetch both configs, build redact, then run `probe.py` → `classify.py` → `candidates.py` → `report.py` (each script's docstring gives its arguments), with `diff.py`, `hand.py` and `rustcheck.py` alongside. Python 3.11 or later is needed for `tomllib`.

## Every rule

Columns: the probe verdict in shape contexts and in named contexts, the class, a note, and how the regex changed in v2 main.

| Betterleaks rule | Bare / log / JSON / table | Behind a secret name | Class | Note | v2 main |
|---|---|---|---|---|---|
| `1password-secret-key` | missed | covered | built in #22 | `credentials`: onepassword-key | same |
| `1password-service-account-token` | missed | covered | built in #22 | `credentials`: onepassword-key | same |
| `abuseipdb-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `adafruit-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `adobe-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `adobe-client-secret` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `age-secret-key` | missed | covered | built in #23 | `credentials`: age-key | same |
| `aikido-ci-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `aikido-client-id` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `aikido-client-secret` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `airtable-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `airtable-oauth-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `airtable-personnal-access-token` | missed | covered | import only | pat + 14 + . + 64 hex: `pat` is an ordinary word; needs the dot-and-hex shape kept whole | same |
| `aiven-auth-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `algolia-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `algolia-application-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `alibaba-access-key-id` | missed | covered | not a secret | identifier, host or public key | same |
| `alibaba-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `alibaba-sts-access-key-id` | missed | covered | import only | STS. + 16-64: short prefix | same |
| `alibaba-sts-access-key-secret` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `alibaba-sts-security-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `amplitude-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `anthropic-admin-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `anthropic-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `apify-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `apollo-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `artifactory-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `artifactory-jfrog-url` | missed | covered | not a secret | identifier, host or public key | same |
| `artifactory-reference-token` | missed | covered | import only | cmVmd + 59: base64 of 'ref', appears in ordinary base64 | same |
| `asaas-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `asana-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `asana-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `assemblyai-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `atlassian-api-token` | missed | covered | built in #17 | `credentials`: atlassian-token | end delimiter only |
| `auth0-client-id.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `auth0-client-secret.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `auth0-domain.1` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `authress-service-client-access-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `aws-access-token` | partly | covered | built in #4 | `credentials`: aws-key (widen) + aws-bedrock-key | same |
| `aws-amazon-bedrock-api-key-long-lived` | missed | covered | built in #4 | `credentials`: aws-key (widen) + aws-bedrock-key | end delimiter only |
| `aws-amazon-bedrock-api-key-short-lived` | missed | covered | built in #4 | `credentials`: aws-key (widen) + aws-bedrock-key | same |
| `aws-secret-access-key` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `azure-ad-client-secret` | missed | covered | import only | redact already has entra-client-secret; see the Entra note | same |
| `azure-app-configuration-connection-string` | covered | covered | covered | named-secret | same |
| `azure-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `azure-servicebus-connection-string` | covered | covered | covered | azure-storage-key hides SharedAccessKey= | same |
| `azure-storage-account-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `azure-storage-account-name` | partly | partly | import only | vendor keyword before the value (hidden in some probes, when the sampled name said key or token) | same |
| `azure-tenant-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `beamer-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `bitbucket-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `bitbucket-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `bitbucket-data-center-token` | missed | covered | built in #17 | `credentials`: atlassian-token | end delimiter only |
| `bitly-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `bitrise-access-token` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `bittrex-access-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `bittrex-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `box-api-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `brave-search-api-key` | missed | covered | import only | BSA + 24-40: short capital prefix | same |
| `browserstack-access-key.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `browserstack-username.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `buildkite-service-token` | missed | covered | built in #21 | `credentials`: ci-token | same |
| `buildkite-user-access-token` | missed | covered | built in #21 | `credentials`: ci-token | same |
| `canadian-digital-service-notify-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `canva-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `canva-client-secret` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `cartesia-api-key.1` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `cerebras-api-key` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `checkout-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `circleci-personal-token` | missed | covered | built in #21 | `credentials`: ci-token | same |
| `circleci-project-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `cisco-meraki-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `civo-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `clerk-secret-key` | covered | covered | covered | vendor-key | end delimiter only |
| `clickhouse-cloud-api-secret-key` | missed | covered | import only | 4b1d + 38: short hex-like prefix | same |
| `clickhouse-cloud-key-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `clickup-personal-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `clojars-api-token` | missed | covered | built in #27 | `credentials`: registry-token | same |
| `cloudflare-account-id.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `cloudflare-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | removed-in-v2 |
| `cloudflare-api-key.2` | missed | covered | built in #14 | `credentials`: cloudflare-token | end delimiter only |
| `cloudflare-global-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `cloudflare-origin-ca-key` | missed | covered | built in #14 | `credentials`: cloudflare-token | end delimiter only |
| `cloudinary-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `cloudinary-api-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `cloudinary-cloud-name` | missed | partly | import only | vendor keyword before the value | same |
| `cloudsmith-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `cockroachlabs-cloud-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `codecov-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `cohere-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `coinbase-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `configcat-sdk-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `configcat-sdk-key-extended` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `confluent-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `confluent-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `contentful-delivery-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `couchbase-capella-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `coveralls-personal-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `crates-io-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `curl-auth-header` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | same |
| `curl-auth-user` | missed | partly | import only | vendor keyword before the value | same |
| `cursor-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `databento-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `databricks-api-token` | missed | covered | built in #19 | `credentials`: databricks-token | end delimiter only |
| `datadog-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `datadog-application-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `datagov-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `datastax-astra-application-token` | missed | covered | built in #30 | `credentials`: elastic-key, astra-token | same |
| `deepgram-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `deepseek-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `defined-networking-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `deno-account-token` | missed | covered | built in #26 | `credentials`: deploy-token | end delimiter only |
| `devcycle-client-sdk-key` | missed | covered | not a secret | identifier, host or public key | same |
| `devcycle-mobile-sdk-key` | missed | covered | not a secret | identifier, host or public key | same |
| `devcycle-server-sdk-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `devin-personal-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `devin-service-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `devin-service-user-token` | missed | covered | import only | cog_ + 52 base32: short prefix | end delimiter only |
| `digitalocean-access-token` | missed | covered | built in #13 | `credentials`: digitalocean-token | end delimiter only |
| `digitalocean-pat` | missed | covered | built in #13 | `credentials`: digitalocean-token | end delimiter only |
| `digitalocean-refresh-token` | missed | covered | built in #13 | `credentials`: digitalocean-token | end delimiter only |
| `discord-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `discord-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `discord-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `disqus-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `docker-swarm-join-token` | missed | covered | built in #5 | `credentials`: dockerhub-token + docker-swarm-token | same |
| `docker-swarm-unlock-key` | missed | covered | built in #5 | `credentials`: dockerhub-token + docker-swarm-token | same |
| `dockerhub-organization-access-token` | missed | covered | built in #5 | `credentials`: dockerhub-token + docker-swarm-token | end delimiter only |
| `dockerhub-personal-access-token` | missed | covered | built in #5 | `credentials`: dockerhub-token + docker-swarm-token | end delimiter only |
| `doppler-api-token` | missed | covered | built in #26 | `credentials`: deploy-token | same |
| `droneci-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `dropbox-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `dropbox-long-lived-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `dropbox-short-lived-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `duffel-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `dynatrace-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `easypost-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `easypost-test-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `ebay-client-id` | missed | covered | not a secret | identifier, host or public key | same |
| `ebay-client-secret` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `elastic-cloud-api-key` | missed | covered | built in #30 | `credentials`: elastic-key, astra-token | end delimiter only |
| `elevenlabs-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `endorlabs-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `endorlabs-api-secret` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `etsy-open-api-key` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `exoscale-api-key` | missed | covered | import only | EXO + 24-30: short capital prefix | end delimiter only |
| `exoscale-api-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `facebook-access-token` | missed | covered | import only | digits + | or % + 27-40: URL-encoded query strings match | end delimiter only |
| `facebook-page-access-token` | missed | covered | import only | EAA + one letter: short prefix, relies on entropy 4.0 | end delimiter only |
| `facebook-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `fal-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `fastly-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `figma-personal-access-header-token` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `figma-personal-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `finicity-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `finicity-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `finnhub-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `flickr-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `flutterwave-encryption-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `flutterwave-public-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `flutterwave-secret-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `flyio-access-token` | missed | covered | built in #26 | `credentials`: deploy-token | end delimiter only |
| `frameio-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `freemius-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `freshbooks-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `fullstory-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `gcp-api-key` | covered | covered | covered | vendor-key | end delimiter only |
| `gcp-application-default-credentials` | covered | missed | covered | google-oauth-secret and google-refresh-token hide both secrets | same |
| `gcp-gemini-api` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `gcp-service-account` | covered | missed | covered | named-secret-quoted hides private_key | same |
| `generic-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | **regex changed** |
| `generic-credential-uri` | covered | partly | covered | url-password | same |
| `generic-password` | partly | partly | import only | vendor keyword before the value (hidden in some probes, when the sampled name said key or token) | **regex changed** |
| `generic-username` | missed | partly | import only | vendor keyword before the value | same |
| `gitea-access-token` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `github-app-token` | covered | covered | covered | github-token | same |
| `github-fine-grained-pat` | covered | covered | covered | github-token | same |
| `github-oauth` | covered | covered | covered | github-token | same |
| `github-pat` | covered | covered | covered | github-token | same |
| `github-refresh-token` | covered | covered | covered | github-token | same |
| `gitlab-cicd-job-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-deploy-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-feature-flag-client-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-feed-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-incoming-mail-address-token` | covered | partly | covered | identity:email hides the whole reply address | same |
| `gitlab-incoming-mail-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-kubernetes-agent-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-oauth-app-secret` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-pat` | covered | covered | covered | gitlab-token | same |
| `gitlab-pat-routable` | covered | covered | covered | gitlab-token | same |
| `gitlab-pat-routable-versioned` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-ptt` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-rrt` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-runner-authentication-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-runner-authentication-token-routable` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-scim-token` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitlab-session-cookie` | missed | covered | built in #2 | `credentials`: gitlab-token (widen) | same |
| `gitter-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `gocardless-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `grafana-api-key` | missed | covered | built in #10 | `credentials`: grafana-token | end delimiter only |
| `grafana-cloud-api-token` | missed | covered | built in #10 | `credentials`: grafana-token | end delimiter only |
| `grafana-service-account-token` | missed | covered | built in #10 | `credentials`: grafana-token | end delimiter only |
| `greptile-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `groq-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `gumroad-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `harness-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `hashicorp-tf-api-token` | missed | covered | built in #7 | `credentials`: vault-token + terraform-token | same |
| `hashicorp-tf-password` | partly | partly | import only | vendor keyword before the value (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `heroku-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `heroku-api-key-v2` | missed | covered | built in #26 | `credentials`: deploy-token | end delimiter only |
| `highnote-secret-live-key` | covered | covered | covered | named-secret vendor-key | end delimiter only |
| `honeycomb-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `hubspot-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `huggingface-access-token` | missed | covered | built in #8 | `credentials`: huggingface-token | end delimiter only |
| `huggingface-organization-api-token` | missed | covered | built in #8 | `credentials`: huggingface-token | end delimiter only |
| `hunter-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `ibm-cloud-user-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `influxdb-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `infomaniak-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `infracost-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `instantly-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `intercom-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `intra42-client-secret` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `ionic-personal-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `jumpcloud-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `jwt` | covered | covered | covered | jwt hides the eyJ…eyJ… form every real JWT has; Betterleaks also takes any ey… | end delimiter only |
| `jwt-base64` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `kagi-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `kimi-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `klaviyo-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `kraken-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `kubernetes-secret-yaml` | covered | partly | covered | kubernetes:secret-data-yaml hides Secret data values | same |
| `kucoin-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `kucoin-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `langchain-langsmith-personal-access-token` | missed | covered | built in #16 | `credentials`: ai-key (widen) | same |
| `langchain-langsmith-service-key` | missed | covered | built in #16 | `credentials`: ai-key (widen) | same |
| `langfuse-public-key.1` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `langfuse-secret-key.1` | covered | covered | covered | ai-key | end delimiter only |
| `lark-app-id` | missed | covered | not a secret | identifier, host or public key | same |
| `lark-app-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `launchdarkly-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `lichess-personal-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `lighton-paradigm-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `linear-api-key` | missed | covered | built in #24 | `credentials`: linear-key, notion-token, postman-key | same |
| `linear-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `linkedin-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `linkedin-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `llama-cloud-api-key.1` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `lob-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `lob-pub-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `looker-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `looker-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mailchimp-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mailersend-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `mailgun-private-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mailgun-pub-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mailgun-signing-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mapbox-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | **regex changed** |
| `mattermost-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `maxmind-license-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `mem0-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mercury-production-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `mergify-application-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `messagebird-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `messagebird-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `microsoft-teams-webhook` | missed | missed | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `midtrans-production-server-client-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `minimax-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `miro-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `miro-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `miro-client-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mistral-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `monday-api-token.1` | covered | covered | covered | jwt | end delimiter only |
| `mongodb-atlas-service-account-id` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `mongodb-atlas-service-account-secret` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `mongodb-connection-string` | covered | covered | covered | url-password hides the password; user and host stay | same |
| `mux-access-token-id.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `mux-access-token-secret.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `neon-api-key` | missed | covered | built in #25 | `credentials`: planetscale-token, neon-key | end delimiter only |
| `netlify-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `new-relic-browser-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `new-relic-insert-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `new-relic-user-api-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `new-relic-user-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `ngrok-api-key.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `notion-api-token` | missed | covered | built in #24 | `credentials`: linear-key, notion-token, postman-key | end delimiter only |
| `npm-access-token` | missed | covered | built in #1 | `npm`: npm-token | end delimiter only |
| `nuget-api-key` | missed | covered | built in #27 | `credentials`: registry-token | end delimiter only |
| `nuget-config-password` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `nvidia-api-key` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `nylas-api-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `nytimes-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `octopus-deploy-api-key` | missed | covered | import only | API- + 26 capitals: ordinary-looking | end delimiter only |
| `okta-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `ollama-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `onesignal-rich-authentication-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `onfido-live-api-token-ca` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `onfido-live-api-token-eu` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `onfido-live-api-token-us` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `openai-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `openrouter-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `openshift-user-token` | missed | covered | built in #28 | `credentials`: openshift-token | same |
| `openweather-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `opsgenie-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `ovh-application-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `ovh-application-secret` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `ovh-consumer-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `paddle-live-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `pagerduty-authorization-token.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `paypal-client-id.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `paypal-client-secret.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `perplexity-api-key` | missed | covered | built in #16 | `credentials`: ai-key (widen) | same |
| `persona-production-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `pinecone-api-key.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `pinecone-api-key.2` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `pinterest-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `pkcs12-file` | n/a | n/a | n/a | matches file paths, not text | same |
| `plaid-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `plaid-client-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `plaid-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `planetscale-api-token` | missed | covered | built in #25 | `credentials`: planetscale-token, neon-key | end delimiter only |
| `planetscale-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | same |
| `planetscale-oauth-token` | missed | covered | built in #25 | `credentials`: planetscale-token, neon-key | end delimiter only |
| `planetscale-password` | missed | covered | built in #25 | `credentials`: planetscale-token, neon-key | end delimiter only |
| `plivo-auth-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `plivo-auth-token` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `polar-oauth-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `polar-organization-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `polar-personal-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `polymarket-address` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `polymarket-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `polymarket-api-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `polymarket-passphrase` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `polymarket-private-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `posthog-personal-api-key` | missed | covered | built in #29 | `credentials`: posthog-key | end delimiter only |
| `posthog-project-api-key` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `postman-api-token` | missed | covered | built in #24 | `credentials`: linear-key, notion-token, postman-key | end delimiter only |
| `postmark-api-token.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `prefect-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `private-key` | covered | covered | covered | private-key | same |
| `privateai-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `proof-full-access-api-key` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `pulumi-api-token` | missed | covered | built in #26 | `credentials`: deploy-token | end delimiter only |
| `pypi-upload-token` | missed | covered | built in #6 | `credentials`: pypi-token | same |
| `rainforest-pay-production-api-key` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `ramp-client-id` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `ramp-client-secret` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `rapidapi-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `razorpay-key-id.1` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `razorpay-key-secret.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `readme-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `redirect-pizza-api-token.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `render-api-key` | missed | covered | built in #26 | `credentials`: deploy-token | end delimiter only |
| `replicate-api-token` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `resend-api-key.1` | missed | covered | import only | re_ + 8 + _ + 24: short prefix | end delimiter only |
| `retell-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `rootly-api-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `rubygems-api-token` | missed | covered | built in #27 | `credentials`: registry-token | end delimiter only |
| `runpod-api-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `salesforce-access-token.1` | missed | covered | import only | 00 + 13 + ! + 80-260: two-digit prefix | end delimiter only |
| `salesforce-instance-url.1` | missed | covered | not a secret | identifier, host or public key | same |
| `samsara-api-token.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `scaleway-secret-key` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `scalingo-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `scalr-api-access-token.1` | covered | covered | covered | jwt named-secret | end delimiter only |
| `segment-public-api-token.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `sendbird-access-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sendbird-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sendgrid-api-token` | missed | covered | built in #18 | `credentials`: sendgrid-key | end delimiter only |
| `sendinblue-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | same |
| `sentry-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sentry-org-token` | missed | covered | built in #15 | `credentials`: sentry-token | same |
| `sentry-user-token` | missed | covered | built in #15 | `credentials`: sentry-token | end delimiter only |
| `settlemint-application-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `settlemint-personal-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `settlemint-service-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `shippo-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `shopify-access-token` | missed | covered | built in #20 | `credentials`: shopify-token | same |
| `shopify-custom-access-token` | missed | covered | built in #20 | `credentials`: shopify-token | same |
| `shopify-private-app-access-token` | missed | covered | built in #20 | `credentials`: shopify-token | same |
| `shopify-shared-secret` | missed | covered | built in #20 | `credentials`: shopify-token | same |
| `sidekiq-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sidekiq-sensitive-url` | partly | covered | import only | url-password hides the password half of user:password (hidden in some probes, when the sampled name said key or token) | same |
| `slack-app-token` | missed | covered | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `slack-bot-token` | covered | covered | covered | vendor-key | same |
| `slack-config-access-token` | missed | covered | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `slack-config-refresh-token` | missed | covered | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `slack-legacy-bot-token` | covered | covered | covered | vendor-key | same |
| `slack-legacy-token` | partly | covered | partly: widen | vendor-key | same |
| `slack-legacy-workspace-token` | partly | covered | partly: widen | vendor-key | same |
| `slack-session-cookie` | missed | covered | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `slack-session-token` | missed | covered | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `slack-user-token` | partly | covered | partly: widen | vendor-key | same |
| `slack-webhook-url` | missed | covered | built in #3 | `credentials`: chat-webhook + vendor-key (widen) | same |
| `snowflake-account-host.1` | missed | covered | not a secret | identifier, host or public key | same |
| `snowflake-programmatic-access-token.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `snyk-api-token` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `sonar-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sourcegraph-access-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `square-access-token` | missed | covered | import only | EAAA branch is a short prefix shared with Facebook tokens | end delimiter only |
| `squarespace-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sslmate-api-key.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `stability-ai-api-key` | covered | covered | covered | ai-key | end delimiter only |
| `stripe-access-token` | partly | covered | partly: widen | vendor-key | end delimiter only |
| `sumologic-access-id` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `sumologic-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `supabase-management-token` | missed | covered | built in #12 | `credentials`: supabase-key | end delimiter only |
| `supabase-project-api-key` | missed | covered | built in #12 | `credentials`: supabase-key | end delimiter only |
| `supabase-project-url` | missed | covered | not a secret | identifier, host or public key | same |
| `tableau-personal-access-token-name.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `tableau-personal-access-token.1` | missed | covered | import only | base64 == : 32: no prefix | same |
| `tableau-server-host.1` | missed | covered | not a secret | identifier, host or public key | same |
| `tailscale-api-key.1` | missed | covered | built in #9 | `credentials`: tailscale-key | **regex changed** |
| `telegram-bot-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `telnyx-api-v2-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `temporal-cloud-api-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `thunderstore-api-token.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `togetherai-api-key` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `travisci-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `twilio-api-key` | missed | covered | import only | SK + 32 hex, no left boundary | same |
| `twitch-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `twitter-access-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `twitter-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `twitter-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `twitter-api-secret` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `twitter-bearer-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `typeform-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `unkey-root-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `upcloud-api-token` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `upstage-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `upstash-redis-rest-token.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `upstash-redis-rest-url.1` | missed | covered | not a secret | identifier, host or public key | end delimiter only |
| `val-town-api-token.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `vault-batch-token` | missed | covered | built in #7 | `credentials`: vault-token + terraform-token | end delimiter only |
| `vault-service-token` | missed | covered | built in #7 | `credentials`: vault-token + terraform-token | end delimiter only |
| `vercel-ai-gateway-key` | missed | covered | built in #11 | `credentials`: vercel-token | end delimiter only |
| `vercel-api-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `vercel-app-access-token` | missed | covered | built in #11 | `credentials`: vercel-token | end delimiter only |
| `vercel-app-refresh-token` | missed | covered | built in #11 | `credentials`: vercel-token | end delimiter only |
| `vercel-integration-token` | missed | covered | built in #11 | `credentials`: vercel-token | end delimiter only |
| `vercel-personal-access-token` | missed | covered | built in #11 | `credentials`: vercel-token | end delimiter only |
| `virustotal-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `voyageai-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `vultr-api-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `wakatime-api-key.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `wakatime-api-key.2` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `weatherstack-api-key.1` | partly | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret (hidden in some probes, when the sampled name said key or token) | end delimiter only |
| `weights-and-biases-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `weights-and-biases-api-key-v1` | missed | covered | built in #16 | `credentials`: ai-key (widen) | end delimiter only |
| `wiz-client-id.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `wiz-client-secret.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `woocommerce-consumer-secret.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `workato-developer-api-token.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `workos-production-api-key.1` | covered | covered | covered | named-secret vendor-key | end delimiter only |
| `xai-api-key` | partly | covered | partly: widen | ai-key | end delimiter only |
| `xendit-production-api-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
| `yandex-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `yandex-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `yandex-aws-access-token` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zai-api-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zendesk-secret-key` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zoho-client-id.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zoho-client-secret.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zoho-oauth-token.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zoho-zapi-key.1` | missed | covered | import only | vendor keyword before the value; hidden when the name says key/token/secret | end delimiter only |
| `zuplo-consumer-api-key.1` | missed | covered | built in, later | distinctive prefix; service less common in terminal output | end delimiter only |
