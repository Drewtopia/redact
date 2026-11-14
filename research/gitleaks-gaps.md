# Which gitleaks rules cover services redact's packs miss?

Research for [#22](https://github.com/Drewtopia/redact/issues/22), done on 2026-11-14.

## Answer

gitleaks' default config has 222 rules. 121 of them match a token by its own shape, such as a fixed prefix. The other 101 are vendor-keyword rules: a vendor name, then `=` or `:`, then a value.

- **Shape rules: 99 of the 121 are gaps.** redact misses each of them when the token stands on its own: in a table, a log line, a bare token file, or a neutral JSON field. They cover about 60 services. redact covers 18 shape rules fully and 3 partly (AWS, Stripe, Slack). One rule (`pkcs12-file`) matches file paths, so it does not apply to terminal text.
- **Vendor-keyword rules: mostly covered already.** redact's `named-secret*` rules catch the value when the name also says key, token, secret or password (`datadog_api_key: …`). `env-dump` catches any `NAME=value` line. A rule is missed only when the name is the vendor and nothing else, or uses a word redact does not treat as secret (`datadog_app_key:` was missed in the probe). These rules are also the most likely to hide ordinary output (see [False-positive risk](#false-positive-risk)).

**Ten worth adding first**, ranked by how often the token reaches a developer's terminal and how much of it redact still lets through:

1. GitLab token family (`glpat-`, `glrt-`, `glcbt-`, `gldt-` and 10 more)
2. Slack incoming webhook URLs, plus the `xapp-`, `xoxe-` and `xoxo-`/`xoxs-` tokens
3. npm access tokens (`npm_`)
4. PyPI upload tokens (`pypi-AgEIcHlwaS5vcmc…`)
5. HashiCorp Vault tokens (`hvs.`, `hvb.`, but not the legacy `s.` form)
6. Hugging Face tokens (`hf_`, `api_org_`)
7. Stripe test and prod keys (`sk_test_`, `rk_test_`, `sk_prod_`). Widen `vendor-key`
8. SendGrid API keys (`SG.`)
9. Grafana tokens (`glsa_`, `glc_`, `eyJrIjoi`)
10. Microsoft Teams incoming webhook URLs

Two gaps take one line each and could ride along with any of these:

- AWS: add the `A3T`, `ABIA` and `ACCA` prefixes to `aws-key`, and add Bedrock `ABSK` keys.
- curl: add `curl -u user:password` to `secret-flag`. The probe missed it.

**Risky to adopt as they are:** `sourcegraph-access-token` (one branch matches any 40-hex string, which is every git SHA), the `s.` branch of `vault-service-token`, `twilio-api-key` (no left word boundary), `octopus-deploy-api-key`, `facebook-access-token`, `clickhouse-cloud-api-secret-key`, `artifactory-reference-token`, `generic-api-key`, and the vendor-keyword rules whose keyword is an ordinary word (`linear`, `lob`, `sumo`, `okta`, `plaid`, `twitter`, `intercom`, `travis`, `telegr`). gitleaks makes these rules safe with an entropy threshold (130 of its rules set one) and allowlists. `generic-api-key` alone carries 1,446 stopwords. redact supports neither, so a rule ported as written would hide more than it does in gitleaks.

## Sources and method

- gitleaks config: [`config/gitleaks.toml` at `5f6ec56`](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml), the master head on 2026-10-23. The file is generated. Its header says to edit [`cmd/generate/config/rules/*.go`](https://github.com/gitleaks/gitleaks/tree/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules) instead, so the per-rule sources below link to those Go files at the same commit.
- gitleaks licence: [MIT, "Copyright (c) 2019 Zachary Rice"](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/LICENSE).
- redact: `packs/*.toml` on `origin/main` at `6ecbdb4`.
- **Probe.** I built redact from `origin/main` at `6ecbdb4`, ran `redact -c <empty config> scan`, and checked whether the random part of each token survived. I generated a token for each shape (prefix plus random characters of the right class and length) and tested it in two passes:
  - **Neutral context:** a bare log line and `{"id": "…"}`. This was 79 shapes: 77 missed and 2 were masked (Anthropic admin, OpenAI service account). The 2 controls are already covered.
  - **Realistic context:** about 55 lines in the form a CLI or config file prints them, such as `.pypirc`, `.npmrc`, `npm token create` table rows, `vault token create`, `glab auth status`, `git remote -v`, webhook JSON, YAML and JSON names, and `curl -u`. The "redact today" column reports this pass.

  Rules I did not probe are marked *regex* in the table: I compared their regex with redact's regex by eye.

## Gaps by how common they are in developer terminal output

"How common" is a judgement about where the token appears in a developer's terminal: CLI login output, CI job logs, config files developers `cat`, and `git remote -v`. Tier 1 is the everyday developer toolchain: source hosting, package registries, secrets managers, chat webhooks, and widely used developer SaaS. Tier 2 is a service common in some stacks. Tier 3 is niche or consumer.

FP risk means the chance that redact hides ordinary output if the rule is ported without an entropy check. *Low:* a long, distinctive prefix. *Med:* a short prefix, or a shape that ordinary data can share. *High:* see [False-positive risk](#false-positive-risk).

Suggested pack: `credentials` is the existing vendor pack. A **new** name is one suggestion for grouping; one bigger `credentials` pack would also work.

### Tier 1: common

| Service | gitleaks rule id(s) | Token shape | redact today | FP risk | Suggested pack |
| :- | :- | :- | :- | :- | :- |
| GitLab | `gitlab-pat`, `gitlab-pat-routable`, `gitlab-ptt`, `gitlab-deploy-token`, `gitlab-runner-authentication-token`, `gitlab-runner-authentication-token-routable`, `gitlab-cicd-job-token`, `gitlab-feed-token`, `gitlab-oauth-app-secret`, `gitlab-scim-token`, `gitlab-kubernetes-agent-token`, `gitlab-incoming-mail-token`, `gitlab-feature-flag-client-token`, `gitlab-rrt`, `gitlab-session-cookie` ([gitlab.go]) | `glpat-`, `glrt-`, `gldt-`, `glft-`, `glsoat-`, `glffct-` + 20 word chars; `glimt-` + 25; `glagent-` + 50; `gloas-` + 64; `glptt-` + 40 hex; `glcbt-` + 1-5 alnum + `_` + 20; routable forms: prefix + 27-300 chars + `.` + 9 lowercase alnum; `GR1348941` + 20; `_gitlab_session=` + 32 | Missed bare, in a CI job log, and in neutral JSON. Masked behind a secret-named field (`token:`, `PRIVATE-TOKEN:`, `oauth2:…@` in a remote URL) | Low | new `gitlab` |
| Slack | `slack-webhook-url`, `slack-app-token`, `slack-config-access-token`, `slack-config-refresh-token`, `slack-legacy-token` ([slack.go]) | `hooks.slack.com/services/` (or `workflows/`, `triggers/`) + 43-56 chars; `xapp-` + digit + `-` + segments; `xoxe-` + digit + 146; `xoxe.xoxb-`/`xoxe.xoxp-` + digit + 163-166; `xoxo-`/`xoxs-` + digit groups + hex | Webhook URL missed in JSON and on a `curl` line; `xapp-`, `xoxe-` and `xoxo-` missed. `xoxe.xoxb-` is partly masked, because `vendor-key` matches from `xoxb-` on | Low | `credentials` (`vendor-key`) |
| npm | `npm-access-token` ([npm.go]) | `npm_` + 36 alnum | Missed in a `npm token create` table row. Masked in `.npmrc` (npm pack) and in a `"token":` field | Low | `npm` |
| PyPI | `pypi-upload-token` ([pypi.go]) | `pypi-AgEIcHlwaS5vcmc` (base64 of the macaroon header) + 50-1000 word chars | Missed bare (printed once at creation; a token file). Masked in `.pypirc` `password =` and `TWINE_PASSWORD=` | Low | new `python` or `credentials` |
| HashiCorp Vault | `vault-service-token`, `vault-batch-token` ([hashicorp_vault.go]) | `hvs.` + 90-120 word chars; `hvb.` + 138-300; legacy `s.` + 24 alnum | Missed in `~/.vault-token` and in the `vault token create` table, which separates name and value with spaces only | Low for `hvs.`/`hvb.`; **High** for `s.` | new `hashicorp` |
| HashiCorp Terraform Cloud | `hashicorp-tf-api-token` ([hashicorp.go]) | 14 alnum + `.atlasv1.` + 60-70 chars | Masked in `credentials.tfrc.json` and after `Token:`. Missed bare (*regex*) | Low | new `hashicorp` |
| Hugging Face | `huggingface-access-token`, `huggingface-organization-api-token` ([huggingface.go]) | `hf_` + 34 letters; `api_org_` + 34 letters | Missed in the bare `~/.cache/huggingface/token` file. Masked as `HF_TOKEN=` | Low-med (`hf_` is short, but 34 letters only is distinctive) | `credentials` |
| Stripe | `stripe-access-token` ([stripe.go]) | `sk_`/`rk_` + `test`/`live`/`prod` + `_` + 10-99 alnum | `_live_` is covered by `vendor-key`. `sk_test_`/`rk_test_`/`_prod_` missed on the line the Stripe CLI prints, and masked behind secret-named fields | Low | `credentials` (`vendor-key`) |
| AWS | `aws-access-token`, `aws-amazon-bedrock-api-key-long-lived`, `aws-amazon-bedrock-api-key-short-lived` ([aws.go]) | `A3T?`/`ABIA`/`ACCA` + 16 upper/base32 (redact has `AKIA`/`ASIA`); `ABSK` + 109-269 base64; `bedrock-api-key-` + fixed base64 host | Missed: `ABIA`/`A3T` bare, and even `aws_access_key_id = A3T…`; `ABSK` bare | Low | `credentials` (`aws-key`) |
| SendGrid | `sendgrid-api-token` ([sendgrid.go]) | `SG.` + 66 chars (two dot-separated parts) | Missed on a log line. Masked as `SENDGRID_API_KEY=` and `"apiKey":` | Low | `credentials` |
| Grafana | `grafana-service-account-token`, `grafana-cloud-api-token`, `grafana-api-key` ([grafana.go]) | `glsa_` + 32 alnum + `_` + 8 hex; `glc_` + 32-400 base64; `eyJrIjoi` + 70-400 alnum | Missed bare, and even in a `"key":` JSON field | Low | `credentials` |
| Microsoft Teams | `microsoft-teams-webhook` ([teams.go]) | `https://<tenant>.webhook.office.com/webhookb2/<guid>@<guid>/IncomingWebhook/<32>/<guid>` | Missed in a JSON `"url":` | Low | `azure` |
| curl | `curl-auth-user` ([curl.go]) | `curl` … `-u`/`--user` `user:password` | Missed for `-u` and `--user` | Low-med (`-u $USER:$TOKEN` would mask variable names) | `credentials` (`secret-flag`) |
| DigitalOcean | `digitalocean-pat`, `digitalocean-access-token`, `digitalocean-refresh-token` ([digitalocean.go]) | `dop_v1_`/`doo_v1_`/`dor_v1_` + 64 hex | Missed in an auth listing (bare). Masked in the doctl config `access-token:` | Low | `credentials` |
| Databricks | `databricks-api-token` ([databricks.go]) | `dapi` + 32 hex (+ optional `-digit`) | Missed in the `databricks tokens list` row. Masked as `token =` | Low-med (`dapi` + hex is short) | `credentials` |
| Heroku | `heroku-api-key-v2` ([heroku.go]) | `HRKU-AA` + 58 word chars | Missed for `heroku auth:token` (bare) and the `.netrc` `password` line | Low | `credentials` |
| JFrog Artifactory | `artifactory-api-key`, `artifactory-reference-token` ([artifactory.go]) | `AKCp` + 69 alnum; `cmVmd` + 59 alnum | Missed bare (*regex*). Masked as `"accessToken":` | Low for `AKCp`; **Med** for `cmVmd` (a base64 prefix that other base64 can start with) | `credentials` |
| NuGet | `nuget-config-password` ([nuget.go]) | `<add key="Password"` or `"ClearTextPassword"` `value="…"` in `nuget.config` | Missed | Low | new `dotnet` or `credentials` |
| 1Password | `1password-service-account-token`, `1password-secret-key` ([1password.go]) | `ops_eyJ` + 250+ base64; `A3-` + 6 + 11 (or 6-5) + three groups of 5, all upper alnum | Missed bare | Low | `credentials` |
| Doppler | `doppler-api-token` ([doppler.go]) | `dp.pt.` + 43 alnum | Missed bare | Low | `credentials` |
| age | `age-secret-key` ([age.go]) | `AGE-SECRET-KEY-1` + 58 bech32 chars | Missed in `age-keygen` output and key files | Low | `credentials` |
| Sentry | `sentry-user-token`, `sentry-org-token` ([sentry.go]) | `sntryu_` + 64 hex; `sntrys_eyJpYXQiO` + base64 holding a region URL | Missed bare | Low | `credentials` |

### Tier 2: common in some stacks

All of these were missed bare in the probe, except those marked *regex*, which were inferred from the regex. FP risk is Low unless the row says otherwise. Suggested pack: `credentials`.

| Service | gitleaks rule id(s) | Token shape | FP risk |
| :- | :- | :- | :- |
| Fly.io | `flyio-access-token` ([flyio.go]) | `fo1_` + 43; `fm1a_`/`fm1r_`/`fm2_` + 100+ base64 | Low |
| Pulumi | `pulumi-api-token` ([pulumi.go]) | `pul-` + 40 hex (masked behind `accessToken`/`Token:`) | Low |
| Shopify | `shopify-access-token`, `shopify-custom-access-token`, `shopify-private-app-access-token`, `shopify-shared-secret` ([shopify.go]) | `shpat_`/`shpca_`/`shppa_`/`shpss_` + 32 hex (masked behind header and `accessToken`) | Low |
| Postman | `postman-api-token` ([postman.go]) | `PMAK-` + 24 hex + `-` + 34 hex | Low |
| Linear | `linear-api-key` ([linear.go]) | `lin_api_` + 40 alnum | Low |
| Notion | `notion-api-token` ([notion.go]) | `ntn_` + 11 digits + 35 alnum | Low |
| Dynatrace | `dynatrace-api-token` ([dynatrace.go]) | `dt0c01.` + 24 + `.` + 64 | Low |
| PlanetScale | `planetscale-api-token`, `planetscale-oauth-token`, `planetscale-password` ([planetscale.go]) | `pscale_tkn_`/`pscale_oauth_`/`pscale_pw_` + 32-64 | Low |
| RubyGems | `rubygems-api-token` ([rubygems.go]) | `rubygems_` + 48 hex | Low |
| Clojars | `clojars-api-token` ([clojars.go]) | `CLOJARS_` + 60 alnum | Low |
| OpenShift | `openshift-user-token` ([openshift.go]) | `sha256~` + 43 word chars (`oc whoami -t`) | Low |
| Octopus Deploy | `octopus-deploy-api-key` ([octopusdeploy.go]) | `API-` + 26 upper alnum | **Med**: `API-` is an ordinary word prefix |
| Prefect | `prefect-api-token` ([prefect.go]) | `pnu_` + 36 alnum | Low |
| Harness | `harness-api-key` ([harness.go]) | `pat.`/`sat.` + 22 + `.` + 24 + `.` + 20 | Low |
| Infracost | `infracost-api-token` ([infracost.go]) | `ico-` + 32 alnum | Low |
| Cloudflare | `cloudflare-origin-ca-key` ([cloudflare.go]) | `v1.0-` + 24 hex + `-` + 146 hex | Low |
| Alibaba Cloud | `alibaba-access-key-id` ([alibaba.go]) | `LTAI` + 20 alnum | Low-med |
| Perplexity | `perplexity-api-key` ([perplexity.go]) | `pplx-` + 48 alnum | Low |
| ClickHouse Cloud | `clickhouse-cloud-api-secret-key` ([clickhouse.go]) | `4b1d` + 38 alnum | **Med**: a 42-char alnum word starting `4b1d` |
| Airtable | `airtable-personnal-access-token` ([airtable.go]) | `pat` + 14 alnum + `.` + 64 hex | Low |
| Adobe | `adobe-client-secret` ([adobe.go]) | `p8e-` + 32 alnum | Low |
| MaxMind | `maxmind-license-key` ([maxmind.go]) | 6 + `_` + 29 + `_mmk` | Low |
| Square | `square-access-token` ([square.go]) | `EAAA`/`sq0atp-` + 22-60 | Low-med (`EAAA` + 22 is short) |
| Brevo (Sendinblue) | `sendinblue-api-token` ([sendinblue.go]) | `xkeysib-` + 64 hex + `-` + 16 | Low |
| Facebook | `facebook-page-access-token`, `facebook-access-token` ([facebook.go]) | `EAAM`/`EAAC` + 100+ alnum; 15-16 digits + `\|` or `%` + 27-40 | Low for `EAA[MC]`; **High** for the digits form |
| Sourcegraph | `sourcegraph-access-token` ([sourcegraph.go]) | `sgp_` + 16 hex or `local` + `_` + 40 hex; `sgp_` + 40 hex; **or any 40 hex** | Port only the `sgp_` branches; the bare 40-hex branch is **High** |
| JWT in base64 | `jwt-base64` ([jwt.go]) | `ZXlK` (base64 of `eyJ`) + base64 of a known header claim | Low |

### Tier 3: niche

All were missed in the probe or inferred from the regex, and all are Low risk unless the row says otherwise. Each is cheap to add if a user asks for it.

| Service | gitleaks rule id(s) | Token shape |
| :- | :- | :- |
| Twilio | `twilio-api-key` ([twilio.go]) | `SK` + 32 hex. This is the API key SID; the auth token has no shape rule. **Med-high**: no left word boundary, and the keyword `sk` is in almost any text |
| Readme | `readme-api-token` ([readme.go]) | `rdme_` + 70 |
| Scalingo | `scalingo-api-token` ([scalingo.go]) | `tk-us-` + 48 |
| Duffel | `duffel-api-token` ([duffel.go]) | `duffel_test_`/`duffel_live_` + 43 |
| EasyPost | `easypost-api-token`, `easypost-test-api-token` ([easypost.go]) | `EZAK`/`EZTK` + 54 |
| Shippo | `shippo-api-token` ([shippo.go]) | `shippo_live_`/`shippo_test_` + 40 hex |
| Frame.io | `frameio-api-token` ([frameio.go]) | `fio-u-` + 64 |
| Flutterwave | `flutterwave-secret-key`, `flutterwave-public-key`, `flutterwave-encryption-key` ([flutterwave.go]) | `FLWSECK_TEST-`/`FLWPUBK_TEST-` + hex (*regex*) |
| SettleMint | `settlemint-*-access-token` x3 ([settlemint.go]) | `sm_aat_`/`sm_pat_`/`sm_sat_` + 16 (*regex*) |
| Authress | `authress-service-client-access-key` ([authress.go]) | `sc_`/`ext_`/`scauth_`/`authress_` + dotted `acc` segments (*regex*) |
| 42 Intra | `intra42-client-secret` ([intra42.go]) | `s-s4t2ud-`/`s-s4t2af-` + 64 hex (*regex*) |
| Freemius | `freemius-secret-key` ([freemius.go]) | `'secret_key' => 'sk_…'` in PHP (*regex*; likely masked already by `named-secret-single-quoted`) |
| Sidekiq | `sidekiq-sensitive-url` ([sidekiq.go]) | `https://<8hex>:<8hex>@gems.contribsys.com` (*regex*; likely masked already by `url-password`) |

### Vendor-keyword rules (101): covered when the name says secret

These rules match `<name containing vendor>` + assignment + a value of fixed length and class. Examples are `datadog-access-token`, `heroku-api-key`, `cloudflare-api-key`, `twitter-*` x5, `new-relic-*` x4, `mailgun-*` x3, `okta-access-token` and `telegram-bot-api-token`. Probe results:

- **Masked:** `DATADOG_API_KEY=` and every env line (`env-dump`), `datadog_api_key:` (YAML), `"heroku_api_key":` (JSON), `twilio_auth_token:`.
- **Missed:** `datadog_app_key:` (YAML), `heroku:` and `datadog:` with no secret word, and `"telegram_bot":`.

Recommendation: do not port these. Their keywords are vendor names, so they would fire on any line that mentions the vendor, and redact has no entropy check to filter the matches. If a name such as `app_key` comes up in practice, add it to the secret words of the `named-secret*` rules instead.

### Covered already (for the record)

| redact rule | gitleaks rules it covers |
| :- | :- |
| `github-token` | `github-pat`, `github-oauth`, `github-app-token`, `github-refresh-token`, `github-fine-grained-pat` |
| `ai-key` | `anthropic-api-key`, `anthropic-admin-api-key`, `openai-api-key` |
| `vendor-key` | `gcp-api-key`, `slack-bot-token`, `slack-user-token`, `slack-legacy-bot-token`, `slack-legacy-workspace-token`; `stripe-access-token` (live only) |
| `aws-key` | `aws-access-token` (`AKIA`/`ASIA` only) |
| `entra-client-secret` | `azure-ad-client-secret` |
| `private-key` | `private-key` |
| `jwt` | `jwt` |
| `secret-data-yaml` (kubernetes) | `kubernetes-secret-yaml` |
| `bearer`, `key-header` | `curl-auth-header` |
| `named-secret*` | `generic-api-key`, `hashicorp-tf-password` (no entropy filter) |

Neither tool covers these. The ticket names Docker Hub, but gitleaks has no Docker Hub rule: no `dckr_pat_` anywhere in the config. A bare Docker Hub PAT also slips past redact; redact's `docker` pack covers only `config.json` `auth` and Env lists. Outside this question, the probe also missed the password on a `.netrc` `machine … login … password …` line and the key in a Sentry DSN URL. gitleaks has no rule for either.

## False-positive risk

These things make a ported rule riskier in redact than it is in gitleaks:

1. **No entropy check.** 130 of gitleaks' 222 rules set `entropy` (2 to 4.5), which drops low-randomness matches. redact has nothing equivalent in `src/` or `docs/reference/`.
2. **No per-rule allowlists or stopwords.** For example, `generic-api-key` has 4 allowlists, one of them 1,446 stopwords. redact's `named-secret*` rules already cover that ground, and they mask by the name rather than by how random the value looks.
3. **Rules to leave out or narrow:**
   - `sourcegraph-access-token`: the bare `[a-fA-F0-9]{40}` branch hides every git SHA on a line that mentions sourcegraph.
   - `vault-service-token`: the `s.` + 24 alnum branch, case-insensitive, matches ordinary dotted identifiers.
   - `twilio-api-key`: `SK` + 32 hex with no `\b`, and the keyword is `sk`.
   - `facebook-access-token`: digits + `|` or `%` + 27-40 chars, which matches URL-encoded query strings.
   - `octopus-deploy-api-key`, `clickhouse-cloud-api-secret-key`, `artifactory-reference-token`: short or common prefixes.
   - The vendor-keyword rules with ordinary-word keywords: `linear`, `lob` (keywords `test_`/`live_`), `sumo`, `okta`, `plaid`, `twitter`, `intercom`, `travis`, `telegr`, `confluent`, `looker`, `kraken`.
   - `generic-api-key` and `hashicorp-tf-password`: redact already covers them, so porting adds only the risk.
4. **Short tokens:** `hf_` + 34, `dapi` + 32 hex, `EAAA` + 22 and `LTAI` + 20 are safe enough with their prefix and a `\b`. Keep the `\b` and the trailing-delimiter group from gitleaks when porting.

## Licence and attribution

gitleaks is [MIT-licensed](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/LICENSE), "Copyright (c) 2019 Zachary Rice". MIT asks that the copyright and permission notice be included with "all copies or substantial portions of the Software". The safe reading is that a set of copied regexes counts, so do what redact already does for transcript-redactor:

1. Add the gitleaks MIT notice to `LICENSE-THIRD-PARTY`, which ships in release archives.
2. Widen the gitleaks row in `docs/reference/thanks.md`. It now credits only "the `regex`, `keywords` and `secretGroup` field names". Make it say the vendor token patterns too.
3. Add a sentence under "Third-party notices" in `docs/reference/thanks.md` naming the packs that adapt gitleaks patterns, linked to `config/gitleaks.toml` or `cmd/generate/config/rules/` at the pinned commit `5f6ec56`.
4. Optional: put a one-line `# adapted from gitleaks <rule-id>` comment above each ported rule, so a later sync can diff it against upstream.

Regex syntax: gitleaks uses Go RE2. Rust's `regex` crate accepts the same constructs these rules use (`(?i)` mid-pattern, `(?-i:…)`, `[[:alnum:]]`, `(?P<name>…)`). I did not compile them in redact.

[1password.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/1password.go
[adobe.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/adobe.go
[age.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/age.go
[airtable.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/airtable.go
[alibaba.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/alibaba.go
[artifactory.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/artifactory.go
[authress.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/authress.go
[aws.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/aws.go
[clickhouse.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/clickhouse.go
[clojars.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/clojars.go
[cloudflare.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/cloudflare.go
[curl.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/curl.go
[databricks.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/databricks.go
[digitalocean.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/digitalocean.go
[doppler.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/doppler.go
[duffel.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/duffel.go
[dynatrace.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/dynatrace.go
[easypost.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/easypost.go
[facebook.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/facebook.go
[flutterwave.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/flutterwave.go
[flyio.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/flyio.go
[frameio.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/frameio.go
[freemius.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/freemius.go
[gitlab.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/gitlab.go
[grafana.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/grafana.go
[harness.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/harness.go
[hashicorp.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/hashicorp.go
[hashicorp_vault.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/hashicorp_vault.go
[heroku.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/heroku.go
[huggingface.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/huggingface.go
[infracost.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/infracost.go
[intra42.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/intra42.go
[jwt.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/jwt.go
[linear.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/linear.go
[maxmind.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/maxmind.go
[notion.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/notion.go
[npm.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/npm.go
[nuget.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/nuget.go
[octopusdeploy.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/octopusdeploy.go
[openshift.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/openshift.go
[perplexity.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/perplexity.go
[planetscale.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/planetscale.go
[postman.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/postman.go
[prefect.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/prefect.go
[pulumi.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/pulumi.go
[pypi.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/pypi.go
[readme.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/readme.go
[rubygems.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/rubygems.go
[scalingo.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/scalingo.go
[sendgrid.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/sendgrid.go
[sendinblue.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/sendinblue.go
[sentry.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/sentry.go
[settlemint.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/settlemint.go
[shippo.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/shippo.go
[shopify.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/shopify.go
[sidekiq.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/sidekiq.go
[slack.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/slack.go
[sourcegraph.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/sourcegraph.go
[square.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/square.go
[stripe.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/stripe.go
[teams.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/teams.go
[twilio.go]: https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/generate/config/rules/twilio.go
