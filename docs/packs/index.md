# How packs work

A pack is a TOML file of rules. Each rule's `regex` finds a spot in the text, and `secretGroup` says which capture group to hide. The rest of the match stays as it was. So `"tenantId": "…"` keeps its key, and only the GUID becomes `[ID-…]`.

## Built-in packs

| Pack | Hides |
| :- | :- |
| [azure](./azure) | IDs, people, hosts, and names in Azure, Azure DevOps, Microsoft Graph, and `az` output |
| [identity](./identity) | Emails anywhere, git authors and `user.name`, and GitHub user records |
| [kubernetes](./kubernetes) | Secret `data:` values in YAML and JSON, and kubeconfig client keys |
| [docker](./docker) | Registry logins in `config.json`, and secret-named `docker inspect` env entries |
| [npm](./npm) | `_authToken`, `_password`, and `_auth` in `.npmrc`, for any registry |
| [http](./http) | `Cookie` and `Set-Cookie` values, and API key headers such as `x-api-key` |
| [gcp](./gcp) | `ya29.` access tokens, and project IDs in key files, resource paths, and `--project` |
| [credentials](./credentials) | Tokens, vendor keys, private keys, URL passwords, values named as secrets, and environment dump values |
| [pii](./pii) | **Off by default.** Phone numbers, card numbers and IBANs that pass their checksums, IP and MAC addresses, and US and UK national ID numbers |

The packs load in the order of this table.

`pii` hides any IP address, which is more than most people want, so it starts switched off. To turn it on, add `[packs] enable = ["pii"]` to your [config](../reference/config#packs).

When two rules hide exactly the same text, the first rule's label wins. A specific Azure label such as `ORG` therefore beats a generic `SECRET`.

## Labels

A label says what kind of thing a placeholder hides, so a model can tell a person from a token. It never says whose, or which product: the hash already keeps two values apart, and `redact scan --explain` names the rule that hid each one.

| Label | Hides |
| :- | :- |
| `SECRET` | Tokens, keys, passwords, cookies and other credentials |
| `ENV-VALUE` | A value from an environment dump, a dotenv file, an `env` variable or a pipeline variable |
| `ID` | Tenant, subscription, app, object and identity IDs |
| `PERSON`, `EMAIL`, `USER`, `PROFILE` | A person's name, email address, login, and profile details such as company or location |
| `ORG`, `PROJECT`, `REPO`, `RESOURCE` | Organisation, project, repository and cloud resource names |
| `PHONE`, `CARD`, `IBAN`, `IP`, `MAC`, `NATIONAL-ID` | Personal data from the `pii` pack |
| `WORDLIST` | A line from one of your word lists |
| `ME-NAME`, `ME-EMAIL`, `ME-GITHUB` | You, with [`me = true`](../guide/me) |

To change what they say, for example `[HIDDEN-…]` everywhere or a label of your own for one rule, see [`[labels]`](../reference/config#labels).

## Your own packs

Every `.toml` and `.txt` file in `~/.config/redact/packs/` loads, and so does anything your config `import`s. See [Writing a pack](./writing).

## Word lists

A `.txt` file is a word list, with one word or phrase per line. `#` starts a note. redact hides each line as a whole word, in any case. Each line hides as `[WORDLIST-…]`, not as the file name, which could say what the list hides.

```text
# customers.txt
Northwind Traders
Contoso Pharma
```

## Remembered values

A rule can mark what it hides as remembered. redact then hides the same value everywhere else in the text too. For example, a person found in a git `Author:` line is also hidden where a later line names them. A GitHub login found in a user record is hidden in every URL that holds it.
