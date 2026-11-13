# How packs work

A pack is a TOML file of rules. Each rule's `regex` finds a spot in the text, and `secretGroup` says which capture group to hide. The rest of the match is left as it was, so `"tenantId": "…"` keeps its key and only the GUID becomes `[TENANT-ID-…]`.

## Built-in packs

| Pack | Hides |
| :- | :- |
| [azure](./azure) | Tenant, subscription and identity IDs; people in Azure DevOps and Microsoft Graph records; your own Azure hosts; Azure DevOps org, project and repo names; `az account` details; pipeline variable values |
| [identity](./identity) | Emails anywhere; git authors and `user.name`; GitHub user records |
| [kubernetes](./kubernetes) | Secret `data:` values (YAML and JSON); kubeconfig client keys |
| [docker](./docker) | Registry logins in `config.json`; secret-named `docker inspect` env entries |
| [npm](./npm) | `.npmrc` `_authToken`, `_password` and `_auth`, Azure Artifacts feeds included |
| [http](./http) | `Cookie` and `Set-Cookie` values; API key headers (`Ocp-Apim-Subscription-Key`, `x-functions-key`, `x-api-key`) |
| [gcp](./gcp) | `ya29.` access tokens; project IDs in key files, resource paths and `--project` |
| [credentials](./credentials) | JWTs and bearer tokens; vendor key shapes; private keys; URL passwords; values named as secrets; environment dump values |
| [pii](./pii) | **Off by default.** Phone numbers; card numbers and IBANs that pass their checksums; IP and MAC addresses; US Social Security and UK National Insurance numbers |

They load in that order. `pii` hides any IP address and any phone-shaped number, which is more than most people want, so it starts switched off: turn it on with `[packs] enable = ["pii"]` in your [config](../reference/config#packs). When two rules hide exactly the same text, the first one's label wins, so a specific Azure label beats a generic one.

## Your own packs

Every `.toml` and `.txt` file in `~/.config/redact/packs/` loads, and so does anything your config `import`s. See [Writing a pack](./writing).

## Word lists

A `.txt` file is a word list: one word or phrase per line, `#` starts a note. Each line is hidden as a whole word, in any case. The file name is the label, so `customers.txt` hides each line as `[CUSTOMERS-…]`.

```text
# customers.txt
Northwind Traders
Contoso Pharma
```

## Remembered values

A rule can mark what it hides as remembered: the same value is then hidden everywhere else in the text too. A person found in a work item's `AssignedTo` is also hidden when an `@mention` names them in a comment, and a project found in a URL is hidden in a path like `C:\<project>\`.
