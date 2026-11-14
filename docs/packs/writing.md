# Writing a pack

```toml
# ~/.config/redact/packs/acme.toml
schema_version = 1
id = "acme"
description = "Customer IDs and account owners in the Acme billing API"
keywords = ["customerid", "accountid"]   # the pack only runs when one of these appears

[[rules]]
id = "customer-id"
description = "A customer ID: C- and six digits"
regex = '''"customerId"\s*:\s*"(C-[0-9]{6})"'''
secretGroup = 1
label = "CUSTOMER-ID"

[[rules]]
id = "account-owner"
description = "The owner of an account record"
regex = '''"owner"\s*:\s*"([^"]+)"'''
secretGroup = 1
label = "PERSON"
within = '''"accountId"\s*:'''
remember = "distinctive"
```

## Fields

### Pack

| Field | What it does |
| :- | :- |
| `schema_version` | Always `1` |
| `id` | The pack's name, shown by `redact packs` and `--explain` |
| `description` | One line on what the pack hides |
| `keywords` | The pack runs only when one of these appears (any case). A cheap test before any regex runs |
| `allow` | Values never to hide, such as public IDs |
| `default` | `false` makes the pack start switched off, for a user to turn on with `[packs] enable`. Defaults to `true` |

### Rule

| Field | What it does |
| :- | :- |
| `id` | The rule's name, shown by `--explain` |
| `description` | One line on what it finds |
| `regex` | Where to look. Rust [`regex`](https://docs.rs/regex) syntax |
| `secretGroup` | The capture group to hide; `0`, the default, is the whole match |
| `label` | What the placeholder says; defaults to the rule id |
| `within` | Run only inside a JSON object whose own fields match this regex, whatever their order and wherever nested objects sit |
| `except` | Leave a found value alone when it matches this regex: a reference such as `$TOKEN` or `<placeholder>`, not a secret. Rust's `regex` has no lookahead, so this is how a rule says "but not these" |
| `exceptMatch` | Leave a find alone when the whole match, not just the value, matches this regex. Use it when the name decides: the paging cursor in `nextPageToken: …` is not a secret, though `token` is in its name. Anchor it with `^` so the value cannot trigger it. With `within`, it is also tested against each JSON object's own fields, and an object it matches is skipped whole: `{"name": "nextPageToken", "value": …}` |
| `remember` | `"distinctive"`: also hide the value everywhere else when it reads as a name (a space, `-`, `_`, `.`, a digit or an inner capital). `"any"`: any value with a capital letter or of 5+ characters |
| `keywords` | The rule runs only when one of these appears |
| `context` | Clue words, as in Microsoft Presidio: hide a found value only when one of these is on its line or the line before. Any case, whole words; `_`, `-` and a camelCase hump count as word edges, so `phone` is found in `mobile_phone` and `homePhone` but not `phones`. For shapes that mean nothing alone, such as `123-45-6789`: `context = ["ssn", "social security"]` |
| `check` | Hide a found value only when it passes a checksum: `"luhn"` for card numbers, `"iban"` for the IBAN mod-97 check, `"not-a-name"` for a token that is not a camelCase name (words of 3+ letters cover under 70% of it). Keeps long runs of digits that are not cards visible |
| `entropy` | Hide a found value only when its Shannon entropy is above this many bits per character, as in gitleaks: `entropy = 3.5`. Equal is not enough. Random keys score near 4 or more; words and repeated text score lower |

## Clue words

`context` looks at the value's own line and the line before it, up to 100 bytes either side of where the value starts. That covers the shapes personal data comes in: `Phone: …`, `"homePhone": "…"`, `… (mobile)`, a YAML list under `phone:`, and a label on the line above. It misses a value further below its label, such as the rows under a table or CSV header. It can also over-hide: in `phone: …` followed by `order: 555-010-0200`, the order number reads as a phone number.

## Regex syntax

redact uses Rust's `regex` crate, which runs in linear time: no pattern can make a scan hang. It has no lookahead or lookbehind. Capture the part to hide instead, and match what sits around it outside the group:

```toml
# not: (?<=tenantId": ")[0-9a-f-]{36}
regex = '''"tenantId"\s*:\s*"([0-9a-f-]{36})"'''
secretGroup = 1
```

Use `'''…'''` literal strings, so backslashes need no escaping.

## Check it

A pack that will not load (bad TOML, a bad regex, a `secretGroup` the regex lacks, an unknown field) stops redact with an error naming the file. Then:

```sh
redact packs
printf '{"customerId": "C-123456"}' | redact scan --explain
```

## Test with fake values

Build test values that look real but are not: `Fabrikam`, `Contoso` and `Northwind` are Microsoft's own made-up company names, and `example.com` is reserved for examples.
