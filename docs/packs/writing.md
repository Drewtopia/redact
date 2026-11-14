# Writing a pack

Save a pack as a `.toml` file in `~/.config/redact/packs/`, or `import` it from your config. This example hides customer IDs and account owners in a billing API's JSON:

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
| `keywords` | The pack runs only when one of these appears, in any case. A cheap test before any regex runs |
| `allow` | Values never to hide, such as public IDs |
| `default` | `false` makes the pack start switched off, for a user to turn on with `[packs] enable`. Defaults to `true` |

### Rule

| Field | What it does |
| :- | :- |
| `id` | The rule's name, shown by `--explain` |
| `description` | One line on what it finds |
| `regex` | Where to look, in Rust [`regex`](https://docs.rs/regex) syntax |
| `secretGroup` | The capture group to hide. `0`, the default, is the whole match |
| `label` | What the placeholder says. Defaults to the rule id |
| `within` | Run only inside a JSON object whose own fields match this regex, whatever their order and wherever nested objects sit |
| `except` | Leave a found value alone when the value matches this regex. See [Exceptions](#exceptions) |
| `exceptMatch` | Leave a find alone when the whole match matches this regex. See [Exceptions](#exceptions) |
| `remember` | Also hide the value everywhere else in the text: `"distinctive"` or `"any"`. See [Remember](#remember) |
| `keywords` | The rule runs only when one of these appears |
| `check` | Hide a found value only when it passes a checksum: `"luhn"` for card numbers, or `"iban"` for the IBAN mod-97 check. Long runs of digits that are not cards stay visible |

### Exceptions

`except` tests the value. Use it for a reference such as `$TOKEN` or `<placeholder>`, which is not a secret. Rust's `regex` has no lookahead, so `except` is how a rule says "but not these".

`exceptMatch` tests the whole match, not just the value. Use it when the name decides. For example, the paging cursor in `nextPageToken: …` is not a secret, though `token` is in its name. Anchor the regex with `^`, so the value cannot trigger it.

With `within`, redact also tests `exceptMatch` against each JSON object's own fields, and skips an object it matches whole, such as `{"name": "nextPageToken", "value": …}`.

### Remember

- `"distinctive"` hides the value everywhere else when it reads as a name: it holds a space, `-`, `_`, `.`, a digit, or an inner capital.
- `"any"` hides any value that has a capital letter or 5 or more characters.

## Regex syntax

redact uses Rust's `regex` crate, which runs in linear time, so no pattern can make a scan hang. The crate has no lookahead or lookbehind. Instead, capture the part to hide, and match what sits around it outside the group:

```toml
# not: (?<=tenantId": ")[0-9a-f-]{36}
regex = '''"tenantId"\s*:\s*"([0-9a-f-]{36})"'''
secretGroup = 1
```

Use `'''…'''` literal strings, so backslashes need no escaping.

## Check it

If a pack has bad TOML, a bad regex, a `secretGroup` the regex lacks, or an unknown field, redact stops with an error that names the file. Once the pack loads, list it and try a sample:

```sh
redact packs
printf '{"customerId": "C-123456"}' | redact scan --explain
```

## Test with fake values

Build test values that look real but are not. `Fabrikam`, `Contoso`, and `Northwind` are Microsoft's own made-up company names, and `example.com` is reserved for examples.
