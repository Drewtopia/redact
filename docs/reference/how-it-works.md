# How it works

## One pass

1. Load the packs, word lists, and values, as [load order](./config#load-order) describes. Apply the overrides that match, and drop the packs that are switched off.
2. For each pack whose keywords appear in the text, run each rule whose keywords appear.
   - A rule with `within` runs only inside the JSON objects whose own fields match it.
   - A found value is left alone when it matches the rule's `except`, fails its `check`, or is on an `allow` list. The `check` is Luhn for cards and mod-97 for IBANs.
   - After each find, the rule looks again from the end of the hidden part, so it finds both of two values one space apart.
3. Collect what each rule found. Values a rule marks as remembered join the word list.
4. Find every word, remembered value, and listed value in one pass with [Aho-Corasick](https://docs.rs/aho-corasick). Matches are whole words in any case, and allowed values are skipped.
5. Where finds overlap, join them into one span that covers every byte any of them found. The earliest find gives the span its label. If two start together, the longer one does.
6. Swap each find for its placeholder.

Every regex runs in linear time, and the word pass costs the same however many words there are. Measured on one laptop, 9 MB of nested JSON takes about 1.3 seconds. 15 MB of text with two email addresses on every line takes about 0.9 seconds and 150 MB of memory.

## Placeholders

A placeholder is `[LABEL-` + the first 8 hex characters of HMAC-SHA256(key, value) + `]`.

- **The same value gets the same tag** within a run, so the text still reads: you can tell one person from another.
- **Two values never share a tag.** If two would, the second is hashed again with a counter until its tag is free.
- **A tag cannot be worked back to its value** without the key. A plain hash would not be safe, because anyone could hash a list of guesses and compare.
- **Without `REDACT_KEY`,** the key is 32 random bytes made fresh for each run, so tags from two runs cannot be matched.
- **With `REDACT_KEY`** of 16 or more characters, the same value gets the same tag in every run that uses the key, so several commands in one session agree.

```sh
export REDACT_KEY=$(openssl rand -hex 32)
```

## Fails closed

When a pack, word list, or config file will not load, redact stops with an error that names the file, and exits with code 3. It does not skip the file. A redactor that quietly skips a rule hides less than you think.

| Exit code | Meaning |
| :- | :- |
| 0 | Done |
| 2 | Bad usage, or a `REDACT_KEY` that is too short |
| 3 | A file would not load, or the scan failed |

## JSON spans

`redact scan --json` prints what it would hide as byte spans, with labels and rule names but never the values. A tool built on redact uses these spans to make its own placeholders.
