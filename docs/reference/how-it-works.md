# How it works

## One pass

1. Load the packs, word lists and values (see [load order](./config#load-order)).
2. For each pack whose keywords appear in the text, run each rule whose keywords appear. A rule with `within` runs only inside the JSON objects whose own fields match it, and a found value that matches its `except` is left alone.
3. Collect what each rule found. Values marked as remembered join the word list.
4. Find every word, remembered value and listed value in one pass ([Aho-Corasick](https://docs.rs/aho-corasick)), as whole words in any case.
5. Where finds overlap, join them into one span that covers every byte any of them found. The earliest (then longest) gives the span its label.
6. Swap each find for its placeholder.

Every regex runs in linear time, and the word pass costs the same however many words there are. Measured on one laptop: 9 MB of nested JSON takes about 1.3 seconds, and 15 MB of text with two email addresses on every line about 0.9 seconds and 150 MB of memory.

## Placeholders

A placeholder is `[LABEL-` + the first 8 hex characters of HMAC-SHA256(key, value) + `]`.

- **The same value, the same tag,** within a run. Text still reads: you can tell one person from another.
- **Two values never share a tag.** If two would, the second is hashed again with a counter until its tag is free.
- **A tag cannot be worked back to its value** without the key. A plain hash would not be safe: anyone could hash a list of guesses and compare.
- **Without `REDACT_KEY`,** the key is 32 random bytes made fresh for each run, so tags from two runs cannot be matched.
- **With `REDACT_KEY`** (16+ characters), the same value gets the same tag in every run that uses the key, so several commands in one session agree.

```sh
export REDACT_KEY=$(openssl rand -hex 32)
```

## Fails closed

A pack, word list or config file that will not load stops redact with an error naming the file (exit code 3), rather than being skipped. A redactor that quietly skips a rule hides less than you think.

| Exit code | Meaning |
| :- | :- |
| 0 | Done |
| 2 | Bad usage, or a `REDACT_KEY` that is too short |
| 3 | A file would not load, or the scan failed |

## JSON spans

`redact scan --json` prints what it would hide as byte spans, with labels and rule names but never the values. A tool built on redact uses this to make its own placeholders.
