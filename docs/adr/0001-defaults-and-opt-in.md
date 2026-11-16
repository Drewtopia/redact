# 1. Hide little by default, and let people add the rest

Status: proposed

## Context

redact started as a way to keep credentials out of text an AI agent reads. It grew to hide names too: people, organisations, projects, repos and hosts. Most of those were switched on by default.

Using it day to day showed the cost:

- A hidden name turns up in paths, commands, links and commit lines. Each one becomes a placeholder, and the command or link breaks ([#104](https://github.com/Drewtopia/redact/issues/104), [#81](https://github.com/Drewtopia/redact/issues/81)).
- Hiding names is never complete. A repo name was only hidden after the session had seen it in a git URL, so it showed in clear at the start of every session.
- Each fix for one of these brought a new edge case, and the Claude Code mod grew special cases faster than anyone could follow them.

Credentials are different. An agent almost never needs to write one in a reply, so hiding them costs almost nothing.

## Decision

1. **Sensible defaults, everything else opt-in.** A default must earn its place: it protects something that matters, and it rarely breaks normal work.
2. **On by default: credentials.** Tokens, keys, passwords and secret values. redact should use the rules from tools built for this, such as Betterleaks and gitleaks ([#44](https://github.com/Drewtopia/redact/issues/44), [#46](https://github.com/Drewtopia/redact/issues/46)), instead of keeping its own large list.
3. **On by default: people.** Names, emails and logins in tool and command output. Other people did not agree to be shared.
4. **Opt-in: your own details and your work's names.** You (`me = true`), and organisation, project, repo and host names. Each is a pack or setting a person turns on.
5. **Easy to extend, the way dcg and worktrunk are.** People add their own packs and word lists, switch packs on and off and single rules off, and allow values. This already works; new features should keep using these same tools instead of adding new kinds of settings.

For the Claude Code mod:

6. **A person can always tell whether redact is on.** A mod that is switched off or cannot find its binary must not look the same as one that found nothing.
7. **The same everywhere.** One install path, from the published release, on every machine.

## What is on by default

| What | Default | Where today |
| :- | :- | :- |
| Credentials: tokens, keys, passwords, cookies, secret values | On | `credentials`, `npm`, `docker`, `http`, `kubernetes`, `gcp` tokens |
| People: names, emails, logins | On | `identity`, people rules in `azure` |
| Cloud IDs: tenant, subscription, object IDs | On | `azure` |
| You: your name, email and GitHub login | Off; `redact config init` writes `me = true` | `me` |
| Work names: organisation, project, repo, host | **Off (change)** | `azure` name rules, `gcp` project IDs |
| Personal data: phone, card, IBAN, IP, national ID | Off | `pii` |
| Your own lists and packs | Yours | `~/.config/redact/packs/` |

The one change from today: the work-name rules move out of the default set into a pack that a person switches on.

## Consequences

- Fewer placeholders in what an agent writes, so fewer broken commands and links.
- Someone who wants work names hidden turns on one pack, and accepts that some commands and links will hold placeholders.
- Issues are weighed against this record: work that adds a new default, or a new kind of setting, needs a reason to break it.
