# See it work

When you give an AI the output of a command, the names, emails and keys in it go too. This page shows what redact does about that, in both directions: how it hides them, and how the Claude Code mod still lets Claude use them without seeing them.

## Hide them: one way only

The `redact` command only goes one way. Text goes in, and the same text comes out with each secret swapped for a tag:

```sh
cat .env | redact
```

```text
ACME_API_KEY=[SECRET-c27f8a14]
DATABASE_PASSWORD=[SECRET-3b9e1d0a]
```

There is no command to turn a tag back into its value, on purpose. A tag is made from the value and a secret key, by default a new one for each run, so nobody can work the value out from the tag: not Claude, and not anyone who sees the chat later.

That is enough when you paste output into a chat window: the AI reads the text and never needs the real values.

## Use them without seeing them: the Claude Code mod

Claude Code does more than read. It runs commands on your computer, and a command sometimes needs the real key. The [Claude Code mod](../integrations/claude-code) handles both directions:

1. It hides everything Claude would read, as the `redact` command does.
2. It remembers which tag stands for which value, in memory on your computer, for as long as the session lasts.
3. When Claude runs a command that holds a tag, the mod puts the real value in just before it runs.
4. When the command prints the value back, the mod hides it again before Claude reads it.

Click through it below. It runs in your browser with a few simple rules, not redact's packs, and sends nothing anywhere.

<ClientOnly>
  <RedactDemo />
</ClientOnly>

## In plain words

Think of your secrets as house keys, and Claude as a helper who is great at chores.

- **Name tags, not keys.** Before the helper sees anything, each key is swapped for a name tag, such as "the blue key". The helper only ever holds the tag.
- **The real key, only for the chore.** When the helper needs the blue key to open a door, the mod takes the real key out of a locked box, opens the door, and puts it back. The helper sees the door open, not the key.
- **Tags back on the way out.** If the door shows the key again, the mod covers it with its tag before the helper looks.

## What it misses

redact finds values by their shape and by where they sit, so it misses some, and the mod cannot stop every way a command could send a value somewhere. Check the output before you share anything that matters. The [limits](../reference/limits) page lists what it misses.
