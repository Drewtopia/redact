---
layout: home

hero:
  name: redact
  text: Keep secrets out of what AI sees
  tagline: Pipe any output through redact. The parts that say who you are or how to get in come back as placeholders, so you can hand the rest to Claude, Codex or a chat window.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: See it work
      link: /guide/see-it-work
    - theme: alt
      text: What it hides
      link: /packs/

features:
  - title: Built to extend
    details: Everything redact hides comes from packs. A few ship built in. Add your own TOML packs and word lists, switch packs on or off, or turn off one rule. Loading gitleaks and Betterleaks rules is planned.
  - title: Finds things by where they sit
    details: The value after password=, the name in a git Author line, the token in an Authorization header. You do not have to list them.
  - title: Placeholders that still make sense
    details: Each hidden part becomes a labelled tag like [PERSON-3f1a9c2e]. The same value gets the same tag, so the text still reads.
  - title: Hides what your environment holds
    details: Hides the values of the environment variables you name and of your .env files, whatever set them, and your own git and GitHub identity.
  - title: One config, every machine
    details: Leave your own organisation visible, switch packs on or off, and change settings by machine, folder or command, all in config.toml.
---

::: warning Work in progress
redact hides a lot, but not everything, and it will miss things. Check its output before you share anything that matters, and do not rely on it as your only safeguard.
:::
