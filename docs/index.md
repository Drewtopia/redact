---
layout: home

hero:
  name: redact
  text: Keep secrets out of what AI sees
  tagline: Pipe any output through redact. The parts that say who you are, who you work for or how to get in come back as placeholders, so you can hand the rest to Claude, Codex or a chat window.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: What it hides
      link: /packs/

features:
  - title: Finds things by where they sit
    details: The value after password=, the name in a git Author line, the token in an Authorization header. You do not have to list them.
  - title: Placeholders that still make sense
    details: Each hidden part becomes a labelled tag like [PERSON-3f1a9c2e]. The same value gets the same tag, so the text still reads.
  - title: Works with what you have
    details: Hides the values fnox, mise or a .env file hold, and your own git and GitHub identity, without reading their files.
  - title: Rule packs
    details: Built-in packs for credentials, people, Kubernetes, Docker, npm, HTTP headers, Google Cloud and Azure, plus an opt-in pack for personal data. Write your own in TOML.
  - title: One config, every machine
    details: Leave your own organisation visible, switch packs on or off, and change settings by machine, folder or command, all in config.toml.
---

::: warning Work in progress
redact hides a lot, but not everything, and it will miss things. Check its output before you share anything that matters, and do not rely on it as your only safeguard.
:::
