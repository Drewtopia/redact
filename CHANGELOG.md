# Changelog

## [0.2.1](https://github.com/Drewtopia/redact/compare/v0.2.0...v0.2.1) (2026-11-15)


### Features

* **config:** [packs] disable takes one rule as pack:rule ([d4a27c8](https://github.com/Drewtopia/redact/commit/d4a27c8571340ac7bdee53ff07bf0cc90c4b4e58))
* **config:** list missing layers in config ls, and add --json to config ls and packs ([66e0ef8](https://github.com/Drewtopia/redact/commit/66e0ef814bed3ab12e22b6461c9d7b8e8331050d)), closes [#34](https://github.com/Drewtopia/redact/issues/34)
* **credentials:** find Stripe test, webhook, GitLab, Groq, xAI and Google OAuth keys ([e824d5f](https://github.com/Drewtopia/redact/commit/e824d5f84bb8f0313ea3ebfd0ee76526cbde3df1))
* **credentials:** more vendor key shapes, a per-rule entropy field and a random-token rule ([e7a910f](https://github.com/Drewtopia/redact/commit/e7a910fb0605b11a9f5ddc39a27fe9f395f749fe))
* **pack:** add a per-rule context field of clue words ([8588b1c](https://github.com/Drewtopia/redact/commit/8588b1c2638666bcdac9e0c6fe4a8cf59aa64962))
* **pack:** add a per-rule entropy field and a random-token rule ([e07bb62](https://github.com/Drewtopia/redact/commit/e07bb6205848f1db93b21995d28018cc4a60fb1c))
* **pii:** hide phone numbers, SSNs and NI numbers only beside a clue word ([704292b](https://github.com/Drewtopia/redact/commit/704292beaec4feea90dbeaa2e00a7d7417108bee))


### Bug Fixes

* **claude:** fail closed on publishing commands, keep placeholder text escaped ([f86424e](https://github.com/Drewtopia/redact/commit/f86424effe66a917843409bfb6576d6d9e10be8a))
* **claude:** scan keys, field names and numbers in tool results ([#28](https://github.com/Drewtopia/redact/issues/28)) ([dd21093](https://github.com/Drewtopia/redact/commit/dd21093a146dda98a7afb8a7a8b3829a5bced47d))
* **claude:** withhold an errored result as a refusal ([fdd3ec7](https://github.com/Drewtopia/redact/commit/fdd3ec74369df7ea61d8cbd64cd310fdfa32155f))
* close redaction leaks in quoted flags, JSON results and publish commands ([029f01f](https://github.com/Drewtopia/redact/commit/029f01f63911b6c70d2d30242def529b8df999b1))
* close the four open findings from the redaction review ([1b463c8](https://github.com/Drewtopia/redact/commit/1b463c8850d6ac163a47f9219fd8b788322ab0fe))
* **credentials:** keep camelCase names out of random-token ([9e39f9a](https://github.com/Drewtopia/redact/commit/9e39f9a3449ab092efcdec25a77f73b9b3a37a0b))
* harden secret detection for quoted flags, JSON and git options ([775ebc1](https://github.com/Drewtopia/redact/commit/775ebc10cd4039e52404c5c8c792f0efb05de0bc))
* **packs:** credit Betterleaks for the Entra shape and tighten its test ([395e3e7](https://github.com/Drewtopia/redact/commit/395e3e7af7ff81a8996c7bc02cd21fa8d524d068))
* **packs:** hide a longer Entra token whole, keep what \b matched ([34999e3](https://github.com/Drewtopia/redact/commit/34999e3fa209f6ee54483369269ec8e2336272fb))
* **packs:** leave a paging cursor's name/value pair visible ([576d77f](https://github.com/Drewtopia/redact/commit/576d77ff44e6a8d024f9fb18a73c30211bd1d014))
* **packs:** leave paging cursors such as nextPageToken visible ([f07b391](https://github.com/Drewtopia/redact/commit/f07b391c37b0b10efbfe9c1217567104b7f2d52b))
* **packs:** match an Entra secret at the start of the input ([f096051](https://github.com/Drewtopia/redact/commit/f096051d22146f542a0d1ccf3723922223119c26))
* **packs:** match Entra client secrets with four characters before Q~ ([bd4689e](https://github.com/Drewtopia/redact/commit/bd4689e0e31e738eca2b0a4decddf65f0ad3b26f)), closes [#57](https://github.com/Drewtopia/redact/issues/57)
* **packs:** start shape rules after any delimiter, not at \b ([64777a3](https://github.com/Drewtopia/redact/commit/64777a3a5307b1c8d6243fcaedbd6d113f0fe3fc)), closes [#61](https://github.com/Drewtopia/redact/issues/61)
* **packs:** stop hiding masked values, comparisons and example.com emails ([6bde603](https://github.com/Drewtopia/redact/commit/6bde603a392362abdfb6cdd37c69917cc6f202cf))
* **plugin:** find redact in install folders when it is not on PATH ([#72](https://github.com/Drewtopia/redact/issues/72)) ([ca16a6b](https://github.com/Drewtopia/redact/commit/ca16a6b1fe429300a04c5f78c9775b74d3a90c0e))
* **scan:** look for clue words only 100 bytes either side of a value ([473f0e1](https://github.com/Drewtopia/redact/commit/473f0e1c3b93b353316e4134dab1d38507f1d0cf))
