# Prior art and thanks

redact borrows ideas, not code, from tools it was built alongside. Thank you to their authors.

| Project | The idea redact takes from it |
| :- | :- |
| [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) | Rule packs with a keyword pre-check, community packs on top of built-in ones, and refusing a pack that will not load. dcg guards the commands an agent runs; redact guards the text it reads |
| [transcript-redactor](https://github.com/ray-amjad/claude-code-mods) by Ray Amjad | Placeholders that stand for a value and can be turned back into it, and the shapes of several credentials (Entra client secrets, Azure storage keys and SAS signatures). MIT licence |
| [fnox](https://github.com/jdx/fnox) | Config imports resolved beside the file that names them, and `fnox exec --redact` masking values in output |
| [mise](https://mise.jdx.dev) | Layered config files and a command that lists which ones loaded |
| [worktrunk](https://github.com/max-sixty/worktrunk) | Config layers merged in a fixed order, and typos in config reported rather than ignored |
| [dotenvx](https://dotenvx.com) | Hiding every value in a `.env` file, `.env.keys` included |
| [gitleaks](https://github.com/gitleaks/gitleaks) | The `regex`, `keywords` and `secretGroup` field names of its rule files |

The docs are built with [VitePress](https://vitepress.dev).
