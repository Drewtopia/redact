# Git hooks and CI

`redact scan --json` prints `[]` when it finds nothing, so `jq -e` can turn it into a check. The check below fails when a line that the staged change adds holds anything redact would hide. `grep '^+'` keeps only the added lines, so a commit that removes a leaked value still goes through.

```sh
git diff --cached -U0 | grep '^+' | redact scan --json | jq -e 'length == 0' > /dev/null
```

Put the check in `.git/hooks/pre-commit`. You can also run it in CI against a log or an artifact before you upload it.

To see which rule fired, run it again with `--explain`. It never prints the value:

```sh
git diff --cached -U0 | grep '^+' | redact scan --explain > /dev/null
```
