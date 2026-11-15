# fnox

[fnox](https://github.com/jdx/fnox) sets secrets as environment variables. Name them in `env`, as in [Hide environment variables](../guide/env), then run redact under `fnox exec`, so fnox sets the variables first:

```sh
kubectl get pods -o yaml | fnox exec -- redact
```

fnox has its own `fnox exec --redact`, which replaces fnox's values with `[REDACTED]` in a command's output. redact also hides shapes such as tokens and people, and gives each value a labelled placeholder. You can use both together.

With [mise](./mise) as well, nest the commands:

```sh
fnox exec -- mise exec -- sh -c 'docker compose logs | redact'
```
