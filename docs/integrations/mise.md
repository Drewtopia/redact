# mise

## Install redact

```sh
mise use -g github:Drewtopia/redact
```

## Hide a project's `[env]`

Inside a project, `mise exec` sets the variables in the project's `[env]`. Name them in `env`, as in [Hide environment variables](../guide/env), then run redact under `mise exec`:

```sh
mise exec -- sh -c 'docker compose logs | redact'
```

With [fnox](./fnox) as well, see that page.
