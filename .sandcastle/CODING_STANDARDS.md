# Coding Standards

The reviewer agent loads this file during review. The repo's own rules come first:
the agent guide at the repo root, `CONTRIBUTING.md`, `commit-check.toml`, and `docs/agents/`.

## Style

- `cargo fmt` formatting, and no `cargo clippy --all-targets -- -D warnings` findings.
- Errors carry context; no `unwrap()` or `expect()` on input the user controls.

## Testing

- New or changed behaviour has a test that fails without the change.
- Test fixtures use made-up values only, never a real name, address, key or host.

## Architecture

- Keep the change as small as the issue needs. No speculative options or abstractions.
- A change to user-visible behaviour updates the docs under `docs/` (see `docs/agents/writing-docs.md`).
