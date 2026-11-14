# Security

## Report privately

Use [a private report](https://github.com/Drewtopia/redact/security/advisories/new), not a public issue, when:

- the Claude Code mod lets a real value reach the model, a commit or the network
- a way to fool redact into restoring a value where it should not, or into skipping its checks
- you already leaked a real value while testing redact, and want it removed from somewhere this project controls

Include the redact version (`redact --version`), the mod version, and a reproduction with made-up values.

A pattern redact simply misses, with no way around a check, can go in a public [missed something](https://github.com/Drewtopia/redact/issues/new?template=missed.yml) issue with a fake value.

## What to expect

This is a hobby project, maintained in spare time. A report gets a first reply within a week. redact lowers the chance that sensitive text reaches an AI; it is not a guarantee, and comes with no warranty (see the licence).
