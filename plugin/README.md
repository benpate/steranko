# Steranko Plugins

Pluggable implementations of the interfaces that [Steranko](../README.md) leaves open for the host application. Each subdirectory provides drop-in values you pass to `steranko.New` via functional options.

- [`hash`](hash/README.md) — `PasswordHasher` implementations (BCrypt for production, Plaintext for development).
- [`rule`](rule/README.md) — `PasswordRule` implementations that enforce password-composition policy (length, character classes, complexity, regex).
- [`haveibeenpwned`](haveibeenpwned/README.md) — a `PasswordRule` that rejects passwords found in known breaches via the HaveIBeenPwned API.

## What matters here

- **Plugins implement Steranko's consumer interfaces; they never import each other.** A plugin depends only on the small interface it satisfies (`PasswordHasher` or `PasswordRule`), so any plugin can be swapped or replaced by a host-provided implementation without touching the others.

- **Order matters for hashers, not for rules.** The first `PasswordHasher` is primary and the rest are deprecated-but-accepted (see [`hash`](hash/README.md)). `PasswordRule`s are all-or-nothing: every configured rule must pass.
