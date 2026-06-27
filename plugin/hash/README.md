# hash

`PasswordHasher` implementations for [Steranko](../../README.md). Pass one or more to `steranko.WithPasswordHasher`; the first is the primary algorithm used to hash new passwords, and the rest are accepted on signin and transparently upgraded to the primary.

- `BCrypt(cost)` — the production hasher. The `int` value is the bcrypt cost.
- `Plaintext{}` — a no-op "hasher" for development and tests **only**.

## What matters here

- **`CompareHashedPassword(ciphertext, plaintext)` — ciphertext first.** The stored hash is the first argument, the candidate password is the second. The interface and both implementations agree on this order; getting it backwards silently fails every comparison.

- **`Plaintext` makes hashing a no-op, which hides hashing bugs in tests.** `HashPassword` returns the input unchanged, so a code path that forgets to hash still "works" under Plaintext. Test anything that stores or compares passwords against `BCrypt`, not `Plaintext`.

- **BCrypt silently truncates input to 72 bytes.** That is bcrypt's hard limit; both `HashPassword` and `CompareHashedPassword` trim to 72 so the two sides stay consistent. Don't rely on bytes beyond 72 contributing to the hash.

- **`CompareHashedPassword` drives the cost-upgrade path.** BCrypt returns `rehash = true` when the stored hash's cost is below the configured cost, signaling Steranko to re-hash and re-save on signin. Plaintext always returns `rehash = true` so any plaintext password is upgraded the moment a real hasher is configured.

- **Plaintext comparison is constant-time** (`crypto/subtle.ConstantTimeCompare`) — kept even for the throwaway hasher so test timing matches production behavior.
