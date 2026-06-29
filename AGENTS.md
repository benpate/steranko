# Steranko — Notes for AI Agents

- **`User.SetPassword` takes a *ciphertext*, never a plaintext.** The `User` interface stores whatever string it is handed. Always hash first by calling the `Steranko.SetPassword` helper (which runs the configured `PasswordHasher`); calling `user.SetPassword` with a raw password persists cleartext and breaks every later signin.

- **The hasher list is ordered: index 0 is primary, the rest are deprecated.** A password matched by any non-primary hasher is transparently re-hashed with the primary on the next signin (the `Rehash`/upgrade path). This is how bcrypt cost upgrades roll out — keep old hashers in the list until every user has signed in.

- **`hash.Plaintext` is for development only and silently makes hashing a no-op.** Because plaintext "hashes" equal the password, tests that use it cannot detect a missing-hash bug. Test hashing-sensitive code paths against `hash.BCrypt` instead.

- **Failed signins are deliberately slow and constant-time.** `crypto/rand` jitter plus a cached decoy hash (`decoyPasswordHash`) keep a missing account indistinguishable from a wrong password, defeating username enumeration. Don't "optimize" these delays away.

- **Cookie names depend on TLS.** Secure requests use the `__Host-Authorization` prefix (domain-locked, HTTPS-only); plain HTTP uses `Authorization`. Signin and signout must agree on the name, which is why both route through `cookieName`.

- **JWT methods are allow-listed to HMAC only** (`JWTValidMethods`: HS256/384/512). This blocks the `alg:none` and algorithm-confusion attacks; don't widen it without reason.
