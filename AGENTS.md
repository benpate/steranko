# Steranko — Notes for AI Agents

- **`User.SetHashedPassword` takes an *already-hashed* value, never a plaintext.** The `User` interface stores whatever string it is handed. Always hash first via `PasswordService.SetPassword` (or the `Steranko.SetPassword` delegation); handing `user.SetHashedPassword` a raw password persists cleartext and breaks every later signin. (The methods were renamed from `Get`/`SetPassword` in the v0.28 breaking change precisely so that raw-plaintext call sites fail to compile.)

- **`PasswordService` owns the hasher chain — never index it from outside.** "The first hasher is the primary" is encoded exactly once, in `PasswordService.primary()`. Applications that need to hash without a full Steranko instance construct one `PasswordService` and share it with Steranko via `WithPasswordService`; they must not reach into a hasher list with `[0]`.

- **The hasher list is ordered: index 0 is primary, the rest are deprecated.** A password matched by any non-primary hasher is transparently re-hashed with the primary on the next signin (the `Rehash`/upgrade path). This is how bcrypt cost changes roll out — keep old hashers in the list until every user has signed in. `BCrypt.CompareHashedPassword` flags a rehash whenever the stored cost differs from the configured cost in EITHER direction: raising the cost upgrades weak hashes, and lowering it retires over-expensive hashes (and their slow comparisons) on the next signin.

- **`hash.Plaintext` is for development only and silently makes hashing a no-op.** Because plaintext "hashes" equal the password, tests that use it cannot detect a missing-hash bug. Test hashing-sensitive code paths against `hash.BCrypt` instead.

- **Failed signins are deliberately slow and constant-time.** `crypto/rand` jitter plus a cached decoy hash (`decoyPasswordHash`) keep a missing account indistinguishable from a wrong password, defeating username enumeration. Don't "optimize" these delays away.

- **Stored bcrypt costs are bounded before they are honored.** `BCrypt.CompareHashedPassword` reads the cost out of the stored hash with `bcrypt.Cost` (~50µs) and refuses anything above `max(configured cost, MaximumCost)` before running the comparison. bcrypt's work factor is exponential and comes from attacker-reachable stored data, so an unbounded cost is a hang: cost 20 is ~52s, cost 24 is ~15 minutes, cost 31 is days. `MaximumCost` is 15; raising the ceiling for an application that configures a higher cost is deliberate, so it is never locked out of its own hashes. Two fuzz crashers are pinned in `plugin/hash/testdata/fuzz`.

- **A cookie read from a REQUEST carries only Name and Value.** Browsers never send `Secure`/`HttpOnly`/`SameSite`/`Path` back, so those fields cannot be copied off `ctx.Cookie(...)` — they must be rebuilt. `stashBackup` rebuilds them deliberately; an earlier version copied them and produced a script-readable, non-`Secure` cookie holding a live session token, which the `__Host-` prefix rules then made browsers discard entirely.

- **Both middlewares must apply the same chain.** `Middleware(factory)` delegates to `(*Steranko).Middleware` rather than re-implementing it. Re-implementing it is how the multi-tenant path silently lost session revalidation and kept admitting deleted users.

- **Cookie names depend on TLS.** Secure requests use the `__Host-Authorization` prefix (domain-locked, HTTPS-only); plain HTTP uses `Authorization`. Signin and signout must agree on the name, which is why both route through `cookieName`.

- **JWT methods are allow-listed to HMAC only** (`JWTValidMethods`: HS256/384/512). This blocks the `alg:none` and algorithm-confusion attacks; don't widen it without reason.
