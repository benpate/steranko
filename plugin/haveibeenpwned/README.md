# haveibeenpwned

A [Steranko](../../README.md) `PasswordRule` that rejects passwords appearing in known data breaches, using the [HaveIBeenPwned](https://haveibeenpwned.com) Pwned Passwords API. Pass `&API{}` to `steranko.WithPasswordRules`.

## What matters here

- **The password is never sent to the API; only a SHA-1 prefix is.** It uses the [k-anonymity range API](https://haveibeenpwned.com/API/v3#PwnedPasswords): the client sends the first 5 hex characters of the SHA-1 hash and matches the remaining suffix against the returned list locally. The `crypto/sha1` use is required by that protocol — it is not a security weakness here, which is why it carries a `//nolint`.

- **It fails *open*.** If the API is unreachable or the response exceeds the size cap, `ValidatePassword` returns `OK = true` rather than blocking every signin on a third-party outage. This is a deliberate availability-over-strictness trade-off; the breach check is defense-in-depth, not the primary password gate.

- **The response is size-capped** (`MaxResponseSize`) so a hostile or malfunctioning server cannot exhaust memory.

- **The unit test is gated behind `//go:build localonly`.** `haveibeenpwned_test.go` calls the live API, so it is excluded from normal `go test` / CI runs (this is why the package reports 0% coverage in CI). Run it explicitly with `go test -tags localonly ./plugin/haveibeenpwned/` when you need to verify against the real service.
