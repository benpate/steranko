# Steranko 🔐

[![GoDoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://pkg.go.dev/github.com/benpate/steranko)
[![Version](https://img.shields.io/github/v/release/benpate/steranko?include_prereleases&style=flat-square&color=brightgreen)](https://github.com/benpate/steranko/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/benpate/steranko/go.yml?style=flat-square)](https://github.com/benpate/steranko/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/benpate/steranko?style=flat-square)](https://goreportcard.com/report/github.com/benpate/steranko)
[![Codecov](https://img.shields.io/codecov/c/github/benpate/steranko.svg?style=flat-square)](https://codecov.io/gh/benpate/steranko)

## Website Authentication/Authorization for Go

Steranko is an embeddable library that manages user authentication, and authorization.  You can configure it at run time (or compile time) to meet your specific project needs.

To use Steranko, you implement two interfaces in your code — a `UserService` (CRUD for your user records) and a `KeyService` (the keys that sign JWT tokens) — then wire Steranko's handlers into your HTTP server.

```go
// userService and keyService are YOUR implementations of the
// steranko.UserService and steranko.KeyService interfaces.
s := steranko.New(
    userService,
    keyService,
    steranko.WithPasswordSchema(schema.New(schema.String{MinLength: 20, Required: true})),
    steranko.WithPasswordHasher(hash.BCrypt(15)),
)

// Wire the handlers into an Echo server.
e := echo.New()
e.POST("/signin", func(ctx echo.Context) error {
    _, err := s.SigninFormPost(ctx)
    return err
})
e.POST("/signout", func(ctx echo.Context) error {
    s.SignOut(ctx)
    return nil
})

// Protect routes with the middleware, then read the authenticated claims.
e.GET("/profile", profileHandler, s.Middleware)
```

## DO NOT USE

This project is a work-in-progress, and should NOT be used by ANYONE, for ANY PURPOSE, under ANY CIRCUMSTANCES.  It is GUARANTEED to blow up your computer, send your cat into an infinite loop, and combine your hot and cold laundry into a single cycle.

## Project Goals

* Create a configurable, open source authentication/authorization system in Go.
* Hashed passwords using bcrypt
* Automatically upgrade password encryption cost on signin.
* Lock out user accounts after N failed attempts.
* Maintain security with [JWT tokens](https://jwt.io/)

* Password strength checking (via JSON-Schema extensions)
* Password vulnerability via HaveIBeenPwned API.

### Possible future additions

* Middleware tracks and blocks malicious users
  * Errors (like 404, and 500) have an associated number of points.
  * Track points per user/ip address with leaky bucket algorithm
  * Block users with a certain number of points
  * Ban users/ip addresses for repeated policy violations
  * Admin console allows tweaking of rules, reinstatement of banned accounts.

* Identify malicious users with a (relatively) invisible CAPTCHA system
  * Track javascript events during signup (keyup, keydown, mousemove, click)
  * Track timing of events.  They must not be too fast, or too consistent.
  * Something to prevent requests from being forwarded to an actual human.
  * Math problems?
  * Geolocation.

## What matters here

- **`User.SetPassword` takes a *ciphertext*, never a plaintext.** The `User` interface stores whatever string it is handed. Always hash first by calling the `Steranko.SetPassword` helper (which runs the configured `PasswordHasher`); calling `user.SetPassword` with a raw password persists cleartext and breaks every later signin.

- **The hasher list is ordered: index 0 is primary, the rest are deprecated.** A password matched by any non-primary hasher is transparently re-hashed with the primary on the next signin (the `Rehash`/upgrade path). This is how bcrypt cost upgrades roll out — keep old hashers in the list until every user has signed in.

- **`hash.Plaintext` is for development only and silently makes hashing a no-op.** Because plaintext "hashes" equal the password, tests that use it cannot detect a missing-hash bug. Test hashing-sensitive code paths against `hash.BCrypt` instead.

- **Failed signins are deliberately slow and constant-time.** `crypto/rand` jitter plus a cached decoy hash (`decoyPasswordHash`) keep a missing account indistinguishable from a wrong password, defeating username enumeration. Don't "optimize" these delays away.

- **Cookie names depend on TLS.** Secure requests use the `__Host-Authorization` prefix (domain-locked, HTTPS-only); plain HTTP uses `Authorization`. Signin and signout must agree on the name, which is why both route through `cookieName`.

- **JWT methods are allow-listed to HMAC only** (`JWTValidMethods`: HS256/384/512). This blocks the `alg:none` and algorithm-confusion attacks; don't widen it without reason.

## Pull Requests Welcome

Steranko is a work in progress, and will benefit from your experience reports, use cases, and contributions.  If you have an idea for making this library better, send in a pull request.  We're all in this together! 🔐
