# Steranko 🔐

[![Go Reference](https://pkg.go.dev/badge/github.com/benpate/steranko.svg)](https://pkg.go.dev/github.com/benpate/steranko)
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

## Pull Requests Welcome

Steranko is a work in progress, and will benefit from your experience reports, use cases, and contributions. If you have an idea for making this library better, send in a pull request. We're all in this together! 🔐
