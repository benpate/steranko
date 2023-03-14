# Steranko 🔐

[![GoDoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://pkg.go.dev/github.com/benpate/steranko)
[![Build Status](https://img.shields.io/github/actions/workflow/status/benpate/steranko/go.yml?branch=main)](https://github.com/benpate/steranko/actions/workflows/go.yml)
[![Codecov](https://img.shields.io/codecov/c/github/benpate/steranko.svg?style=flat-square)](https://codecov.io/gh/benpate/steranko)
[![Go Report Card](https://goreportcard.com/badge/github.com/benpate/steranko?style=flat-square)](https://goreportcard.com/report/github.com/benpate/steranko)
[![Version](https://img.shields.io/github/v/release/benpate/steranko?include_prereleases&style=flat-square&color=brightgreen)](https://github.com/benpate/steranko/releases)
![Lines of Code](https://shields.io/tokei/lines/github.com/benpate/steranko)

## Website Authentication/Authorization for Go

**This project is a work-in-progress, and should NOT be used by ANYONE, for ANY PURPOSE, under ANY CIRCUMSTANCES.  It is GUARANTEED to blow up your computer, send your cat into an infinite loop, and combine your hot and cold laundry into a single cycle.**

Steranko is an embeddable library that manages user authentication, and authorization.  You can configure it at run time (or compile time) to meet your specific project needs.

To use Steranko, you have to implement two tiny interfaces in your code, then wire Steranko's handlers into your HTTP server.

```go
s := steranko.New(userService, steranko.Conig{
    Tokens: "cookie:auth",
    PasswordSchema: `{"type":"string", "minLength":20}`
})

s.Register(echo)
```

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

## Pull Requests Welcome

Steranko is a work in progress, and will benefit from your experience reports, use cases, and contributions.  If you have an idea for making this library better, send in a pull request.  We're all in this together! 🔐
