# rule

`PasswordRule` implementations for [Steranko](../../README.md) that enforce password-composition policy. Pass any combination to `steranko.WithPasswordRules`; every configured rule must pass for a password to be accepted.

Each rule is a named integer (or regex) type so it carries its threshold inline:

- `MinLength(n)` — minimum character count.
- `MinUppercase(n)`, `MinLowercase(n)`, `MinDigits(n)`, `MinSymbols(n)` — minimum count of each character class.
- `MinComplexity(n)` — minimum number of possible password combinations (an entropy-style floor).

The character-class counting helpers used by these rules (`CountDigits`, `CountUppercase`, `CountLowercase`, `CountSymbols`) live in `regex.go`.

## What matters here

- **Rules are AND-ed: all must pass.** Steranko stops at the first failing rule and returns its message. There is no "any of" combinator — compose policy by adding rules, not by relaxing them.

- **Character-class counts use Unicode-aware matching.** The counting helpers (`CountDigits`, `CountUppercase`, etc.) run over runes via regex, so multi-byte input is counted correctly rather than by byte.

- **`MinComplexity` measures the search space, not raw length.** It estimates combinations from the character classes actually present, so a long single-class password can still fail. Use it when you care about guess-resistance rather than a literal length floor.
