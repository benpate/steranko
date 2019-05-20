package password

import (
	"regexp"
)

var digitsRegex = regexp.MustCompile("[0123456789]")
var uppercaseRegex = regexp.MustCompile("[ABCDEFGHIJKLMNOPQRSTUVWXYZ]")
var lowercaseRegex = regexp.MustCompile("[abcdefghijklmnopqrstuvwxyz]")
var symbolRegex = regexp.MustCompile(`[\~\!\@\#\$\%\^\&\*\(\)\_\+\=\{\[\}\]\|\:\;\'\<\,\>\.\?\/\}\"\\\-` + "`]")

// CountDigits returns the number of digits in a string
func CountDigits(value string) int {
	return count(value, digitsRegex)
}

// CountUppercase returns the number of uppercase letters in a string
func CountUppercase(value string) int {
	return count(value, uppercaseRegex)
}

// CountLowercase returns the number of lowercase letters in a string
func CountLowercase(value string) int {
	return count(value, lowercaseRegex)
}

// CountSymbols returns the number of special symbols in a string
func CountSymbols(value string) int {
	return count(value, symbolRegex)
}

// count uses a regular expression to count the number of occurrences of a
// character in the provided string.
func count(value string, re *regexp.Regexp) int {

	array := re.FindAll([]byte(value), -1)

	if array == nil {
		return 0
	}

	return len(array)
}
