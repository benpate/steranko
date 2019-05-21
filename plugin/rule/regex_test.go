package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCountDigits(t *testing.T) {

	assert.Equal(t, 0, CountDigits("hello-there"))
	assert.Equal(t, 1, CountDigits("1hello-there"))
	assert.Equal(t, 2, CountDigits("1hello-there2"))
	assert.Equal(t, 3, CountDigits("1hello-2there3"))
	assert.Equal(t, 4, CountDigits("1Hello-2There34"))
	assert.Equal(t, 9, CountDigits("123456789"))
	assert.Equal(t, 10, CountDigits("1234567890"))
	assert.Equal(t, 20, CountDigits("12345678901234567890"))
}

func TestCountLowercase(t *testing.T) {

	assert.Equal(t, 0, CountLowercase(""))
	assert.Equal(t, 0, CountLowercase("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	assert.Equal(t, 0, CountLowercase("@#$%^&*"))
	assert.Equal(t, 0, CountLowercase("1234567890"))
	assert.Equal(t, 1, CountLowercase("12345-a-67890"))
	assert.Equal(t, 1, CountLowercase("a1234567890"))
	assert.Equal(t, 1, CountLowercase("1234567890b"))
	assert.Equal(t, 1, CountLowercase("a"))
	assert.Equal(t, 2, CountLowercase("ab"))
	assert.Equal(t, 3, CountLowercase("xyz"))
	assert.Equal(t, 25, CountLowercase("abcdefghijklmnopqrstuvwxy"))
	assert.Equal(t, 26, CountLowercase("abcdefghijklmnopqrstuvwxyz"))
}

func TestCountUppercase(t *testing.T) {

	assert.Equal(t, 0, CountUppercase(""))
	assert.Equal(t, 0, CountUppercase("abcdefghijklmnopqrztuvwxyz"))
	assert.Equal(t, 0, CountUppercase("@#$%^&*"))
	assert.Equal(t, 0, CountUppercase("1234567890"))
	assert.Equal(t, 1, CountUppercase("12345-A-67890"))
	assert.Equal(t, 1, CountUppercase("A1234567890"))
	assert.Equal(t, 1, CountUppercase("1234567890B"))
	assert.Equal(t, 1, CountUppercase("A"))
	assert.Equal(t, 2, CountUppercase("AB"))
	assert.Equal(t, 3, CountUppercase("XYZ"))
	assert.Equal(t, 25, CountUppercase("ABCDEFGHIJKLMNOPQRSTUVWXY"))
	assert.Equal(t, 26, CountUppercase("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
}

func TestCountSymbol(t *testing.T) {

	assert.Equal(t, 0, CountSymbols(""))
	assert.Equal(t, 0, CountSymbols("abcdefghijklmnopqrztuvwxyz"))
	assert.Equal(t, 0, CountSymbols("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	assert.Equal(t, 0, CountSymbols("1234567890"))
	assert.Equal(t, 1, CountSymbols(`\`))
	assert.Equal(t, 1, CountSymbols(`"`))
	assert.Equal(t, 2, CountSymbols("!@"))
	assert.Equal(t, 3, CountSymbols(")(*"))
	assert.Equal(t, 32, CountSymbols("`~!@#$%^&*()_-+={[}]|:;'<,>.?/)"+`"`))
}
