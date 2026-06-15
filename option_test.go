package steranko

import (
	"encoding/json"
	"testing"

	"github.com/benpate/rosetta/schema"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/stretchr/testify/require"
)

func TestWithPasswordSchema(t *testing.T) {

	custom := schema.New(schema.String{MinLength: 3, MaxLength: 5})

	s := New(getTestUserService(), getTestKeyService(), WithPasswordSchema(custom))

	require.IsType(t, schema.String{}, s.passwordSchema.Element)
	require.Equal(t, 3, s.passwordSchema.Element.(schema.String).MinLength)
	require.Equal(t, 5, s.passwordSchema.Element.(schema.String).MaxLength)
}

func TestWithPasswordRules(t *testing.T) {

	// Rules are appended, so multiple calls accumulate.
	s := New(getTestUserService(), getTestKeyService())
	require.Empty(t, s.passwordRules)

	s.WithOptions(WithPasswordRules(allowAllRule{}))
	require.Len(t, s.passwordRules, 1)

	s.WithOptions(WithPasswordRules(rejectAllRule{}, allowAllRule{}))
	require.Len(t, s.passwordRules, 3)
}

func TestWithPasswordHasher(t *testing.T) {

	// WithPasswordHasher REPLACES the hasher list (it does not append).
	s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(hash.Plaintext{}, hash.BCrypt(4)))

	require.Len(t, s.passwordHashers, 2)
	require.Equal(t, "Plaintext", s.passwordHashers[0].ID())
	require.Equal(t, "BCrypt", s.passwordHashers[1].ID())
}

func TestWithSigninService(t *testing.T) {

	spy := &spySigninService{}
	s := New(getTestUserService(), getTestKeyService(), WithSigninService(spy))

	require.Same(t, spy, s.signinService)
}

func TestWithConfigFile(t *testing.T) {

	// A config with a populated schema overrides the default schema.
	{
		var passwordSchema schema.Schema
		require.Nil(t, json.Unmarshal([]byte(`{"type":"string", "minLength":12, "maxLength":40}`), &passwordSchema))

		config := Config{PasswordSchema: passwordSchema}
		s := New(getTestUserService(), getTestKeyService(), WithConfigFile(config))

		require.Equal(t, 12, s.passwordSchema.Element.(schema.String).MinLength)
		require.Equal(t, 40, s.passwordSchema.Element.(schema.String).MaxLength)
	}

	// A config with an empty (nil Element) schema must NOT clobber the default
	// schema installed by New.
	{
		s := New(getTestUserService(), getTestKeyService(), WithConfigFile(Config{}))

		require.NotNil(t, s.passwordSchema.Element, "empty config must not erase the default schema")
		require.Equal(t, 8, s.passwordSchema.Element.(schema.String).MinLength)
	}
}
