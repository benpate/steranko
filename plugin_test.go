package steranko

import (
	"testing"

	"github.com/benpate/data/memory"
	"github.com/stretchr/testify/assert"
)

func TestPlugins(t *testing.T) {

	ds := memory.New()

	s := New(ds)

	assert.Empty(t, s.Plugins)

	empty := pluginEmpty(true)
	s.UsePlugin(empty)

	{
		assert.NotEmpty(t, s.Plugins)
		assert.Equal(t, 1, len(s.Plugins))
		assert.Equal(t, "EmptyPlugin", s.Plugins[0].Name())
	}

	{
		result := s.RemovePlugin("EmptyPlugin")
		assert.True(t, result)
		assert.Empty(t, s.Plugins)
		assert.Equal(t, 0, len(s.Plugins))
	}

	{
		result := s.RemovePlugin("NonExistantPlugin")
		assert.False(t, result)
		assert.Empty(t, s.Plugins)
		assert.Equal(t, 0, len(s.Plugins))
	}
}

type pluginEmpty bool

func (p pluginEmpty) Name() string {
	return "EmptyPlugin"
}
