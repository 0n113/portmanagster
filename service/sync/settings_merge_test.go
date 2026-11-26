package sync

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safing/portmaster/base/config"
)

// TestMergeSettings checks that an import without reset keeps the global
// settings that are not part of the import.
func TestMergeSettings(t *testing.T) {
	t.Parallel()

	const changed = "a/changed"
	current := map[string]any{"a/kept": 5, changed: 6}
	merged := mergeSettings(current, map[string]any{changed: 7, "a/new": 8})
	assert.Equal(t, map[string]any{"a/kept": 5, changed: 7, "a/new": 8}, merged)
	assert.Equal(t, 6, current[changed], "current must not be modified")
}

// TestGlobalUserSettings checks that options without a user value are left out.
func TestGlobalUserSettings(t *testing.T) {
	t.Parallel()

	const key = "test/sync/userSettingsUnset"
	_, err := config.GetOption(key)
	if err != nil {
		require.NoError(t, config.Register(&config.Option{
			Name:         "User Settings Test",
			Key:          key,
			Description:  "test option",
			OptType:      config.OptTypeInt,
			DefaultValue: 1,
		}))
	}
	assert.NotContains(t, globalUserSettings(), key)
}
