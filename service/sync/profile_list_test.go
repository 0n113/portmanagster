package sync

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safing/portmaster/service/profile"
)

// TestListProfiles checks that the list contains the scoped IDs sorted, marks
// special profiles and filters by source.
//
//nolint:paralleltest // Uses the global database.
func TestListProfiles(t *testing.T) {
	save := func(source profile.ProfileSource, id, name string) {
		t.Helper()
		p := &profile.Profile{ID: id, Source: source, Name: name, Config: map[string]any{}}
		p.SetKey(profile.MakeProfileKey(source, id))
		require.NoError(t, p.Save())
	}
	save(profile.SourceLocal, "list-b", "B")
	save(profile.SourceLocal, "list-a", "A")
	save(profile.SourceLocal, profile.SystemProfileID, "System")
	save(profile.SourceSpecial, "list-special", "S")

	all, err := ListProfiles("")
	require.NoError(t, err)
	byID := make(map[string]ProfileListEntry, len(all))
	for i, e := range all {
		byID[e.ID] = e
		if i > 0 {
			assert.Less(t, all[i-1].ID, e.ID, "list must be sorted by ID")
		}
	}
	require.Contains(t, byID, "local/list-a")
	require.Contains(t, byID, "local/list-b")
	require.Contains(t, byID, "special/list-special")
	assert.Equal(t, "A", byID["local/list-a"].Name)
	assert.False(t, byID["local/list-a"].Special)
	assert.True(t, byID["local/"+profile.SystemProfileID].Special, "the system profile is special")

	local, err := ListProfiles(profile.SourceLocal)
	require.NoError(t, err)
	for _, e := range local {
		assert.Equal(t, profile.SourceLocal, e.Source, "source filter: %s", e.ID)
	}
	assert.NotEmpty(t, local)
}
