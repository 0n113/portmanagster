package sync

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/safing/portmaster/base/config"
)

// TestImportRefusesLockedSettings checks that settings locked by the
// management policy cannot be imported, globally or into a profile.
//
//nolint:paralleltest // Uses the global config.
func TestImportRefusesLockedSettings(t *testing.T) {
	registerNilConfigTestOption(t)
	require.Empty(t, config.SetPolicy(map[string]any{nilConfigTestOptionKey: true}, []string{nilConfigTestOptionKey}))
	t.Cleanup(func() { config.SetPolicy(nil, nil) })

	for _, target := range []string{ExportTargetGlobal, "local/some-profile"} {
		_, err := ImportSettings(&SettingsImportRequest{
			ImportRequest: ImportRequest{Target: target, ValidateOnly: true},
			Export: &SettingsExport{
				Type:   TypeSettings,
				Config: config.Expand(map[string]any{nilConfigTestOptionKey: false}),
			},
		})
		if !errors.Is(err, config.ErrLockedByPolicy) {
			t.Fatalf("%s: want ErrLockedByPolicy, got %v", target, err)
		}
	}
	_, err := ImportSingeSetting(&SingleSettingImportRequest{
		ImportRequest: ImportRequest{Target: ExportTargetGlobal, ValidateOnly: true},
		Export:        &SingleSettingExport{Type: TypeSingleSetting, ID: nilConfigTestOptionKey, Value: false},
	})
	if !errors.Is(err, config.ErrLockedByPolicy) {
		t.Fatalf("single setting: want ErrLockedByPolicy, got %v", err)
	}

	// The effective export shows the policy value.
	export, err := ExportEffectiveSettings(ExportTargetGlobal, []string{nilConfigTestOptionKey})
	require.NoError(t, err)
	require.Equal(t, true, config.Flatten(export.Config)[nilConfigTestOptionKey])
	_, err = ExportEffectiveSettings("local/some-profile", nil)
	require.Error(t, err)
}
