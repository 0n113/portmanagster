package config

import (
	"errors"
	"sync"
	"testing"

	"github.com/tidwall/gjson"
)

const (
	keyLocked  = "test/locked"
	keyDefault = "test/default"
	keyLater   = "test/later"
)

func registerPolicyTestOptions(t *testing.T) {
	t.Helper()
	options = make(map[string]*Option)
	for _, o := range []*Option{
		{Name: "a", Key: keyLocked, Description: "d", OptType: OptTypeInt, DefaultValue: 1},
		{Name: "b", Key: keyDefault, Description: "d", OptType: OptTypeInt, DefaultValue: 1},
		{Name: "c", Key: "test/free", Description: "d", OptType: OptTypeInt, DefaultValue: 1},
	} {
		err := Register(o)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		SetPolicy(nil, nil)
		options = make(map[string]*Option)
	})
}

func TestPolicyPrecedence(t *testing.T) { //nolint:paralleltest // Uses global state.
	registerPolicyTestOptions(t)

	locked := GetAsInt(keyLocked, 0)
	def := GetAsInt(keyDefault, 0)
	free := GetAsInt("test/free", 0)

	vErrs, _ := ReplaceConfig(map[string]any{keyLocked: 2, keyDefault: 2, "test/free": 2})
	if len(vErrs) > 0 {
		t.Fatal(vErrs[0])
	}
	vErrs = SetPolicy(map[string]any{keyLocked: 9, keyDefault: 8}, []string{keyLocked})
	if len(vErrs) > 0 {
		t.Fatal(vErrs[0])
	}
	// The locked value wins over the user value; the user value wins over
	// the policy default.
	if locked() != 9 || def() != 2 || free() != 2 {
		t.Fatalf("with user values: locked %d default %d free %d", locked(), def(), free())
	}
	if !IsLocked(keyLocked) || IsLocked(keyDefault) || IsLocked("unknown") {
		t.Fatal("IsLocked is wrong")
	}

	// Without user values the policy default applies.
	vErrs, _ = ReplaceConfig(map[string]any{})
	if len(vErrs) > 0 {
		t.Fatal(vErrs[0])
	}
	if locked() != 9 || def() != 8 || free() != 1 {
		t.Fatalf("without user values: locked %d default %d free %d", locked(), def(), free())
	}

	// Writes of a locked key are refused; others work.
	err := SetConfigOption(keyLocked, 3)
	if !errors.Is(err, ErrLockedByPolicy) {
		t.Fatalf("want ErrLockedByPolicy, got %v", err)
	}
	err = SetConfigOption(keyLocked, nil)
	if !errors.Is(err, ErrLockedByPolicy) {
		t.Fatalf("delete: want ErrLockedByPolicy, got %v", err)
	}
	err = SetConfigOption(keyDefault, 4)
	if err != nil || def() != 4 {
		t.Fatalf("set unlocked key: %v, value %d", err, def())
	}
	err = CheckNotLocked("test/free", keyLocked)
	if !errors.Is(err, ErrLockedByPolicy) {
		t.Fatalf("CheckNotLocked: %v", err)
	}
	if CheckNotLocked("test/free", "unknown") != nil {
		t.Fatal("CheckNotLocked refuses unlocked keys")
	}
	if keys := LockedKeys(); len(keys) != 1 || keys[0] != keyLocked {
		t.Fatalf("LockedKeys: %v", keys)
	}

	// The record for the UI shows the policy.
	opt, _ := GetOption(keyLocked)
	r, err := opt.Export()
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.MarshalRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	// The record has a format prefix byte before the JSON.
	j := data[1:]
	if gjson.GetBytes(j, "PolicyValue").Int() != 9 || !gjson.GetBytes(j, "Locked").Bool() ||
		gjson.GetBytes(j, "Annotations").Get(escapeKey(PolicyAnnotation)).String() != PolicyLocked {
		t.Fatalf("record: %s", j)
	}
	if v, l := opt.PolicyValue(); v != int64(9) || !l {
		t.Fatalf("PolicyValue: %v %v", v, l)
	}
	if v := opt.EffectiveValue(); v != int64(9) {
		t.Fatalf("EffectiveValue: %v", v)
	}

	// A user value stored while locked is kept and applies once unlocked.
	vErrs, _ = ReplaceConfig(map[string]any{keyLocked: 5})
	if len(vErrs) > 0 {
		t.Fatal(vErrs[0])
	}
	if locked() != 9 {
		t.Fatalf("stored user value must be inert while locked: %d", locked())
	}
	SetPolicy(nil, nil)
	if locked() != 5 || def() != 1 || IsLocked(keyLocked) {
		t.Fatalf("after removing the policy: locked %d default %d", locked(), def())
	}
	if _, ok := opt.GetAnnotation(PolicyAnnotation); ok {
		t.Fatal("the policy annotation must be removed")
	}
}

func escapeKey(key string) string {
	out := make([]byte, 0, len(key))
	for i := range len(key) {
		switch key[i] {
		case '.', ':', '*', '?':
			out = append(out, '\\')
		}
		out = append(out, key[i])
	}
	return string(out)
}

func TestPolicyBeforeRegistration(t *testing.T) { //nolint:paralleltest // Uses global state.
	options = make(map[string]*Option)
	t.Cleanup(func() {
		SetPolicy(nil, nil)
		options = make(map[string]*Option)
	})

	// The policy is set before the options exist, as at boot.
	vErrs := SetPolicy(map[string]any{keyLater: 7, "test/bad": "x"}, []string{keyLater})
	if len(vErrs) > 0 {
		t.Fatalf("unregistered keys must not fail: %v", vErrs[0])
	}
	for _, o := range []*Option{
		{Name: "a", Key: keyLater, Description: "d", OptType: OptTypeInt, DefaultValue: 1},
		{Name: "b", Key: "test/bad", Description: "d", OptType: OptTypeInt, DefaultValue: 1},
	} {
		err := Register(o)
		if err != nil {
			t.Fatal(err)
		}
	}
	if GetAsInt(keyLater, 0)() != 7 || !IsLocked(keyLater) {
		t.Fatal("policy not applied at registration")
	}
	// An invalid policy value is left out.
	if GetAsInt("test/bad", 0)() != 1 || IsLocked("test/bad") {
		t.Fatal("an invalid policy value must be ignored")
	}

	// Invalid values of registered options are reported.
	vErrs = SetPolicy(map[string]any{keyLater: "x"}, nil)
	if len(vErrs) != 1 {
		t.Fatalf("want 1 validation error, got %d", len(vErrs))
	}
}

func TestPolicyConcurrent(t *testing.T) { //nolint:paralleltest // Uses global state.
	registerPolicyTestOptions(t)
	locked := GetAsInt(keyLocked, 0)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					v := locked()
					if v != 1 && v != 9 {
						t.Errorf("unexpected value %d", v)
						return
					}
				}
			}
		})
	}
	for i := range 200 {
		if i%2 == 0 {
			SetPolicy(map[string]any{keyLocked: 9}, []string{keyLocked})
		} else {
			SetPolicy(nil, nil)
		}
	}
	close(stop)
	wg.Wait()
}

func TestPolicyWithoutModule(t *testing.T) { //nolint:paralleltest // Uses global state.
	registerPolicyTestOptions(t)
	savedModule, savedDB := module, dbController
	module, dbController = nil, nil
	t.Cleanup(func() { module, dbController = savedModule, savedDB })

	// As early at boot: no module and no database yet.
	if vErrs := SetPolicy(map[string]any{keyLocked: 9}, []string{keyLocked}); len(vErrs) > 0 {
		t.Fatal(vErrs[0])
	}
	if GetAsInt(keyLocked, 0)() != 9 {
		t.Fatal("policy not applied")
	}
}
