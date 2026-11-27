package policy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/safing/jess"
)

func publicKey(t *testing.T, key *jess.Signet) *jess.Signet {
	t.Helper()
	text, err := key.Export(false)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jess.RecipientFromTextFormat(text)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestSignVerify(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKey("other")
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{
		Version:  7,
		Issued:   time.Unix(1700000000, 0).UTC(),
		Computer: "c1",
		Settings: map[string]any{"filter/askTimeout": 33},
		Locked:   []string{"filter/askTimeout"},
	}
	signed, err := Sign(p, key)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(signed, publicKey(t, key), "c1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Version != 7 || got.Settings["filter/askTimeout"] != float64(33) || got.Type != TypePolicy {
		t.Fatalf("unexpected policy: %+v", got)
	}

	// Another key, another computer, a modified policy and no signature fail.
	_, err = Verify(signed, publicKey(t, other), "c1")
	if err == nil {
		t.Error("policy signed by another key must fail")
	}
	_, err = Verify(signed, publicKey(t, key), "c2")
	if !errors.Is(err, ErrWrongComputer) {
		t.Errorf("want ErrWrongComputer, got %v", err)
	}
	tampered := bytes.Replace(signed, []byte("33"), []byte("34"), 1)
	if bytes.Equal(tampered, signed) {
		t.Fatal("test did not modify the policy")
	}
	_, err = Verify(tampered, publicKey(t, key), "c1")
	if err == nil {
		t.Error("modified policy must fail")
	}
	_, err = Verify([]byte(`{"type":"policy","version":1,"computer":"c1"}`), publicKey(t, key), "c1")
	if err == nil {
		t.Error("unsigned policy must fail")
	}
}

func TestCheckVersion(t *testing.T) {
	t.Parallel()

	p := &Policy{Version: 5}
	err := CheckVersion(p, 5)
	if err != nil {
		t.Errorf("same version: %v", err)
	}
	err = CheckVersion(p, 4)
	if err != nil {
		t.Errorf("newer version: %v", err)
	}
	err = CheckVersion(p, 6)
	if !errors.Is(err, ErrRollback) {
		t.Errorf("want ErrRollback, got %v", err)
	}
}

func TestKeyFingerprint(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	fp1, err := KeyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := KeyFingerprint(publicKey(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 || !strings.HasPrefix(fp1, "sha256:") || len(fp1) != len("sha256:")+64 {
		t.Fatalf("fingerprints differ or malformed: %s %s", fp1, fp2)
	}
}
