package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadSettingsFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "s.yaml")
	err := os.WriteFile(yamlFile, []byte("# jess-checksum: x\ntype: settings\nconfig:\n  filter:\n    askTimeout: 33\n    lists: [TRAC, MAL]\n  dns:\n    nameservers: []\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readSettingsFile(yamlFile)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"filter/askTimeout": 33,
		"filter/lists":      []any{"TRAC", "MAL"},
		"dns/nameservers":   []any{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	jsonFile := filepath.Join(dir, "s.json")
	err = os.WriteFile(jsonFile, []byte(`{"type":"settings","config":{"filter":{"askTimeout":33}},"_jess-checksum":"x"}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got, err = readSettingsFile(jsonFile)
	if err != nil {
		t.Fatal(err)
	}
	if got["filter/askTimeout"] != 33 {
		t.Fatalf("json: got %#v", got)
	}

	noConfig := filepath.Join(dir, "n.yaml")
	err = os.WriteFile(noConfig, []byte("type: settings\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readSettingsFile(noConfig)
	if err == nil {
		t.Fatal("want an error for a file without config")
	}
}
