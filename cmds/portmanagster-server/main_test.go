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

func TestReadProfileFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "p.yaml")
	err := os.WriteFile(yamlFile, []byte("type: profile\nname: restic\nsource: local\nconfig:\n  filter:\n    endpoints: [\"+ example.com\"]\n# jess-checksum: x\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readProfileFile(yamlFile)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"config":{"filter":{"endpoints":["+ example.com"]}},"name":"restic","source":"local","type":"profile"}`
	if string(got) != want {
		t.Fatalf("got %s", got)
	}

	jsonFile := filepath.Join(dir, "p.json")
	err = os.WriteFile(jsonFile, []byte(`{"type":"profile","name":"a","_jess-checksum":"x"}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got, err = readProfileFile(jsonFile)
	if err != nil || string(got) != `{"name":"a","type":"profile"}` {
		t.Fatalf("json: got %s, %v", got, err)
	}

	settings := filepath.Join(dir, "s.yaml")
	err = os.WriteFile(settings, []byte("type: settings\nconfig: {}\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readProfileFile(settings)
	if err == nil {
		t.Fatal("want an error for a settings export")
	}
}

func TestCellRemovesControlCharacters(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":                       "-",
		"pc-01":                  "pc-01",
		"Büro-PC":                "Büro-PC",
		"v2.1\x1b[2K\rpc-99\tok": "v2.1?[2K?pc-99?ok",
		"a\nb":                   "a?b",
		"evil\u202egnp.exe":      "evil?gnp.exe",
		"x\u2028y":               "x?y",
		"bad\xffutf8":            "bad?utf8",
	}
	for in, want := range tests {
		if got := cell(in); got != want {
			t.Errorf("cell(%q) = %q, want %q", in, got, want)
		}
	}
}
