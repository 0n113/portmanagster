package main

import "testing"

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
