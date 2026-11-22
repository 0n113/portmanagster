package core

import (
	"strings"
	"testing"
)

func TestEscapeMarkdown(t *testing.T) {
	t.Parallel()

	tests := []struct{ in, want string }{
		{"plain name", "plain name"},
		{"[Details](https://evil.example)", `\[Details\]\(https://evil.example\)`},
		{"<a href=x>", `\<a href=x\>`},
		{"a`b", "a\\`b"},
		{`back\slash`, `back\\slash`},
		{"line1\r\nline2\nline3", "line1  line2 line3"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := escapeMarkdown(tc.in); got != tc.want {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateAppName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
		ok       bool
	}{
		{"My App", "My App", true},
		{"  trimmed  ", "trimmed", true},
		{"app-1.2_3+x@host", "app-1.2_3+x@host", true},
		{"Äpfel Übung 日本", "Äpfel Übung 日本", true},
		{"", "", false},
		{"   ", "", false},
		{"[x](http://a)", "", false},
		{"http://evil.example", "", false},
		{"a\nb", "", false},
		{"a<b", "", false},
		{"a`b", "", false},
		{strings.Repeat("a", 64), strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), "", false},
		{strings.Repeat("日", 64), strings.Repeat("日", 64), true},
	}
	for _, tc := range tests {
		got, err := validateAppName(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("validateAppName(%q) = %q, %v; want %q ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}
