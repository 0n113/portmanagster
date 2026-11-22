package tags

import (
	"testing"

	"github.com/safing/portmaster/service/process"
)

func TestValidateAppImageEnv(t *testing.T) {
	t.Parallel()

	const dir = "/tmp/.mount_fooAbC123"
	tests := []struct {
		name, path, appImage, appDir string
		want                         bool
	}{
		{"valid", dir + "/usr/bin/foo", "/home/u/Foo.AppImage", dir, true},
		{"relative appimage", dir + "/usr/bin/foo", "Foo.AppImage", dir, false},
		{"unclean appimage", dir + "/usr/bin/foo", "/home/u/../x/Foo.AppImage", dir, false},
		{"appdir not a mount dir", "/usr/bin/foo", "/home/u/Foo.AppImage", "/usr", false},
		{"appdir with subpath", dir + "/usr/bin/foo", "/home/u/Foo.AppImage", dir + "/usr", false},
		{"path outside appdir", "/usr/bin/foo", "/home/u/Foo.AppImage", dir, false},
		{"bare string prefix", dir + "evil/bin/foo", "/home/u/Foo.AppImage", dir, false},
		{"path equals appdir", dir, "/home/u/Foo.AppImage", dir, false},
		{"empty values", "", "", "", false},
	}
	for _, tc := range tests {
		if got := validateAppImageEnv(tc.path, tc.appImage, tc.appDir); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAppImageMountMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, source, appImage string
		want                   bool
	}{
		{"full path", "/home/u/Foo.AppImage", "/home/u/Foo.AppImage", true},
		{"file name only", "Foo.AppImage", "/home/u/Foo.AppImage", true},
		{"different file", "Bar.AppImage", "/home/u/Foo.AppImage", false},
		{"different full path", "/opt/Foo.AppImage", "/home/u/Foo.AppImage", false},
		{"case differs", "foo.appimage", "/home/u/Foo.AppImage", false},
		{"empty source", "", "/home/u/Foo.AppImage", false},
		{"empty appimage", "Foo.AppImage", "", false},
	}
	for _, tc := range tests {
		if got := appImageMountMatches(tc.source, tc.appImage); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAppImageAddTagsIgnoresFakedEnv(t *testing.T) {
	t.Parallel()

	p := &process.Process{
		Path: "/tmp/.mount_fakeXYZ/bin/evil",
		Env: map[string]string{
			"APPIMAGE": "/home/u/Victim.AppImage",
			"APPDIR":   "/tmp/.mount_fakeXYZ",
		},
	}
	new(AppImageHandler).AddTags(p)
	if p.MatchingPath != "" {
		t.Errorf("matching path must not be set from faked env, got %q", p.MatchingPath)
	}
	if _, ok := p.GetTag(appImagePathTagKey); ok {
		t.Error("app image path tag must not be set from faked env")
	}
}
