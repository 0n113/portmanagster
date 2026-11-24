//go:build !windows

package tags

import (
	"testing"

	"github.com/safing/portmaster/service/process"
)

const (
	testAppImage     = "/home/u/Foo.AppImage"
	testAppImageName = "Foo.AppImage"
)

func TestValidateAppImageEnv(t *testing.T) {
	t.Parallel()

	const dir = "/tmp/.mount_fooAbC123"
	tests := []struct {
		name, path, appImage, appDir string
		want                         bool
	}{
		{"valid", dir + "/usr/bin/foo", testAppImage, dir, true},
		{"relative appimage", dir + "/usr/bin/foo", testAppImageName, dir, false},
		{"unclean appimage", dir + "/usr/bin/foo", "/home/u/../x/Foo.AppImage", dir, false},
		{"appdir not a mount dir", "/usr/bin/foo", testAppImage, "/usr", false},
		{"appdir with subpath", dir + "/usr/bin/foo", testAppImage, dir + "/usr", false},
		{"path outside appdir", "/usr/bin/foo", testAppImage, dir, false},
		{"bare string prefix", dir + "evil/bin/foo", testAppImage, dir, false},
		{"path equals appdir", dir, testAppImage, dir, false},
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
		{"full path", testAppImage, testAppImage, true},
		{"file name only", testAppImageName, testAppImage, true},
		{"different file", "Bar.AppImage", testAppImage, false},
		{"different full path", "/opt/Foo.AppImage", testAppImage, false},
		{"case differs", "foo.appimage", testAppImage, false},
		{"empty source", "", testAppImage, false},
		{"empty appimage", testAppImageName, "", false},
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
