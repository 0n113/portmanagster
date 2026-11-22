package tags

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
	"github.com/safing/portmaster/service/profile/binmeta"
)

func init() {
	err := process.RegisterTagHandler(new(AppImageHandler))
	if err != nil {
		panic(err)
	}
}

const (
	appImageName          = "AppImage"
	appImagePathTagKey    = "app-image-path"
	appImageMountIDTagKey = "app-image-mount-id"
)

var (
	appImageMountDirRegex         = regexp.MustCompile(`^/tmp/.mount_[^/]+`)
	appImageMountNameExtractRegex = regexp.MustCompile(`^[A-Za-z0-9]+`)
)

// AppImageHandler handles AppImage processes on Unix systems.
type AppImageHandler struct{}

// Name returns the tag handler name.
func (h *AppImageHandler) Name() string {
	return appImageName
}

// TagDescriptions returns a list of all possible tags and their description
// of this handler.
func (h *AppImageHandler) TagDescriptions() []process.TagDescription {
	return []process.TagDescription{
		{
			ID:          appImagePathTagKey,
			Name:        "AppImage Path",
			Description: "Path to the app image file itself.",
		},
		{
			ID:          appImageMountIDTagKey,
			Name:        "AppImage Mount ID",
			Description: "Extracted ID from the AppImage mount name. Use AppImage Path instead, if available.",
		},
	}
}

// AddTags adds tags to the given process.
func (h *AppImageHandler) AddTags(p *process.Process) {
	// Detect app image path via ENV vars.
	// The env vars are set by the process itself and can be faked by any
	// program. They are therefore only accepted if APPDIR is a real AppImage
	// mount that contains the binary and whose mount source names the same
	// AppImage file as APPIMAGE. Note that a user who creates their own FUSE
	// mount can still fake this (same trust level as the mount ID tag below), so
	// this raises the bar from "set two environment variables", but is not proof
	// of identity.
	func() {
		appImageLocation := p.Env["APPIMAGE"]
		appImageMountDir := p.Env["APPDIR"]
		if appImageLocation == "" || appImageMountDir == "" {
			return
		}

		// Cheap, pure checks first.
		if !validateAppImageEnv(p.Path, appImageLocation, appImageMountDir) {
			return
		}

		// Confirm that APPDIR is a real AppImage mount and that its source is
		// the AppImage given in APPIMAGE.
		mountSource, err := getAppImageMountName(appImageMountDir)
		if err != nil {
			log.Debugf("process/tags: failed to get mount name: %s", err)
			return
		}
		if !appImageMountMatches(mountSource, appImageLocation) {
			return
		}

		// Add matching path for regular profile matching.
		p.MatchingPath = appImageLocation

		// Add app image tag.
		p.Tags = append(p.Tags, profile.Tag{
			Key:   appImagePathTagKey,
			Value: appImageLocation,
		})
	}()

	// Detect app image mount point.
	func() {
		// Check if binary path matches app image mount pattern.
		mountDir := appImageMountDirRegex.FindString(p.Path)
		if mountDir == "" {
			return
		}

		// Get mount name of mount dir.
		// Also, this confirm this is actually a mounted dir.
		mountName, err := getAppImageMountName(mountDir)
		if err != nil {
			log.Debugf("process/tags: failed to get mount name: %s", err)
			return
		}
		if mountName == "" {
			return
		}

		// Extract a usable ID from the mount name.
		mountName, _ = strings.CutPrefix(mountName, "gearlever_")
		mountName = appImageMountNameExtractRegex.FindString(mountName)
		if mountName == "" {
			return
		}

		// Add app image tag.
		p.Tags = append(p.Tags, profile.Tag{
			Key:   appImageMountIDTagKey,
			Value: mountName,
		})
	}()
}

// CreateProfile creates a profile based on the tags of the process.
// Returns nil to skip.
func (h *AppImageHandler) CreateProfile(p *process.Process) *profile.Profile {
	if tag, ok := p.GetTag(appImagePathTagKey); ok {
		return profile.New(&profile.Profile{
			Source:              profile.SourceLocal,
			Name:                binmeta.GenerateBinaryNameFromPath(p.Path),
			PresentationPath:    p.Path,
			UsePresentationPath: true,
			Fingerprints: []profile.Fingerprint{
				{
					Type:      profile.FingerprintTypeTagID,
					Key:       tag.Key,
					Operation: profile.FingerprintOperationEqualsID,
					Value:     tag.Value, // Value of appImagePathTagKey.
				},
			},
		})
	}

	if tag, ok := p.GetTag(appImageMountIDTagKey); ok {
		return profile.New(&profile.Profile{
			Source:              profile.SourceLocal,
			Name:                binmeta.GenerateBinaryNameFromPath(p.Path),
			PresentationPath:    p.Path,
			UsePresentationPath: true,
			Fingerprints: []profile.Fingerprint{
				{
					Type:      profile.FingerprintTypeTagID,
					Key:       tag.Key,
					Operation: profile.FingerprintOperationEqualsID,
					Value:     tag.Value, // Value of appImageMountIDTagKey.
				},
			},
		})
	}

	return nil
}

func getAppImageMountName(mountPoint string) (mountName string, err error) {
	// Get mounts.
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			switch {
			case fields[1] != mountPoint:
			case !strings.HasSuffix(strings.ToLower(fields[0]), ".appimage"):
			default:
				// Found AppImage mount!
				return fields[0], nil
			}
		}
	}
	if scanner.Err() != nil {
		return "", scanner.Err()
	}

	return "", nil
}

// validateAppImageEnv checks the purely syntactic requirements of the APPIMAGE
// and APPDIR values: APPIMAGE must be an absolute, clean path and the process
// binary must be inside APPDIR, which must itself be a mount dir of the form
// /tmp/.mount_*. The path boundary check prevents "/tmp/.mount_x" from
// matching "/tmp/.mount_xyz/bin".
func validateAppImageEnv(procPath, appImage, appDir string) bool {
	if !filepath.IsAbs(appImage) || filepath.Clean(appImage) != appImage {
		return false
	}
	if !filepath.IsAbs(appDir) || filepath.Clean(appDir) != appDir {
		return false
	}
	if appImageMountDirRegex.FindString(appDir) != appDir {
		return false
	}
	return strings.HasPrefix(procPath, appDir+"/")
}

// appImageMountMatches returns whether the mount source from /proc/mounts
// names the given AppImage file. Depending on the runtime, the source is the
// full path or only the file name; both are accepted, compared exactly.
func appImageMountMatches(mountSource, appImage string) bool {
	if mountSource == "" || appImage == "" {
		return false
	}
	return mountSource == appImage || mountSource == filepath.Base(appImage)
}
