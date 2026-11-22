# Release checklist

## 1. Freeze

- [ ] Upstream merged: the latest "sync upstream development" pull request is merged or closed.
- [ ] `development` is green in all workflows.
- [ ] VM tests pass on the release commit: `tools/vmtest/test-linux.sh`,
      `tools/vmtest/test-windows.sh all`, and a soak test of at least 60 minutes on both.
- [ ] `CHANGELOG.md`: move `[Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] Version set in `desktop/tauri/src-tauri/Cargo.toml` and `Cargo.lock` (package `portmaster`).

## 2. Release candidate

- [ ] Create the branch `release-candidate/X.Y.Z` and push the tag `vX.Y.Z-rcN` on it. The
      workflows create a pre-release with all assets (tags containing `-` become pre-releases).
- [ ] Test the Windows installer on a real Windows machine:
  - install over an existing Portmaster or portmasterpro installation; settings are kept
  - the service `PortmasterCore` starts, the driver loads, the UI connects
  - network history survives a restart, the bandwidth charts fill
  - no connection to Safing except `updates.safing.io`
  - uninstalling removes the service, the driver and the autostart entry
- [ ] Install a Linux package on Fedora and Debian/Ubuntu: service starts, UI connects, the
      network works after `systemctl stop portmaster`.
- [ ] Run it for at least 7 days without a blocking bug.

## 3. Release

- [ ] Only fixes since the release candidate; otherwise make another `-rcN`.
- [ ] Push the tag `vX.Y.Z`. The workflows create the release.
- [ ] Check the release page: all assets are there and `SHA256SUMS.txt` matches.

## Notes

- GitHub runs scheduled and manually triggered workflows only from the default branch,
  `development`.
- Split Tunnel needs a newer signed kernel driver than Safing's stable release. Enable it only
  when Safing publishes one.
- Without a code signing certificate, SmartScreen warns on Windows. With a certificate, sign
  with `packaging/windows/sign_binaries_in_dist.ps1`; the driver stays Safing's signed driver.
