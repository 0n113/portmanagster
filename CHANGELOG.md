# Changelog

All notable changes of portmasterpro relative to upstream
[safing/portmaster](https://github.com/safing/portmaster).
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow SemVer;
pre-releases carry a `-rcN` suffix.

## [Unreleased]

### Security
- Linux: `portmaster-boot-guard.service` blocks the network from early boot until the core has
  set its rules. Before, NetworkManager could bring the network up a few seconds earlier and
  apps connected unfiltered. `recover-iptables` also removes the guard.
- Linux: the core checks every 30 seconds, not only during the first 45 seconds, that its rules
  are first in their chains, and moves them back if other software put rules before them.

## [0.3.3] - 2026-11-25

### Added
- Linux: forwarded traffic of VMs, containers and hotspot clients is filtered. It shows up as
  the app "Forwarded Traffic", with the global rules and filter lists and its own settings;
  "Filter Forwarded Traffic" in the advanced settings turns it off. Blocks also hold when other
  software (e.g. Docker) accepts forwarded packets before the Portmaster rules. Domains are known
  when guests resolve names through the host; P2P blocking and DNS bypass prevention are off for
  forwarded traffic.

## [0.3.2] - 2026-11-24

There is no 0.3.1: the fork carries upstream's old tag `v0.3.1`.

### Security
- Linux: the service reports ready to systemd (`Type=notify`) only after its firewall rules are in
  place, so services ordered after `network.target`, like sshd, no longer start unfiltered at
  boot.
- CI: all GitHub Actions are pinned by commit SHA, the downloaded tauri-cli is checked against
  its sha256.
- The shared `exec` directory of the app has the sticky bit.

### Fixed
- On the first start, the filter lists are applied as soon as they are downloaded. Before, they
  only took effect up to 15 s later, and connections in between were not checked against them.
- The AppImage unit test no longer runs on Windows.
- The tamper check tests no longer depend on the processes of the test machine.

## [0.3.0] - 2026-11-24

### Security
- Linux: after a crash of the core, the firewall rules stay in place, so new connections are
  dropped until the service is back instead of passing unfiltered. Only a clean stop removes
  them.
- The API refuses requests for foreign host names (DNS rebinding from a web page).
- Linux: the app binary does not get API trust when it runs under a debugger or was started
  with `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH`.
- A permanently allowed connection that a settings change blocks no longer stays allowed when a
  packet arrives while the verdict is updated.
- Debug endpoints (`debug/*`, `debug/core`) and the DNS resolver list need user permission;
  CPU profiles are limited to 5 minutes.
- Linux service: more systemd hardening, no write access to `/usr/lib/portmaster`; icons are only
  read from regular files; the app calls `/usr/bin/systemctl` through pkexec.
- Release workflow: build jobs only get read access.

### Added
- Settings → Appearance: themes (macOS Dark, Graphite, Midnight, Classic), accent color (macOS
  colors or a custom one), corners, font, text size and reduced motion, with a live preview.

### Changed
- UI: the macOS dark appearance is complete: no hard-coded grays left, dark help texts, macOS
  toggles and focus rings.

### Fixed
- Linux packages: an upgrade no longer logs "fork/exec /usr/bin/iptables: permission denied": the
  SELinux label is set before the old service stops.

## [0.2.0] - 2026-11-24

First stable release, the same code as 0.2.0-rc1 plus the changes below.

### Changed
- UI in the macOS dark appearance: system grays, accent blue, macOS status colors, the system
  font (Adwaita Sans, SF Pro) and rounder corners.
- README: install notes for the Linux packages.

### Fixed
- Linux packages: an upgrade starts the service again if it ran before, instead of leaving the
  system unprotected until the next reboot.
- Desktop app dependencies with advisories updated: `cookie` 0.18.3, `url` 2.5.9.

### Upgrade notes
- Fedora: rpm sorts `0.2.0-rc1` above `0.2.0`. Upgrade from rc1 with
  `sudo dnf downgrade ./portmasterpro_0.2.0.x86_64.rpm`; it keeps the settings. Plain `rpm -U`
  refuses the unsigned package on Fedora 45.
- The service conflicts with `firewalld`; removing the package deletes `/var/lib/portmaster`.

## [0.2.0-rc1] - 2026-11-22

### Removed
- All SPN code (`spn/`, about 37,000 lines) and the SPN server tools `cmds/hub` and
  `cmds/observation-hub`; the core is built without SPN.
- The SPN and account UI: SPN page, login, pricing, account details, SPN quick settings,
  "Pause SPN", the SPN column and filters in the connection list.
- Upstream issue workflows, Travis CI and funding configuration that do not apply to the fork.

### Changed
- Upstream merged up to 2.2.9 and later `development` commits.
- UI upgraded from Angular 16 to 20.3, Node 22; build tooling and dependencies updated for
  security advisories.
- Built with Go 1.27.
- Documentation rewritten in English, with a comparison to the original Portmaster.
- The upstream sync workflow opens its pull requests against `development`.

### Fixed
- Windows: hangs when closing archives and the log writer at shutdown; DNS Client cache is
  flushed when interception starts; the core DLL is built with the static C runtime; a binary
  without an icon is no longer an error.
- Updates: stalled downloads are aborted and failed downloads retried; no upgrades into a
  read-only installation; an installed upgrade is reported as success.
- DNS: systemd-resolved cache flushed on start, CNAME chains kept, the network check retries
  once before going offline, UDP queries are retransmitted.
- Firewall: the verdict of an ended connection is no longer applied to a new socket;
  connections to `0.0.0.0` and `::` are no longer named.
- Profiles: app filter lists apply once the list index is available; missing intel data at first
  start is not reported as a settings failure or warned about on every connection.
- Linux: eBPF programs load on kernels with an extended BTF header; a missing IVPN client is not
  logged as an error; the desktop app reports a missing or failed system service correctly and
  no longer needs libssl.
- Security: links in untrusted text no longer load foreign pages into the app window, the app
  commands are checked by Tauri's ACL and its HTTP command only reaches the core API; the API
  trusts a socket only if all processes holding it are trusted (Linux); the AppImage path is no
  longer taken from the environment unchecked.
- Security: the UI connects only to the local API; only the app's own webview inherits API trust;
  HTML injection through app names and the app authorization prompt fixed; dependencies with
  known advisories updated (Go, npm, Cargo).
- Linux packages: `portmaster-core` gets the SELinux label `bin_t` also without `semanage`; on a
  fresh Fedora the service failed to start ("fork/exec /usr/bin/iptables: permission denied").
- Call limiters keep working when the clock is set back; reversed port ranges, log file
  permissions, config flatten order, the `.free` TLD.

### Performance
- SQLite writes without a `RETURNING` clause, one idle timer per batch, faster filter list
  decoding.

### Added
- VM test suite for Linux and Windows (`tools/vmtest`), also on Proxmox VE: smoke tests with
  packet interception, filter list and blocking checks, eBPF bandwidth data, and soak tests for
  leaks under constant traffic.
- Linux `.deb` and `.rpm` packages in the releases, built on Debian 12 (glibc 2.36).
- Release workflow creates the GitHub release on `v*` tag push; weekly upstream sync workflow.

## [0.1.0-rc1] - 2026-10-01

First public release candidate.

### Removed
- SPN (Safing Privacy Network), Safing account/login, subscription and feature gating.
- Telemetry / cloud sync (`service/sync` is a no-op).
- SPN navigation, `/spn` route, login/subscribe header, upsell widgets and "Portmaster Plus/Pro"
  copy in the Angular UI; SPN entries in the tray menu.

### Changed
- Network History and Bandwidth Visibility are available locally for everyone; history follows the
  per-app setting.
- Upstream **software** update checks are opt-in (`core/automaticUpdates=false`): upstream
  binaries would replace this build. Intelligence data updates (filter lists, GeoIP) stay enabled.
- `spn/access` reduced to an offline compatibility shim so remaining SPN packages compile but are
  never started.

### Added
- `no-telemetry-ci.yml`: full Go build/vet/test, race checks, Angular production build and guards
  against account/telemetry endpoints in Go sources and the built UI bundle.
- Linux cross-build of the Windows NSIS installer (`packaging/windows/render_nsis_linux.py`) and the
  `release-windows-installer.yml` workflow.
- `BUILDING.md` with the full build, test and installer flow.

### Security
- No connection to `account.safing.io`; the only remaining upstream endpoint is
  `updates.safing.io` for intelligence data (and, if enabled, binary update checks).
- Installer and binaries are unsigned; the kernel driver is Safing's signed stable driver (2.2.3).
