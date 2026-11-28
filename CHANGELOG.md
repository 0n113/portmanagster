# Changelog

All notable changes of portmasterpro relative to upstream
[safing/portmaster](https://github.com/safing/portmaster).
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow SemVer;
pre-releases carry a `-rcN` suffix.

## [Unreleased]

### Added
- Summaries of blocked connections for the management server (management phase C4), off by
  default and turned on per group (`group block-summary NAME on`, or in the UI): every report
  counts the blocked connections per app, reason, filter list and domain or IP (at most 200
  entries, no allowed connections, no user names). The server keeps them per hour for
  `serve --block-retention` (default 30 days) and shows them on the computer and group pages,
  on a new page "Blocks" with filters, and with `portmanagster-server blocks`. The Managed panel
  of the app tells the user when the summary is sent.
- Write actions in the admin web UI of the management server (management phase C3): create
  and delete groups, edit their settings (with locks), endpoint rules and app profiles, create
  and revoke enrollment tokens (the UI shows the enroll command once; `serve --client-url`
  sets the address in it), move and revoke computers; every change is in the audit log. New
  commands `group delete`, `token list`, `token revoke` and `computer move`. Settings, profile
  and rule files are checked by the same code in the command line and the UI; locked keys must
  be in the settings. Moving a computer marks its policy as pending until its next report.
- Read-only pages in the admin web UI of the management server (management phase C2):
  dashboard with the computers that need attention (silent, policy error, problems, refused
  settings) and the latest changes; computers with filters and a detail page with the last
  report; groups with settings, locks, rules, profiles and computers; enrollment tokens; audit
  log with search. `computer list` judges the policy state per group instead of by the global
  policy sequence.
- Admin web UI of the management server (management phase C1): `serve` runs it on
  `127.0.0.1:8444` (`--admin-listen`, `--admin-url`, `--admin-cert/--admin-key`). Accounts
  (`portmanagster-server admin add/list/reset/remove`, roles admin and viewer) log in with a
  passkey or TOTP after a one-time setup link, no passwords. Sessions with idle and maximum
  age, CSRF tokens, same-origin check, login rate limit, strict content security policy. An
  audit log records the changes through the UI and the command line
  (`portmanagster-server audit`). The UI has a dashboard; more pages follow.
- Policy layer in the settings (management phase B1): values of a management policy are
  either locked (highest precedence, changes refused with "managed by policy") or a default a
  local admin may override. `settings export --effective` exports the values in force.
- App profiles respect the policy layer (management phase B2): app profiles cannot override a
  locked setting (including outgoing and incoming rules and filter lists) and cannot set or
  change it; policy rules are evaluated before the rules of all app profiles and the global
  rules.
- Management client and server use the policy layer (management phase B3): the client sets the
  signed policy as policy layer instead of importing it as user settings, already when the core
  is created, so there is no unmanaged window at boot. Groups get endpoint rules
  (`portmanagster-server group rules`), evaluated before all other rules. The report lists
  overridden policy defaults and refused settings instead of drift. `manage leave` keeps the
  policy values and rules as user settings.
- VM smoke tests of the management policy (management phase B5), Linux and Windows: locked
  settings refused through settings import, config API and app profiles, a policy rule wins over
  an app profile allow rule, locked filter lists, override reports.
- The app shows the management policy (management phase B4): locked settings are read-only and
  marked "Managed by your organisation" in the global and the app settings, policy defaults are
  marked "Default set by your organisation" and reset to the policy value, and the global
  settings show a panel with the server, group, policy version, last update, changed defaults
  and settings not applied.
- Management server (phase A, `docs/management-server.md`): `portmanagster-server` with
  enrollment, groups, signed policies with settings and app profiles, and client reports;
  `portmaster-core manage enroll|status|pull|leave` applies the policy, corrects local changes and
  reports version, drift and health.
- `portmaster-core settings export|import` and `portmaster-core profile export|import`: export
  and import the global settings and app profiles of the running Portmaster from the command
  line, for Ansible, Salt and other remote administration tools. See
  [docs/central-management.md](docs/central-management.md).
- `portmaster-core status` shows the health of the running Portmaster as JSON (version, all
  modules running, interception active, filter list age, module warnings and errors).
  `status --check` prints one line and exits 0/1/2/3 (OK, warning, critical, unknown) for
  Nagios, Icinga, Zabbix and RMM tools. API endpoint `core/status`.
- Ansible role in `integrations/ansible/`: install the package, apply settings and profiles
  idempotently, check the health and back up the settings. It imports a profile for sshd that
  allows incoming SSH from the LAN, so the Portmaster does not lock Ansible out.
- Salt state in `integrations/salt/` and scripts for RMM and monitoring tools (Tactical RMM,
  MeshCentral, Zabbix, Icinga/Nagios, Wazuh) in `integrations/rmm/`, for Linux and Windows.
- `portmaster-core connections` exports the connection history as JSON lines (computer, app,
  destination, verdict, reason, filter lists). `--cursor FILE` exports each connection once
  across runs, for periodic export; `--blocked` exports only blocked connections.
- `integrations/siem/`: systemd timer and logrotate config for the export, Wazuh agent config
  and rules (blocks by malware lists, many blocks from one app, status check), and snippets for
  Fluent Bit, Loki, Filebeat and Graylog.
- `portmaster-core backup create DIR` saves the global settings and all local app profiles to
  a directory (`settings.yaml`, `profiles/*.yaml`, `manifest.json`); `backup restore DIR`
  validates all of it first and imports nothing if a file is invalid. `profile list` lists the
  profiles with their scoped IDs (API endpoint `sync/profile/list`).
  The Ansible role (`portmaster_backup`) and the RMM backup scripts now back up the app
  profiles too.
- `integrations/backup-agents/`: app profiles that let only the backup agent (restic, Borg,
  UrBackup; Linux and Windows) reach the backup server. Ansible role variable
  `portmaster_app_rules` writes and imports such rule profiles per host.

### Fixed
- With a locked filter list setting, the global config profile could not be saved ("managed by
  policy"), so the app settings showed outdated global values: special profiles written by the
  Portmaster are exempt from the check for locked settings.
- `portmaster-core profile import FILE` without flags failed with "failed to parse import
  request": the API read the export as an import request.
- Firewall: blocked ICMPv6 packets are dropped like ICMP; before, the iptables rules let them
  pass. Inbound LAN and localhost connections blocked by scope are dropped silently instead of
  rejected. The DNS tunnel heuristic scores the subdomain, not the start of the domain. DNS
  responses without address records (MX, TXT, CNAME) are no longer blocked when an extra
  record was filtered.
- Windows: verdict updates of IPv6 connections reach the kernel extension (address encoding).
- Linux: a failed nfqueue start is undone, so a later start tries again; conntrack entries of
  IPv4 connections held in 16 byte form are deleted; the DNS monitor does not panic on answers
  without a record.
- Network environment: all search domains and tab-separated nameservers of resolv.conf are
  read; Arch Linux's connectivity check domain is recognised; the IPv6 timezone location is
  kept; the device location ranking is consistent.
- Network: the active connection metric counts open connections; fast socket lookups stop
  after the fast limit; the network debug info prints a header for every process and profile.
- Importing global settings without "reset" replaced all settings: settings missing from the
  import were set back to their defaults. They now stay; "reset" replaces all settings.

## [0.3.4] - 2026-11-25

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
