# portmasterpro

A fork of the application firewall [Portmaster](https://github.com/safing/portmaster) by Safing,
**without SPN, Safing accounts, subscriptions or telemetry**. The features that upstream sells
as part of a paid plan and that run locally on your computer (Network History, Bandwidth
Visibility) are available to everyone.

> Not affiliated with or endorsed by Safing. "Safing" and "Portmaster" are trademarks of Safing
> ICS Technologies GmbH, see [TRADEMARKS](TRADEMARKS). The code is licensed under the
> [GPLv3](LICENSE), like upstream.

## What it does

Portmaster watches every network connection of every app on your computer and lets you decide
what is allowed:

- **Monitor:** see all connections per app, live and in the network history.
- **Block:** block apps, domains, IPs, countries, LAN or internet access, per app or globally.
- **Filter lists:** block ads, trackers and malware domains for the whole system.
- **Secure DNS:** resolve names over DNS-over-TLS/HTTPS with the resolvers you choose.
- **Bandwidth:** see how much data each connection and app sends and receives.

## Compared to the original Portmaster

| | portmasterpro | Portmaster (Safing) |
|---|---|---|
| Firewall, monitoring, filter lists, secure DNS | yes | yes |
| Network History, Bandwidth Visibility | free, local | paid plan (Plus or higher) |
| SPN (Safing Privacy Network, a multi-hop VPN) | removed | paid plan (Pro) |
| Safing account and login | removed | optional, needed for paid features |
| Requests to Safing besides intel data updates | none | account, subscription and support services |
| Intel data (filter lists, GeoIP) | from Safing's update server | from Safing's update server |
| Automatic app updates | off: Safing's binaries would replace this build | on |
| Installers | Windows (unsigned); Linux core binary | signed Windows installer, Linux packages |
| Kernel driver (Windows) | Safing's signed stable driver, unchanged | Safing's signed driver |
| Split Tunnel | off: needs a newer signed driver | as released by Safing |
| Support | none: no issue tracker, one maintainer | documentation, Discord, support for subscribers |

### Pros

- All local features without account or subscription.
- No SPN code and no account code: less code that runs with administrator rights, and nothing
  that connects to Safing except the intel data updates.
- Fixes that upstream does not have yet: stability on Windows shutdown, update downloads that
  stall or fail, DNS cache handling, filter lists at first start, several UI security fixes.
  See [CHANGELOG.md](CHANGELOG.md).
- Current UI stack (Angular 20) without known security advisories in production dependencies.
- Tested in VMs on Linux and Windows, including hour-long soak tests for leaks
  ([tools/vmtest](tools/vmtest/README.md)).

### Cons

- No SPN. If you want Safing's multi-hop VPN, use the original.
- Unsigned installer: Windows SmartScreen warns on first start.
- No automatic updates of the app; install new releases yourself.
- No Linux packages in the releases; build them from source (`earthly +installer-linux`).
- Depends on Safing for the signed Windows driver and for intel data.
- Pre-release quality: a small project with one maintainer and no support channel.
- Upstream changes arrive with a delay: they are merged weekly by pull request.

## Download

[Releases](https://github.com/0n113/portmasterpro/releases): Windows x64 installer, core binaries
for Linux and Windows, `SHA256SUMS.txt`. The Windows installer replaces an existing Portmaster
installation (same service name and install directory).

## Build and test

- [BUILDING.md](BUILDING.md): build the core, the UI and the Windows installer.
- [TESTING.md](TESTING.md): unit tests, CI, VM tests and manual checks.
- [RELEASE.md](RELEASE.md): release checklist.

## Repository

- `development` is the main branch. A weekly workflow opens a pull request when upstream
  `safing/portmaster:development` has new commits.
- `release-candidate/*` branches are frozen release candidates.
- Changes go in by pull request; CI must be green before merging.

| Path | Content |
|---|---|
| `service/`, `base/`, `cmds/` | Go core (`portmaster-core`) and tools |
| `desktop/angular/` | UI (Angular), see [desktop/CHANGES.md](desktop/CHANGES.md) |
| `desktop/tauri/` | Desktop app and tray (Tauri, Rust) |
| `windows_kext/`, `windows_core_dll/` | Windows kernel extension sources and core DLL |
| `packaging/` | Linux packages, Windows installer |
| `tools/vmtest/` | Test VMs for Linux and Windows |
