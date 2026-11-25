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
| Installers | Windows installer, `.deb`, `.rpm` (all unsigned) | signed Windows installer, Linux packages |
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
- Linux packages are not signed and come without a package repository.
- Depends on Safing for the signed Windows driver and for intel data.
- A small project with one maintainer and no support channel.
- Upstream changes arrive with a delay: they are merged weekly by pull request.

## Download

[Releases](https://github.com/0n113/portmasterpro/releases): Windows x64 installer, Linux `.deb`
and `.rpm` packages, core binaries for Linux and Windows, `SHA256SUMS.txt`. The installers replace
an existing Portmaster installation (same service name and install directory).

### Linux (Fedora, Debian, Ubuntu)

```bash
sudo dnf install ./portmasterpro_0.3.4.x86_64.rpm   # Fedora
sudo apt install ./portmasterpro_0.3.4_amd64.deb    # Debian, Ubuntu
sudo systemctl start portmaster                     # first install only
```

- The service `portmaster` replaces the system firewall: it conflicts with `firewalld`, which
  stops when Portmaster starts. Portmaster blocks incoming connections by default; allow them per
  app or in the global settings.
- On Fedora with SELinux, the package labels `portmaster-core` as `bin_t`.
- An upgrade starts the service again if it ran before.
- If the core crashes, its rules stay: new connections are dropped until the service is back,
  about 10 seconds. If it cannot start again, remove the rules with
  `sudo /usr/lib/portmaster/portmaster-core --recover-iptables`.
- Forwarded traffic (VMs, containers, hotspot clients) is filtered as the app "Forwarded
  Traffic": the global rules and filter lists apply, plus its own settings. Domains are known
  when the guests resolve names through this computer (libvirt and Podman networks); guests with
  their own DNS servers (e.g. Docker) are only matched by IP, country and ASN. Turn it off with
  Settings → Advanced → "Filter Forwarded Traffic". If the core is down, forwarded traffic is
  dropped like local traffic.
- At boot, `portmaster-boot-guard.service` blocks the network (except loopback, DHCP and ICMPv6)
  before it is configured, until the core has set its rules. If the core cannot start, the
  network stays blocked: remove the rules with
  `sudo /usr/lib/portmaster/portmaster-core --recover-iptables`, or turn the guard off with
  `sudo systemctl mask portmaster-boot-guard.service`.
- The core checks every 30 seconds that its rules are still first in their chains and moves them
  back if other software (Docker, VPN clients) put rules before them.
- Removing the package deletes the settings and the history in `/var/lib/portmaster`.
- Upgrade: install the new package the same way (`sudo dnf install ./portmasterpro_X.x86_64.rpm`).
  The settings stay. rpm sorts `0.2.0-rc1` above `0.2.0`; from rc1, upgrade straight to 0.3.4 or
  later.

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
