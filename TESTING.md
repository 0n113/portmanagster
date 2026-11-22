# Testing portmasterpro

## Go tests

```bash
go test -short -count=1 ./...                 # as in CI
go test -race -short -count=1 ./...           # with the race detector
go vet ./...
golangci-lint run --new-from-rev=origin/development
```

`-short` skips tests that need a full desktop system, as upstream does. Some tests need
internet access, `iptables` or intel data and fail in a minimal environment.

## CI

Pull requests into `development` run these workflows (most only when files in their area
change):

| Workflow | Checks |
|---|---|
| `no-telemetry-ci.yml` | Go build, vet, tests, race tests of privacy-critical packages, Angular production build, Tauri clippy for Linux and Windows, and guards: no Safing account or telemetry endpoints, no SPN code, no subscription gating |
| `go.yml` | golangci-lint on new code, Go tests and build |
| `angular.yml` | Earthly build of the UI, ESLint on the changed files |
| `tauri.yml` | Earthly build and lint of the desktop app |
| `kext.yml`, `windows-dll.yml` | Windows kernel extension and core DLL |

## VM tests

[tools/vmtest](tools/vmtest/README.md) runs the core with packet interception in local VMs:
Linux (Fedora, nfqueue, eBPF) as root and Windows 11 with Safing's signed kernel driver.

```bash
tools/vmtest/test-linux.sh            # unit tests + smoke test
tools/vmtest/test-windows.sh all
tools/vmtest/test-linux.sh soak 60    # 60 minutes of constant traffic, checks for leaks
```

The smoke tests check DNS, HTTPS, blocking by settings and filter lists, the API, netquery,
bandwidth data, 40 parallel connections and a clean shutdown. The soak test samples memory,
goroutines, open files and data size every minute and fails if one keeps growing.

## UI against a real core

Run the core unprivileged with `--disable-interception` on port 18817 and serve the UI with a
proxy, see [BUILDING.md](BUILDING.md#ui-desktopangular). This covers all pages and settings,
but no live connections, because interception is off.

## Manual checks

- No requests to Safing except `updates.safing.io` (intel data): watch the connections of
  `portmaster-core` in the UI or with a packet capture.
- <http://icmpcheck.popcount.org/>: ICMP path MTU and fragmented packet delivery.
