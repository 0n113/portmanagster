# Building portmasterpro

How to build the core, the UI and the Windows installer from source. For tests, see
[TESTING.md](TESTING.md).

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Go | see `go.mod` (`go` and `toolchain` lines; Go downloads the toolchain if needed) | core |
| Node.js | 22 | UI |
| Rust | stable | desktop app (Tauri) |
| Earthly | 0.8 | optional: the full release build, Linux packages |

All builds below work on Linux. Windows binaries are cross-compiled.

## Core (`portmaster-core`)

```bash
go build ./...                                   # check that everything compiles
CGO_ENABLED=0 go build -trimpath -o dist/portmaster-core ./cmds/portmaster-core
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o dist/portmaster-core.exe ./cmds/portmaster-core
```

Release builds also set the version with
`-ldflags "-X github.com/safing/portmaster/base/info.version=X.Y.Z"`, see
`.github/workflows/release-windows-installer.yml`.

Run it unprivileged for UI work (no packet interception, API on a free port):

```bash
dist/portmaster-core --bin-dir /tmp/pm/bin --data-dir /tmp/pm/data --devmode \
  --disable-interception --api-address 127.0.0.1:18817 --log-stdout
```

## UI (`desktop/angular`)

```bash
cd desktop/angular
npm ci
npm run build          # libraries + app, output in dist/
npm run build-tauri    # the UI built into the desktop app
npm run lint
```

The bundle-size budget warning is known. Details of what the fork changed in the UI:
[desktop/CHANGES.md](desktop/CHANGES.md).

To develop against a running core, start the core as above and serve the UI with a proxy file
`{"/api": {"target": "http://127.0.0.1:18817/", "ws": true}}`:

```bash
npx ng serve --configuration production --port 4200 --proxy-config proxy-local.json
```

## Desktop app (`desktop/tauri`)

```bash
cd desktop/tauri/src-tauri
cargo build --release
```

## Windows installer (cross-built on Linux)

The release workflow `release-windows-installer.yml` builds the NSIS installer on Linux. The
Tauri CLI refuses `--bundles nsis` on non-Windows hosts, so
`packaging/windows/render_nsis_linux.py` renders Tauri's NSIS template (including the hooks for
the service, the driver and intel data) and runs `makensis`. To do it by hand:

```bash
# Toolchain
sudo apt install nsis mingw-w64 lld llvm zip
rustup target add x86_64-pc-windows-gnu
# tauri-cli 2.2.7 (prebuilt): https://github.com/tauri-apps/tauri/releases/tag/tauri-cli-v2.2.7

# 1. UI and asset bundles
(cd desktop/angular && npm ci && npm run build \
  && NODE_ENV=production npx ng build --configuration production tauri-builtin)
mkdir -p dist/binary/all dist/binary/windows_amd64
(cd desktop/angular/dist && zip -qr ../../../dist/binary/all/portmaster.zip ./ -x "tauri-builtin/*")
(cd assets/data && zip -qr -9 -X ../../dist/binary/all/assets.zip *)

# 2. Core and update tool
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-X github.com/safing/portmaster/base/info.version=X.Y.Z" \
  -o dist/binary/windows_amd64/portmaster-core.exe ./cmds/portmaster-core
CGO_ENABLED=0 go build -trimpath -o /tmp/updatemgr ./cmds/updatemgr

# 3. Safing's signed kernel driver and intel data
/tmp/updatemgr download https://updates.safing.io/stable.v3.json --platform windows_amd64 dist/downloaded/windows_amd64
/tmp/updatemgr download https://updates.safing.io/intel.v3.json dist/intel

# 4. Core DLL with the static C runtime: the artifact "portmaster-core-dll" of the
#    "Windows Portmaster Core DLL" workflow (windows-dll.yml). Safing's DLL needs the
#    VC++ runtime, which a clean Windows does not have.
cp path/to/portmaster-core.dll dist/downloaded/windows_amd64/

# 5. Desktop app
(cd desktop/tauri/src-tauri && cargo tauri build --ci --target x86_64-pc-windows-gnu --no-bundle)

# 6. Installer
T=desktop/tauri/src-tauri
mkdir -p "$T/binary" "$T/intel"
cp dist/downloaded/windows_amd64/{portmaster-kext.sys,portmaster-core.dll} \
   dist/binary/windows_amd64/portmaster-core.exe dist/binary/all/*.zip \
   "$T/target/x86_64-pc-windows-gnu/release/WebView2Loader.dll" "$T/binary/"
cp dist/intel/* "$T/intel/"
python3 packaging/windows/render_nsis_linux.py X.Y.Z
# -> dist/windows_amd64/portmasterpro_X.Y.Z_x64-setup.exe
```

Notes:

- The kernel driver `portmaster-kext.sys` is Safing's signed stable driver, unchanged. Split
  Tunnel needs a newer driver and stays off (`splittun/enable=false`).
- The installer and binaries are not signed, so SmartScreen warns on first start.
- The installer uses the same service name (`PortmasterCore`) and install directory as
  Portmaster and replaces an existing installation.

## Full build with Earthly

The Earthfile from upstream still builds everything in containers, for example
`earthly +release-prep` (all binaries into `dist/`) or `earthly +installer-linux`
(`.deb` and `.rpm`). The CI job "Build" runs `earthly +angular-ci`.
