# Design: management server and agent (roadmap step 4)

Status: phase A done: the server side of enrollment and policies (A1, see
[Server commands](#server-commands)) and the client module in portmaster-core (A2, see
[Client commands](#client-commands)), profiles per group and reports (A3), and the VM tests
on Linux and Windows (A4, step "Management" of the smoke tests). Phase B done (policy layer,
see [Phase B plan](#phase-b-plan)). Phase C planned, see [Phase C plan](#phase-c-plan).
This document fixes the architecture and the order of work; details of each phase are settled
in its PR.

## Why

Steps 0-3 manage the Portmaster by push through existing tools (Ansible, Salt, RMM). That leaves
four gaps:

1. **No central view**: which computers run which version, are they healthy, what do they block.
2. **No enforcement**: a local admin can change every setting again; the next push may or may
   not come.
3. **Offline computers**: a laptop that is away during the push stays on the old config.
4. **No fleet-wide events**: the connection export goes to a SIEM only if one exists.

The management server closes these gaps. It does not replace the integrations: small setups
keep using Ansible; the server is for setups that need the four points above.

## Goals and non-goals

Goals:
- Self-hosted, one binary, no cloud, no telemetry, no account at a vendor.
- Clients pull; no open port on any client.
- A compromised network or a stolen server TLS key must not be enough to change a client's
  firewall: clients apply only policies signed with the policy key they pinned at enrollment.
- Works with the Linux and Windows Portmaster of this fork, same code.
- Usable from the first phase: central view and enforcement before a web UI exists.

Non-goals (for now):
- Multi-tenant hosting, high availability, a cloud service.
- Remote shell or software distribution: RMM tools do that.
- Collecting full connection history centrally by default (privacy; opt-in per group).

## Architecture

```
            admins (CLI on the server host, later web UI)
                         |
              +----------v-----------+        policy signing key
              |  portmanagster-server |<----- (on the server, or offline in phase D)
              |  SQLite, CA, API      |
              +----------^-----------+
                         | HTTPS, mutual TLS, client pulls every few minutes
          +--------------+---------------+
          |              |               |
   portmaster-core  portmaster-core  portmaster-core
   + managed module + managed module + managed module
```

### Server: `cmds/portmanagster-server`

- Go, in this repository, one static binary; packaged later as rpm/deb and a container.
- Storage: SQLite (`zombiezen.com/go/sqlite`, already used by netquery), one file, backup with
  existing tools (step 3).
- Internal CA for client certificates, created at `init`. The server's own TLS certificate is
  separate (internal CA or ACME/own PKI); clients pin it at enrollment.
- Admin interface in phase A: a CLI on the server host that talks to the server over a Unix
  socket (root only). No admin port on the network until the web UI phase, which adds admin
  accounts with passkeys/TOTP (see [Phase C plan](#phase-c-plan)).

### Client: module `service/managed` in portmaster-core

- No separate agent process: the core already runs as root/SYSTEM, has the settings, profiles,
  status and netquery in-process. Off unless enrolled.
- State in the data dir: client key and certificate, pinned server certificate and policy key,
  last applied policy (signed, as received), so the policy applies at boot without network.
- Pull loop: every 5 minutes (server-tunable, with jitter) and a long-poll so a policy change
  arrives in seconds while online. Backoff on errors; the last good policy stays in force.
- Reports with each pull: version, `core/status` (the same data as `status`), applied policy
  version, overridden policy defaults and refused settings. Optional per group: summary of
  blocked connections (counts per app/list/domain), or the connection export lines.

### Enrollment

1. Admin creates a one-time token for a group:
   `portmanagster-server token create --group office --expires 24h`.
   The output contains the server URL, the token and the fingerprints of the server TLS
   certificate and of the policy key.
2. On the client (as root, e.g. through Ansible or the RMM tool once):
   `portmaster-core manage enroll --server https://pm.example.lan:8443 --token ... --server-fp sha256:... --policy-key-fp sha256:...`
3. The client creates its key pair locally (the private key never leaves it), sends a CSR with
   the token; the server checks the token (single use, not expired), issues a client
   certificate (1 year, renewed automatically at half life) and records the computer.
4. From then on every request uses mutual TLS. Revoking a computer = server rejects its
   certificate (checked against the database, no CRL distribution needed).

`portmaster-core manage status` shows the state; `manage leave` unenrolls (local root can
always do this, as root can always uninstall; the server sees the computer go silent).

### Policy

A policy is a JSON document per computer, built by the server from the computer's groups:

```json
{
  "type": "policy",
  "version": 42,
  "issued": "2026-12-01T10:00:00Z",
  "computer": "<computer ID, the CN of its client certificate>",
  "settings": { "filter/lists": ["TRAC", "MAL", "BAD"], "filter/blockInbound": true },
  "locked": ["filter/lists", "filter/blockInbound"],
  "rules": { "endpoints": ["- MAL"], "serviceEndpoints": [] },
  "profiles": [ { "type": "profile", "source": "local", "name": "restic", "...": "..." } ]
}
```

- Signed with the policy key using jess `filesig` JSON signatures (Ed25519), the same mechanism
  as the update indexes, so no new crypto code.
- The client checks: signature against the pinned key, `computer` is itself, `version` higher
  than the applied one (no rollback/replay). Then it applies and stores it.
- `settings` and `profiles` use the formats of the existing settings and profile exports, so the
  import code (`service/sync`) does the validation and the application.
- `rules` are policy-level endpoint rules evaluated before all profile and global rules (e.g.
  organisation-wide blocks); see phase B.
- Groups: a computer is in one or more groups; policies of later groups override earlier ones
  per key. Settings not in the policy stay local.

### Enforcement: the policy layer (phase B)

Phase A enforced by **drift correction**: the client set the policy settings again when they
differed and reported the drift. A local admin could still change a setting until the next
pull, and an app profile could override a global setting. Since phase B (B3) the client sets a
**policy layer** that the config system and the profiles respect: locked settings cannot be
changed at all, unlocked ones are defaults a local admin may override (reported, not
reverted). See [Phase B plan](#phase-b-plan) for the details.

## Server commands

```bash
# Once: CA, server certificate for the given names/IPs, policy signing key, database.
portmanagster-server --dir /var/lib/portmanagster init --host pm.example.lan --host 192.168.1.10
portmanagster-server fingerprints

# Groups and their settings (a settings export from `portmaster-core settings export`).
portmanagster-server group create office
portmanagster-server group set office office-settings.yaml --lock filter/lists
portmanagster-server group list

# App profiles of a group (profile exports from `portmaster-core profile export`), e.g. the
# backup agent rules from integrations/backup-agents; replaces the previous ones.
portmanagster-server group profiles office restic.yaml sshd.yaml
portmanagster-server group profiles office --clear

# Endpoint rules of a group, evaluated before all app profile and global rules. The file is
# YAML or JSON: {endpoints: ["- *.ads.example"], serviceEndpoints: ["- *"]}; every rule
# starts with "+ " or "- ".
portmanagster-server group rules office office-rules.yaml
portmanagster-server group rules office --clear

# One-time enrollment token; prints the enroll command for the client.
portmanagster-server token create --group office --valid 24h --url https://pm.example.lan:8443

# Client API on :8443 (mutual TLS); computers and revocation.
portmanagster-server serve --listen :8443
portmanagster-server computer list          # with policy version and health of the last report
portmanagster-server computer show <id>     # last report as JSON
portmanagster-server computer revoke <id>
```

The data directory is root-only (0700): `ca.key`, `server.key` and `policy.key` are the
secrets; `portmanagster.db` holds groups, token hashes and computers. Back it up with the
tools from step 3. The admin commands open the database directly, so they run on the server
host only and the server has no admin port. Policy versions come from one sequence that
increases with every change of a group or an enrollment.

After every pull the client sends a report (`POST /v1/report`): the applied policy version,
the core version, the policy defaults a local admin overrode (`overridden`), the policy
settings that are not in force (`refused`: invalid value or unknown to this core version, or
invalid rules), the last error and the `core/status` data. The server keeps the last report
per computer. `computer list` shows the applied version (`current` when it is the newest) and a
health summary (`ok`, or e.g. `no interception, 2 problems, 1 overridden`); overrides, refused
settings and client errors are also logged by `serve`.

## Client commands

```bash
# Enroll with the command printed by `token create`; both fingerprints are pinned.
portmaster-core manage enroll --server https://pm.example.lan:8443 --token <token> \
  --server-fp sha256:... --policy-key-fp sha256:...
portmaster-core manage status
portmaster-core manage pull    # pull and apply now, send a report
portmaster-core manage leave   # the policy values stay as user settings
```

Before it sends the token, the client fetches the policy key (`GET /v1/policy-key`) and checks
it against the pin, so a wrong pin does not use up the token.

The client keeps its state in `<data dir>/managed/` (0700, files 0600): `state.json`,
`client.key`, `client.crt`, `ca.crt` and the last verified `policy.json`. When the core is
created, before interception starts, it sets the policy layer (settings and rules) from the
stored policy, so there is no unmanaged window at boot and an offline computer stays
configured; at start it imports the profiles of the stored policy, then pulls every 5 minutes.
A policy is applied only if its signature matches the pinned policy key, it names this
computer and its version is not lower than the applied one; otherwise the previous policy
stays in force (at boot: none, so the user values apply).

The policy values are a layer above the user settings: `settings export` shows the user
values, `settings export --effective` the values in force. Locked settings cannot be changed
(`managed by policy`); a local admin may override an unlocked one, which is listed as
`overridden` in the status and in the report. `manage leave` removes the layer and keeps the
configuration: locked values and defaults without a user value become user values, and the
policy rules are put before the global rules.

The app shows the policy: locked settings are read-only and marked "Managed by your
organisation" (also in the app settings), policy defaults are marked "Default set by your
organisation" and "Reset" returns to the policy value. The global settings start with a panel
showing the server, group, policy version, last update, changed defaults and settings not
applied.

## Phases

| Phase | Content | Done when |
|---|---|---|
| A | Server (init, CA, tokens, groups, computers, policies; admin CLI over Unix socket); client module with enroll, pull, signed policy, apply via `service/sync`, drift correction, status report; `manage` commands | VM test: Linux and Windows client enroll, get a policy, a local change is reverted, an offline client applies the stored policy at boot, a revoked client is rejected, a tampered/old policy is refused |
| B | Policy layer in `base/config` and `service/profile`; locked settings rejected by API and shown in the UI; policy endpoint rules | Locked setting cannot be changed in UI/API; app profile cannot override it; unmanaged install behaves as before (smoke tests) |
| C | Web UI for admins (computers, versions, health, groups, policies, recent blocks); admin accounts with passkeys/TOTP; blocked-connection summaries and alerts (malware list hits, new apps with network access) | Admin can do in the UI everything the CLI does |
| D | Hardening: offline policy signing (sign on an admin machine, server only distributes), key rotation, certificate renewal edge cases, server backup/restore docs, packaging | Server compromise alone cannot push a policy when offline signing is used |

Phase A is the first PR series; each phase ships on its own and is usable.

## Phase B plan

### How settings work today

- `base/config`: each option has `activeValue` (user, from `config.json`), `activeDefaultValue`
  (set at runtime, e.g. `core/enableProcessDetection` on some systems) and
  `activeFallbackValue` (registration default); `getValueCache` returns the first that is set.
  Writes go through `setConfigOption` (UI via the `config:` database, `settings import` of a
  single key, API keys) and `ReplaceConfig` (loading `config.json`, `settings import`).
- `service/profile`: a LayeredProfile is the app profile layers plus the global settings. The
  `wrap*Option` functions return the first layer that sets the key, else the global value; the
  `Match*` functions check the endpoint lists of the layers first, then the global list;
  `MatchFilterLists` uses the first layer that sets `filter/lists`. So **an app profile wins
  over every global setting**, including endpoint rules and filter lists.
- Profile writes (UI, `profile import`, the managed module) pass the database hook `PrePut` in
  `service/profile/database.go`, which validates the profile config.

### Semantics

- **Locked settings** (`locked` in the policy) are enforced: their policy value has the highest
  precedence, in the global settings and in every app profile. Writes that change them are
  refused with "managed by policy". User values stay stored but have no effect while locked.
- **Unlocked policy settings** become a **policy default**: they replace the default, a local
  admin may override them, and the override is reported (not reverted). This replaces the drift
  correction of phase A for unlocked keys; an admin who wants a value kept locks it.
- **Policy rules** (`rules.endpoints`, `rules.serviceEndpoints`) are evaluated before all app
  profile and global rules. They cannot be overridden; an app can only decide what the policy
  rules leave open. Typical use: organisation-wide blocks and the allowed management/backup
  servers.
- **Leave** (`manage leave`) copies the policy values into the user values before clearing the
  layer, so a computer keeps its configuration when it leaves management (as in phase A).
- Unmanaged installs: the layer is empty; behaviour and performance are unchanged.

Precedence after phase B (first that is set wins):

| Global setting | In an app profile |
|---|---|
| policy locked value | policy locked value |
| user value | app profile layers |
| policy default | global setting (left column) |
| runtime default, registration default | |

Endpoint rules: policy rules, then app profile rules, then global rules.

### Steps

| Step | Content | Done when |
|---|---|---|
| B1 | `base/config`: per option `policyValue` and `locked`; `config.SetPolicy(values, locked)` replaces the layer atomically, keeps values of keys not yet registered and applies them at registration; `getValueCache` order as above. `setConfigOption` and `sync.ImportSettings` refuse locked keys (`config.ErrLockedByPolicy`); `ReplaceConfig` keeps them stored but inert. The option record gets `PolicyValue`, `Locked` and an annotation for the UI. `settings export` exports user values only, with `--effective` for the values in force. | Unit tests: precedence, refused writes, pending keys, release level, concurrent reads (race test) |
| B2 | `service/profile`: `wrap*Option` and `MatchFilterLists` skip the app layers for locked keys; `MatchEndpoint` / `MatchServiceEndpoint` check the policy rules first. `PrePut` refuses a save that sets or changes a locked key (existing values stay, inert), so the UI and `profile import` get a clear error. A change of the policy bumps the revision of all active layered profiles. Special profiles written by the Portmaster itself (the global config profile, the built-in profiles) are exempt from the `PrePut` check. | Unit tests with a layered profile: locked key ignores the app value, unlocked key does not; policy rule wins over an app allow rule |
| B3 | Managed module and server: apply through `SetPolicy` instead of the settings import; apply the stored policy in `managed.New`, i.e. before interception starts, so there is no unmanaged window at boot; `policy.Policy.Rules` and `portmanagster-server group rules NAME FILE`; the report lists overridden unlocked keys instead of corrected ones; `leave` copies the values. | End to end test client/server: locked, unlocked and rules arrive; leave keeps the values |
| B4 | UI (Angular): locked settings are read-only with "Managed by your organisation" in the global and the app settings; policy defaults show their origin; a small "Managed" panel (server, group, policy version, last pull). | UI build; manual check in the browser against a managed core |
| B5 | VM tests Linux and Windows, step "Management" extended: a locked setting cannot be changed through the config API, `settings import` or an app profile; a policy rule blocks a domain that an app profile allows (curl from a profiled binary); an overridden unlocked setting is reported; the full smoke test without enrollment is unchanged. | Both VMs pass |

Status: B1–B5 are done. The VM smoke tests (step "Management") check on Linux and Windows:
- a locked setting is in force over the user value and cannot be changed through `settings
  import`, the config API (`sync/single-setting/import`) or an app profile;
- a policy rule blocks a domain that the app profile of curl allows;
- with locked filter lists the global config profile is updated without errors;
- an overridden default is reported;
- offline start, refused old and tampered policies, revocation, and leave keeping the values.

The own connections of the Portmaster (updates, DNS, the management pull) are allowed before
any profile or policy check, so a locked setting such as the default action cannot block them.

Order: B1 → B2 → B3 (each a PR, usable on its own: B1/B2 without B3 change nothing, as the
layer stays empty), then B4 and B5. B4 can run in parallel with B3.

### Risks

- Hot path: the `wrap*Option` functions run per connection. The locked check must be a lookup
  in an immutable snapshot taken at refresh time, not a config call per read.
- Boot order: options are registered in the modules' constructors; the pending values of
  `SetPolicy` cover keys that are not registered yet when `managed.New` runs.
- `core/enableProcessDetection` and other runtime defaults: a policy default for the same key
  sits above the runtime default; locking such a key overrides the system detection. The
  server should warn when it is locked.
- Upstream merges: `base/config` and `service/profile` are upstream code; the changes are kept
  small and in separate files where possible.

## Phase C plan

Phase C gives admins a web UI on the server: everything the CLI does, plus a view of what the
clients block and alerts. The CLI stays; both work on the same database.

### Decisions

- **UI technology: server-rendered HTML in the server binary.** Go `html/template` pages with
  a few lines of plain JavaScript (passkey ceremony, confirm dialogs), embedded with
  `go:embed`. No Node build for the server, one static binary, a strict Content Security
  Policy (`default-src 'self'`, no inline scripts), and the handlers are tested with
  `httptest` like the client API. The Angular code of the Portmaster app is not reused: it is
  built around the local portapi and its websocket database, and would put a large build and
  dependency tree into the server. (This settles the open question below.)
- **Separate admin listener.** `serve --admin-listen 127.0.0.1:8444` (default: localhost only).
  The client API on `:8443` stays as it is (mutual TLS, no admin routes). Admins reach the UI
  through an SSH tunnel, or bind it to the LAN with a certificate the browsers trust
  (`--admin-cert/--admin-key`, e.g. from the company PKI or ACME). Reason: passkeys
  (WebAuthn) need a secure context, which `http://localhost` is and a page with a certificate
  warning is not; the internal CA of the client API is not trusted by browsers.
- **Admin accounts with passkeys, TOTP as fallback.** No passwords. The first account is
  created on the server host: `portmanagster-server admin add NAME` prints a one-time setup
  link (15 min); opening it registers a passkey, or a TOTP secret if the browser has no
  passkey support. Library for WebAuthn: `github.com/go-webauthn/webauthn` (new dependency,
  needs approval to download); TOTP (RFC 6238) is small enough to implement with
  `crypto/hmac`. `admin list|remove|reset NAME` on the CLI; a removed or reset admin loses all
  sessions.
- **Roles: `admin` and `viewer`.** Viewers see everything and change nothing. Finer roles
  (per group) only if needed later.
- **Sessions:** random 256-bit ID in a cookie (`Secure` unless on localhost, `HttpOnly`,
  `SameSite=Strict`), stored hashed in SQLite, 12 h lifetime, 30 min idle timeout. Every
  POST carries a CSRF token bound to the session; login is rate-limited per account and IP.
- **Audit log:** every change (UI and CLI) is written to an `audit` table: time, actor
  (`admin:NAME` or `cli`), action, object, and a summary of the change (e.g. the keys that
  changed in a group policy, not the full values of large lists). Shown in the UI, readable
  with `portmanagster-server audit [--since]`. Not editable through the UI.

### Blocked-connection summaries (opt-in per group)

- A group setting `blockSummary` (off by default). When it is on, the client adds a summary to
  each report: per (app, verdict reason, filter list or rule, domain or IP) the number of
  blocked connections since the last report, from netquery, capped at the 200 largest entries.
  No allowed connections, no connection lines, no user names.
- The server keeps the summaries for `--block-retention` (default 30 days) and aggregates them
  per group and computer. The UI shows "recent blocks" per computer and per group, filterable by
  app, list and domain.
- The opt-in is shown on the group page and in the client's Managed panel ("Your organisation
  receives a summary of blocked connections"), so users and works councils can see it.

### Alerts

Computed on the server from reports and summaries; shown on the dashboard and, if configured,
sent as JSON to a webhook (`--alert-webhook URL`, e.g. for an RMM tool, Matrix or a mail
gateway). Each alert has a state (new, acknowledged) and is audited when acknowledged.

| Alert | Source |
|---|---|
| Computer silent for more than N hours (per group, default 24) | `last_seen` |
| Interception off, core module errors | report status |
| Policy refused or settings not applied | report `refused`, last error |
| Policy default overridden locally | report `overridden` (info level) |
| Hit on a malware filter list (`MAL` and the malware lists of the index) | block summary |
| New app with network access on a computer | block summary and a new "apps" list in the report (app name and path hash, opt-in with the summary) |

### UI pages

- **Dashboard:** number of computers per state (ok, problems, silent, revoked), open alerts,
  computers not on the current policy.
- **Computers:** list with filters (group, state, OS, version); detail page with the last
  report, health, applied version, overridden and refused settings, recent blocks; revoke,
  move to another group.
- **Groups:** create, delete (only if empty); settings editor (YAML/JSON as in the CLI, with a
  lock checkbox per key; the clients validate the values and report invalid or unknown keys as
  `refused`, which the group page lists per computer),
  profiles (upload, list, remove), rules editor, block summary opt-in, silent threshold.
- **Enrollment:** create a token for a group, show the enroll command with both fingerprints,
  list and revoke unused tokens.
- **Admins and audit log** (admin role only).

### Steps

| Step | Content | Done when |
|---|---|---|
| C1 | Admin listener, accounts (`admin add/list/remove/reset`), passkey and TOTP login, sessions, CSRF, rate limit, audit table (CLI changes audited too), empty dashboard. | Handler tests: login, logout, expiry, CSRF refused, viewer cannot POST; manual check with a passkey in the browser over an SSH tunnel |
| C2 | Read-only pages: dashboard, computers (list, detail), groups, tokens, audit log. | Handler tests; browser check against a server with enrolled VMs |
| C3 | Write actions: group create/delete/settings/profiles/rules, token create/revoke, computer revoke/move. Same validation as the CLI (shared functions moved from `cmds/portmanagster-server` into `mgmt/server`). | Everything the CLI does works in the UI (checked against the command list); every change is in the audit log |
| C4 | Block summaries: client part in `service/managed` (netquery aggregate, opt-in from the policy, cap), report field, server storage with retention, "recent blocks" views, notice in the client's Managed panel. | Unit tests; VM test: a blocked domain shows up on the server with app and list |
| C5 | Alerts and webhook. | Unit tests per rule; VM test: silent computer and a `MAL` hit raise alerts, the webhook receives them |

Order: C1 → C2 → C3; C4 can start after C1 (client and report part are independent of the UI);
C5 after C4.

### Risks

- **Attack surface:** the admin UI can change every firewall. Mitigations: localhost-only
  default, no passwords, CSRF tokens, strict CSP, no inline scripts, `html/template` escaping,
  audit log; policy signing stays as it is, so a UI bug cannot bypass the clients' signature
  check, but can produce a signed bad policy (phase D adds offline signing for that case).
- **Passkeys and TLS:** passkeys fail on a page with a certificate warning. The docs must make
  the SSH tunnel the default path and explain `--admin-cert`. TOTP works in any case.
- **Privacy:** block summaries are personal data in many jurisdictions (which app a person
  used, which domains were blocked). Off by default, per group, retention limited, visible to
  the user.
- **Report size:** summaries are capped per report; the server rejects reports above a limit.
- **SQLite growth:** summaries are aggregated per hour and pruned by retention in the existing
  database; no second database.

## Security considerations

- **The server controls every firewall.** Mitigations: clients verify the policy signature
  (phase A), optional offline signing key (phase D), admin access only on the server host
  until phase C, audit log of every policy change on the server.
- **Network attacker**: mutual TLS with pinned server certificate; policies are signed on top,
  so even a TLS break does not allow changing the firewall.
- **Stolen client certificate**: lets the thief read that computer's policy and send fake
  reports, nothing more; revoke the computer.
- **Replay/rollback**: policy version must increase; the client stores the highest version.
- **Local admin**: can always unenroll or uninstall (root); the server notices the silence.
  The policy layer stops casual changes, not a determined root user.
- **Availability**: a broken server never weakens a client: the last good policy stays.

## Privacy

Default report: version, health, policy state. Blocked-connection summaries and connection
lines are opt-in per group and documented, so works councils and GDPR reviews can see what is
collected. No data leaves the self-hosted server.

## Open questions

- Whether clients should also accept a policy from a file (air-gapped networks), signed the
  same way.
- Name and default port of the server (`portmanagster-server`, 8443 assumed here).
