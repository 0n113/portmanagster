# Design: management server and agent (roadmap step 4)

Status: plan, not implemented. This document fixes the architecture and the order of work;
details of each phase are settled in its PR.

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
  accounts with passkeys/TOTP.

### Client: module `service/managed` in portmaster-core

- No separate agent process: the core already runs as root/SYSTEM, has the settings, profiles,
  status and netquery in-process. Off unless enrolled.
- State in the data dir: client key and certificate, pinned server certificate and policy key,
  last applied policy (signed, as received), so the policy applies at boot without network.
- Pull loop: every 5 minutes (server-tunable, with jitter) and a long-poll so a policy change
  arrives in seconds while online. Backoff on errors; the last good policy stays in force.
- Reports with each pull: version, `core/status` (the same data as `status`), applied policy
  version, and drift (settings that differ from the policy). Optional per group: summary of
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
  "computer": "<client cert fingerprint>",
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

Today a setting has a user value and defaults; app profiles override global settings. For
enforcement, the core gets a **policy layer** on top of both:

- `base/config`: a policy value per option, highest precedence, set only by the managed module.
  Setting a locked key through the API (UI, `settings import`) fails with "managed by policy";
  the option carries an annotation so the UI shows it as locked.
- `service/profile`: the LayeredProfile checks the policy layer first for locked keys, so an app
  profile cannot override a locked global setting, and evaluates the policy `rules` before the
  profile and global rules.
- Without enrollment the layer is empty and nothing changes for unmanaged installs.

Until phase B, enforcement is by **drift correction**: the client re-applies the policy
settings and profiles when they differ (on every pull and on config change), and reports the
drift.

## Phases

| Phase | Content | Done when |
|---|---|---|
| A | Server (init, CA, tokens, groups, computers, policies; admin CLI over Unix socket); client module with enroll, pull, signed policy, apply via `service/sync`, drift correction, status report; `manage` commands | VM test: Linux and Windows client enroll, get a policy, a local change is reverted, an offline client applies the stored policy at boot, a revoked client is rejected, a tampered/old policy is refused |
| B | Policy layer in `base/config` and `service/profile`; locked settings rejected by API and shown in the UI; policy endpoint rules | Locked setting cannot be changed in UI/API; app profile cannot override it; unmanaged install behaves as before (smoke tests) |
| C | Web UI for admins (computers, versions, health, groups, policies, recent blocks); admin accounts with passkeys/TOTP; blocked-connection summaries and alerts (malware list hits, new apps with network access) | Admin can do in the UI everything the CLI does |
| D | Hardening: offline policy signing (sign on an admin machine, server only distributes), key rotation, certificate renewal edge cases, server backup/restore docs, packaging | Server compromise alone cannot push a policy when offline signing is used |

Phase A is the first PR series; each phase ships on its own and is usable.

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

- Web UI technology for phase C: reuse the Angular code of the Portmaster UI, or a small
  separate UI.
- Whether clients should also accept a policy from a file (air-gapped networks), signed the
  same way.
- Name and default port of the server (`portmanagster-server`, 8443 assumed here).
