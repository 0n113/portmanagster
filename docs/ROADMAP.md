# Roadmap

portmanagster builds central management on top of portmasterpro (Portmaster without SPN,
accounts and telemetry). The approach: integrate with tools that already do a job well instead
of rebuilding them, and add our own server only where the Portmaster needs one.

## Step 0: scriptable settings and profiles (done)

`portmaster-core settings|profile export|import`, see
[central-management.md](central-management.md). Any remote administration tool that can run a
command as root can manage the Portmaster with it.

## Step 1: integration with remote administration tools

- Done: Ansible role in `integrations/ansible/` (install, settings, profiles, health check,
  settings backup).
- Done: `portmaster-core status` and `status --check` with monitoring exit codes.
- Ansible collection on Galaxy.
- Salt state and examples for MeshCentral and Tactical RMM scripts.
- Read-only export of connection history for the tools below.

## Step 2: network-wide monitoring of malware connections

The Portmaster sees which app on which computer connects where, and which connections the filter
lists (malware, phishing, trackers) block. Sent to a central place, this shows infected
computers early.

- Export of connection events as JSON lines (syslog or file), with computer, app, destination,
  verdict and the matching filter list.
- Integration with an existing SIEM/EDR instead of an own analysis: Wazuh (decoder and rules),
  Graylog, Elastic, Loki.
- Alerts for blocked connections to malware domains, new apps with network access, and many
  denied connections from one app.

## Step 3: backups

Backups are not the job of a firewall; existing tools do it better (restic, Borg, UrBackup).
portmanagster will support them where the firewall is involved:

- Backup and restore of the Portmaster's own settings and profiles (step 0 exports).
- Examples for allowing exactly the backup agent to reach the backup server, per computer.
- Optionally, the backup state of each computer in the central view (step 4).

## Step 4: own management server and agent

Needed when push via other tools is not enough: central view, policies that local admins cannot
change, offline computers that apply the policy when they come back.

- Pull model: each Portmaster asks the server for its policy; no open port on the clients.
- Enrollment with a one-time token, then mutual TLS with a per-computer certificate.
- Policies signed with Ed25519; clients apply only signed policies of their server.
- A locked central settings layer: settings set by the policy cannot be changed in the local UI.
- Admin view: computers, versions, state, recent blocks; groups with their own policies.
- Self-hosted, no cloud, no telemetry.
