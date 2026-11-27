# Firewall rules for backup agents

Backups are made by existing tools (restic, Borg, UrBackup). These app profiles let exactly the
backup agent reach the backup server and block every other destination of that agent, so a
compromised or misconfigured agent cannot send data elsewhere. The rest of the computer is not
affected.

| File | Agent | Rules |
|---|---|---|
| `restic-linux.yaml`, `restic-windows.yaml` | restic (rest-server, S3, ...) | out: repository host and port only |
| `borg-ssh-linux.yaml` | Borg over SSH | out: the **ssh client** to the backup server only (see below) |
| `urbackup-client-linux.yaml`, `urbackup-client-windows.yaml` | UrBackup client | in: TCP 35621, 35623, UDP 35622 from the server; out: TCP 55413-55415, UDP 35622 to the server |

Before importing, replace `backup.example.lan` / `192.168.1.10` and the port with your backup
server, and check the binary path: the Portmaster matches the real path of the executable
(no symlinks), shown in the app list of the Portmaster UI. The Windows paths depend on the
installer.

```bash
sudo /usr/lib/portmaster/portmaster-core profile import --validate restic-linux.yaml
sudo /usr/lib/portmaster/portmaster-core profile import --allow-replace restic-linux.yaml
```

Rules are checked in order and the first match wins; `- *` at the end blocks the rest. The
entity can be a domain (`backup.example.lan`, `*.example.lan`), an IP, a range
(`192.168.1.0/24`) or a scope (`LAN`, `Localhost`); the optional last field is `TCP/<port>`,
`TCP/<from>-<to>` or `UDP/<port>`. `endpoints` are outgoing rules, `serviceEndpoints` incoming
rules; incoming rules only apply with `blockInbound: false` in the same profile.

**Borg** opens its connection through `ssh`, so the Portmaster sees `/usr/bin/ssh` and not
borg. Limiting ssh to the backup server also limits every other ssh use of that computer; add
rules for other destinations you need.

**Ansible**: `portmaster_app_rules` in the [role](../ansible/roles/portmaster/README.md) writes
and imports such profiles per host, e.g. with the backup server from the inventory:

```yaml
portmaster_app_rules:
  - name: restic
    path: /usr/bin/restic
    endpoints: ["+ {{ backup_server }} TCP/8000", "- *"]
```

Tested on Fedora 45: all example files validate; with the restic rule `+ example.com TCP/443`,
`- *`, restic reached example.com and its connection to wikipedia.org was blocked
("denied by rule").
