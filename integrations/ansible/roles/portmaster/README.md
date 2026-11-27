# Ansible role: portmaster

Installs, configures and checks [Portmaster](../../../../docs/central-management.md) on Linux
hosts through `portmaster-core` (settings and profile import/export, `status`). Needs only
ansible-core (2.12+), no extra collections, and `become: true`. Without gathered facts the
role collects the minimal facts it needs for the install itself.

Order: sshd profile file, install and first start, wait until ready, sshd profile import,
backup, settings, profiles, health check.

**SSH access:** the Portmaster blocks incoming connections by default, which would also block
Ansible. With `portmaster_ssh_access` (on by default), the role writes a profile for sshd that
allows incoming SSH by `portmaster_ssh_rules` (default: from the LAN and localhost only). On
the first start, starting the service, waiting until it is ready and importing this profile
run as one job on the host, so the job finishes even while the SSH connection is blocked.
Turn it off if you manage SSH access yourself, e.g. with your own sshd profile.

```yaml
- hosts: portmaster
  become: true
  roles:
    - role: portmaster
      vars:
        portmaster_settings:
          filter: {askTimeout: 33, lists: [TRAC, MAL]}
```

See [example-playbook.yml](../../example-playbook.yml).

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `portmaster_core_path` | `/usr/lib/portmaster/portmaster-core` | Core binary. |
| `portmaster_install` | `false` | Install the package and enable/start `portmaster.service`. |
| `portmaster_package_url` | `""` | rpm/deb URL or path on the host; fallback for the two below. |
| `portmaster_package_rpm` / `_deb` | `""` | Package for the RedHat / Debian family. |
| `portmaster_disable_gpg_check` | `false` | For unsigned local rpm files. |
| `portmaster_ready_retries` / `_delay` | `30` / `5` | Retries and seconds while waiting for `ready: true`. |
| `portmaster_settings` | `{}` | Nested dict, same as `config:` in a settings export. |
| `portmaster_settings_reset` | `false` | `--reset`: settings not listed are removed. |
| `portmaster_settings_allow_unknown` | `false` | `--allow-unknown`. |
| `portmaster_settings_keys` | `[]` | Override of the compared keys (slash-joined, e.g. `filter/askTimeout`). |
| `portmaster_restart_if_required` | `false` | Restart the service when the import reports `restartRequired`. |
| `portmaster_profiles` | `[]` | Profile export files on the controller. |
| `portmaster_profiles_allow_unknown` | `false` | `--allow-unknown` for profiles. |
| `portmaster_profiles_force` | `false` | Import all profiles on every run, not only changed files. |
| `portmaster_ssh_access` | `true` | Import a profile for sshd that allows incoming SSH (see above). |
| `portmaster_ssh_rules` | `["+ LAN", "+ Localhost", "- *"]` | Incoming rules for sshd; first match wins. |
| `portmaster_managed_dir` | `/etc/portmaster/ansible` | Host directory for the profile files the role imports. |
| `portmaster_fail_on_critical` | `true` | Fail the play on `status --check` exit 2 or 3. |
| `portmaster_max_intel_age` | `336h` | Passed as `--max-intel-age`. |
| `portmaster_backup` | `false` | Back up settings and app profiles (`tasks/backup.yml`) before applying changes. |
| `portmaster_backup_dir` | `{{ playbook_dir }}/portmaster-backups` | Controller directory for backups. |

Result fact: `portmaster_status` is the parsed JSON of `portmaster-core status`
(`version`, `ready`, `interception`, `filtering`, `intelAgeHours`, `problems`, ...).

## Behaviour

- **Settings** are written as a YAML export to a root-only (0600) temp file that is always
  removed. `settings import --validate` runs first and fails the play on an invalid file.
  The file never contains a checksum.
- **Idempotency**: the role derives the slash-joined key of every leaf of `portmaster_settings`
  (a recursive Jinja macro, lists are leaves), exports only those keys with `--format json` and
  imports only when a requested value differs or is missing. Lists compare in order. With
  `portmaster_settings_reset: true` the whole export must equal `portmaster_settings`.
- **Profiles** are copied to `portmaster_managed_dir/profiles` (root-only), validated and
  imported with `--allow-replace`, but only when the file there changed (or always with
  `portmaster_profiles_force`). After a failed import the file is removed, so the next run
  imports it again. Changes made in the Portmaster UI are not undone without the force option.
  A profile file needs `type: profile`, `source: local`, a `name` and `fingerprints`. Leave
  out `id` in hand-written files: the Portmaster derives it from the fingerprints and rejects
  an `id` that does not match. Files from `portmaster-core profile export` keep their ID.
  Example (the sshd path differs by distribution: `/usr/bin/sshd` on current Fedora (tested on 45), where sbin
  is merged into bin; `/usr/sbin/sshd` on Debian):

  ```yaml
  type: profile
  source: local
  name: OpenSSH Server
  fingerprints:
    - type: path
      operation: equals
      value: /usr/sbin/sshd
  config:
    filter:
      blockInbound: false
  ```
- **Health**: `status --check` exit 1 (WARNING) only prints a debug message; 2 (CRITICAL) and
  3 (UNKNOWN) fail the play unless `portmaster_fail_on_critical: false`.
- **Backup** runs `portmaster-core backup create` on the host and writes
  `<backup_dir>/<inventory_hostname>-backup-<YYYY-MM-DD>.tar.gz` (mode 0600) on the controller:
  the global settings, all local app profiles and a manifest. To restore, copy it to the host,
  unpack it and run `portmaster-core backup restore <dir>/backup` (`--validate` checks only).
- In check mode, read-only commands still run; imports and installs are skipped.
