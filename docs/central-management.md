# Central management with existing tools

portmanagster is meant to manage the Portmaster on many computers of one network. The first
step is a scriptable interface on each computer: `portmaster-core` can export and import the
global settings and app profiles of the running Portmaster. Configuration management and remote
administration tools (Ansible, Salt, Puppet, MeshCentral, Tactical RMM, plain SSH) run these
commands as root and so manage every computer from one place, without a server of our own yet.

## Commands

Run as root (Linux) or as administrator (Windows) on the computer itself. The commands talk to
the local API of the running Portmaster at `127.0.0.1:817` (`--api` changes it). The API trusts
them because they are run from the Portmaster installation directory
(`/usr/lib/portmaster/portmaster-core` on Linux); a copy elsewhere is denied.

```bash
# Export all global settings that differ from the defaults (YAML, or --format json).
sudo /usr/lib/portmaster/portmaster-core settings export -o settings.yaml

# Export selected settings only.
sudo /usr/lib/portmaster/portmaster-core settings export --key filter/lists --key dns/nameservers

# Check an import and see what it would change, without applying it.
sudo /usr/lib/portmaster/portmaster-core settings import --validate settings.yaml

# Apply. Settings missing from the file stay as they are.
sudo /usr/lib/portmaster/portmaster-core settings import settings.yaml

# Apply and remove every setting that is not in the file (the file is the full config).
sudo /usr/lib/portmaster/portmaster-core settings import --reset settings.yaml

# App profiles: export by scoped ID, import (--allow-replace overwrites an existing one).
sudo /usr/lib/portmaster/portmaster-core profile export local/<id> -o app.yaml
sudo /usr/lib/portmaster/portmaster-core profile import --allow-replace app.yaml
```

`-` reads the import from stdin. Imports print the result as JSON
(`restartRequired`, `replacesExisting`, `containsUnknown`). Every command exits non-zero on an
error, e.g. when the Portmaster is not running or the file is invalid. Unknown setting keys are
rejected unless `--allow-unknown` is given, so a typo does not go unnoticed.

Exports carry a checksum (`_jess-checksum` in JSON, a `# jess-checksum:` comment in YAML).
If you edit an export or write the file from a template, remove that line; a file without
checksum is accepted, one with a wrong checksum is not.

A minimal settings file:

```yaml
type: settings
config:
  filter:
    blockInbound: true
    lists: [TRAC, MAL, BAD, UNBREAK]
  dns:
    nameservers:
      - dot://dns.quad9.net?ip=9.9.9.9&name=Quad9
```

## Ansible example

```yaml
- hosts: portmaster
  become: true
  tasks:
    - name: Copy the Portmaster settings
      ansible.builtin.template:
        src: portmaster-settings.yaml.j2
        dest: /etc/portmaster-settings.yaml
        mode: "0600"
      register: pm_settings

    - name: Apply the Portmaster settings
      ansible.builtin.command:
        argv: [/usr/lib/portmaster/portmaster-core, settings, import, --reset, /etc/portmaster-settings.yaml]
      when: pm_settings.changed
```

## Limits of this step

- Push only: each computer applies what it is given. There is no central view of the computers
  and their state, and a user with admin rights on a computer can change the settings again.
- No signed policies: whoever can run commands as root on a computer can change its settings.
  That is the same trust the remote administration tool already has.

The next steps are in [ROADMAP.md](ROADMAP.md).
