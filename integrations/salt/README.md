# Salt formula: Portmaster

States in `portmaster/`:

| File | Purpose |
|------|---------|
| `init.sls` | Installs package `portmaster` (optional `source`), runs `portmaster.service`, includes the rest |
| `settings.sls` | Renders pillar `portmaster:settings` to `/etc/portmaster/managed-settings.yaml` (mode 600) and runs `settings import --validate` + `settings import` when the file changes (`onchanges`) |
| `status.sls` | Runs `portmaster-core status --check`; retcodes 0 and 1 are success (`success_retcodes: [0, 1]`), 2/3 fail |
| `pillar.example` | Example pillar |

## Usage

1. Copy `portmaster/` into your `file_roots` (e.g. `/srv/salt/portmaster`).
2. Add pillar data (see `pillar.example`) and assign it to minions.
3. Apply: `salt 'host*' state.apply portmaster`

Pillar keys: `pkg_name`, `source`, `source_hash`, `core_path`
(default `/usr/lib/portmaster/portmaster-core`), `max_intel_age` (default `336h`),
`settings` (map placed under `config:`), `settings_reset` (default `False`, i.e. merge).

Notes:
- Settings are merged unless `settings_reset: True`. Only keys in the pillar are managed.
- The rendered file contains no `_jess-checksum`; do not add one.
- Use `state.apply portmaster test=True` to preview; the import runs only when the file changes.
