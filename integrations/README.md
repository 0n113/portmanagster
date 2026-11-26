# Integrations

| Directory | Contents |
|---|---|
| `ansible/` | Ansible role and example playbook: install, settings, profiles, SSH access, health check, backup |
| `salt/` | Salt formula: package, service, settings from pillar, status check |
| `siem/` | Connection export as JSON lines (systemd timer, logrotate) for Wazuh (agent config and rules), Fluent Bit, Loki, Filebeat, Graylog |
| `rmm/` | Check, apply-settings and backup scripts for Linux (sh) and Windows (PowerShell), plus notes for Tactical RMM, MeshCentral, Zabbix, Icinga/Nagios, Wazuh |

All integrations drive `portmaster-core` (`settings`, `profile`, `status`, `connections` subcommands).
