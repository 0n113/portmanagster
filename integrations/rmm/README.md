# Portmaster with RMM and monitoring tools

Scripts wrap `portmaster-core` (must run as root/SYSTEM):

| Script (`linux/*.sh`, `windows/*.ps1`) | Purpose |
|---|---|
| `portmaster-check` | `status --check`; exit 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (also when the binary is missing) |
| `portmaster-apply-settings FILE` | `settings import --validate`, then import (merge; `RESET=1` / `-Reset` to replace); non-zero on failure |
| `portmaster-backup DIR` | `settings export` to `DIR/portmaster-settings-<host>-<date>.yaml`; keeps the last `KEEP` (default 14) / `-Keep` |

Linux binary: `/usr/lib/portmaster/portmaster-core` (override with `CORE=`).
Windows: parameter `-CorePath`, default `$env:ProgramFiles\Portmaster\portmaster-core.exe`.
**The Windows install path of the core has not been verified**; adjust `-CorePath` if needed.

## Tactical RMM

Add the scripts under Settings > Script Manager (Shell for `.sh`, PowerShell for `.ps1`).
Create a Script Check on the agent/policy running `portmaster-check`: exit 0 = pass,
exit 1 = warning, exit 2 (and 3) = fail. Set the warning/error exit-code mapping in the
check's settings. Use `apply-settings` and `backup` as tasks (arguments: file path / target dir).

## MeshCentral

Upload the scripts under My Files / Scripts, then use "Run Commands" on a device or group,
or schedule them (Scripts > Schedule). Example one-off command:
`/usr/lib/portmaster/portmaster-core status --check`.

## Zabbix

Agent config (the agent user needs root, e.g. via sudo):

```
UserParameter=portmaster.status,sudo /usr/lib/portmaster/portmaster-core status
UserParameter=portmaster.check,sudo /usr/lib/portmaster/portmaster-core status --check; echo $?
```

`portmaster.status` returns JSON: use a dependent item with a JSONPath preprocessing step
(`$.ready`, `$.filtering`, `$.intelAgeHours`, `$.problems.length()`). For `portmaster.check`
use a "Regular expression" step or a trigger on the last character (exit code 0..3);
alternatively wrap `portmaster-check.sh`. Example trigger: last value of exit code `>=2`.

## Icinga / Nagios

The check output and exit codes follow the Nagios plugin convention.

NRPE (`nrpe.cfg`, with a sudoers entry for the nrpe user):
```
command[check_portmaster]=sudo /opt/portmaster/portmaster-check.sh
```
check_by_ssh (Nagios):
```
define command {
  command_name check_portmaster
  command_line $USER1$/check_by_ssh -H $HOSTADDRESS$ -l monitor -C "sudo /usr/lib/portmaster/portmaster-core status --check"
}
```
Icinga 2: use `check_by_ssh` / `nrpe` CheckCommand with `command` set the same way.

## Wazuh

Command monitoring in the agent `ossec.conf`:

```xml
<localfile>
  <log_format>command</log_format>
  <command>/usr/lib/portmaster/portmaster-core status --check</command>
  <alias>portmaster status</alias>
  <frequency>300</frequency>
</localfile>
```

Enable remote commands for the agent (`wazuh_command.remote_commands=1` in
`local_internal_options.conf`) if required. A custom rule on the manager can alert when the
output starts with `CRITICAL`, e.g. a rule matching `<match>^CRITICAL</match>` on the
`ossec` command decoder output with a suitable level.
