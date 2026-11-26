# SIEM integration

Ships Portmaster connection events (JSON lines) and health status to a SIEM.
`portmaster-core connections --cursor FILE` exports only connections not exported before,
so a timer can run it every minute and append to a log file that any shipper can tail.

## Privacy

The log contains every domain, IP and application each computer connects to. Restrict access
to the file (0600 root) and to the SIEM index, and set a retention period that matches your policy.
To reduce volume, add `--blocked` to `ExecStart` in the service to export only blocked connections.

## Setup (on each Portmaster host)

```sh
install -m 644 systemd/portmaster-connections-export.{service,timer} /etc/systemd/system/
install -m 644 logrotate/portmaster-connections /etc/logrotate.d/
install -m 644 tmpfiles/portmaster-connections.conf /etc/tmpfiles.d/
systemd-tmpfiles --create /etc/tmpfiles.d/portmaster-connections.conf
systemctl daemon-reload
systemctl enable --now portmaster-connections-export.timer
```

Check: `systemctl list-timers portmaster-connections-export` and `tail /var/log/portmaster/connections.json`.
Fields per line: `time`, `ended`, `host`, `id`, `verdict`, `reason`, `filterLists`, `direction`, `type`,
`profile`, `app`, `path`, `pid`, `domain`, `protocol`, `localIP`, `localPort`, `remoteIP`, `remotePort`,
`country`, `asn`, `asOwner`, `bytesSent`, `bytesReceived` (empty fields are omitted).

## Wazuh

1. Agent: add the contents of `wazuh/ossec-agent.conf` to the agent's `ossec.conf`
   (the `full_command` check may need `wazuh_command.remote_commands=1` in the agent's
   `local_internal_options.conf` if pushed from the manager), then `systemctl restart wazuh-agent`.
2. Manager: copy `wazuh/portmaster_rules.xml` to `/var/ossec/etc/rules/`, test with
   `/var/ossec/bin/wazuh-logtest`, then `systemctl restart wazuh-manager`.
3. Adjust the list IDs in rule 100803 (`MAL|PHISH|BAD`) to the filter lists you enabled.

Rules (IDs 100800-100899): blocked connection (5), blocked by filter list (7), malware/phishing list (10),
20 blocked from one app in 120 s (10), blocked inbound from a public address (6),
status check CRITICAL (12) / UNKNOWN (10) / WARNING (5).

## Other shippers

All tail `/var/log/portmaster/connections.json` (readable by root only; run the shipper with suitable rights).

Fluent Bit:
```ini
[INPUT]
    Name   tail
    Path   /var/log/portmaster/connections.json
    Tag    portmaster
    Parser json
[PARSER]
    Name        json
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S%z
```

Promtail / Grafana Alloy (Loki), Promtail syntax:
```yaml
scrape_configs:
  - job_name: portmaster
    static_configs:
      - targets: [localhost]
        labels: {job: portmaster, __path__: /var/log/portmaster/connections.json}
    pipeline_stages:
      - json:
          expressions: {verdict: verdict, direction: direction, app: app}
      - labels: {verdict:, direction:}
      - timestamp: {source: time, format: RFC3339}
```
(Keep high-cardinality fields such as `app` or `domain` out of labels. In Alloy use `loki.source.file` with `loki.process` and the same `stage.json` / `stage.labels` / `stage.timestamp`.)

Filebeat:
```yaml
filebeat.inputs:
  - type: filestream
    id: portmaster-connections
    paths: [/var/log/portmaster/connections.json]
    parsers:
      - ndjson:
          target: portmaster
          add_error_key: true
```

Graylog: ship with the Filebeat config above to a Beats input (JSON fields are extracted automatically),
or send GELF from Fluent Bit (`Name gelf`) to a GELF input.
