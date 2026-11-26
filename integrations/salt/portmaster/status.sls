{#- Health check. Retcode 0 (OK) and 1 (WARNING) are treated as success;
    2 (CRITICAL) and 3 (UNKNOWN) fail the state. -#}
{%- set pm = salt['pillar.get']('portmaster', {}) %}
{%- set core = pm.get('core_path', '/usr/lib/portmaster/portmaster-core') %}

portmaster-status-check:
  cmd.run:
    - name: {{ core }} status --check --max-intel-age {{ pm.get('max_intel_age', '336h') }}
    - success_retcodes: [0, 1]
    - require:
      - service: portmaster-service
