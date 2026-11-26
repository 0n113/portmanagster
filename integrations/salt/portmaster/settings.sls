{#- Render pillar portmaster:settings to a managed file and import it
    (merge) whenever the file changes. Set portmaster:settings_reset: True
    to replace all settings instead of merging. -#}
{%- set pm = salt['pillar.get']('portmaster', {}) %}
{%- set core = pm.get('core_path', '/usr/lib/portmaster/portmaster-core') %}
{%- set file = '/etc/portmaster/managed-settings.yaml' %}
{%- set settings = pm.get('settings', {}) %}

{%- if settings %}
portmaster-managed-settings:
  file.managed:
    - name: {{ file }}
    - user: root
    - group: root
    - mode: '0600'
    - makedirs: True
    - dir_mode: '0755'
    - contents: |
        type: settings
        config: {{ settings | json }}
    - require:
        - service: portmaster-service

portmaster-import-settings:
  cmd.run:
    - name: {{ core }} settings import {{ file }} --validate && {{ core }} settings import {{ file }}{% if pm.get('settings_reset', False) %} --reset{% endif %}
    - onchanges:
      - file: portmaster-managed-settings
    - require:
      - service: portmaster-service
{%- endif %}
