{#- Install Portmaster (fork) and keep the service running.
    Pillar (optional):
      portmaster:
        pkg_name: portmaster            # package name
        source: salt://files/portmaster.rpm   # optional: local package file / URL
        source_hash: sha256=...         # recommended with source
-#}
{%- set pm = salt['pillar.get']('portmaster', {}) %}
{%- set pkg_name = pm.get('pkg_name', 'portmaster') %}

portmaster-pkg:
  pkg.installed:
    - name: {{ pkg_name }}
{%- if pm.get('source') %}
    - sources:
      - {{ pkg_name }}: {{ pm['source'] }}
{%- if pm.get('source_hash') %}
    - source_hash: {{ pm['source_hash'] }}
{%- endif %}
{%- endif %}

portmaster-service:
  service.running:
    - name: portmaster
    - enable: True
    - require:
      - pkg: portmaster-pkg

# The core needs some seconds after the start until its API answers and it is
# ready; the settings import and the status check need that.
portmaster-ready:
  cmd.run:
    - name: |
        for i in $(seq 1 90); do
          {{ pm.get('core_path', '/usr/lib/portmaster/portmaster-core') }} status 2>/dev/null | grep -q '"ready":true' && exit 0
          sleep 2
        done
        echo "Portmaster is not ready after 180s"
        exit 1
    - require:
      - service: portmaster-service
    - unless: {{ pm.get('core_path', '/usr/lib/portmaster/portmaster-core') }} status 2>/dev/null | grep -q '"ready":true'

include:
  - .settings
  - .status
