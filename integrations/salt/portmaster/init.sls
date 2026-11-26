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

include:
  - .settings
  - .status
