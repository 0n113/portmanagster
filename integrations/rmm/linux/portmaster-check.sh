#!/bin/sh
# Portmaster health check wrapper. Exit: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
# Env: CORE (binary path), MAX_INTEL_AGE (default 336h)
CORE="${CORE:-/usr/lib/portmaster/portmaster-core}"
MAX_INTEL_AGE="${MAX_INTEL_AGE:-336h}"

if [ ! -x "$CORE" ]; then
    echo "UNKNOWN - portmaster-core not found at $CORE"
    exit 3
fi

"$CORE" status --check --max-intel-age "$MAX_INTEL_AGE"
exit $?
