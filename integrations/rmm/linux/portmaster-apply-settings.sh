#!/bin/sh
# Validate and import a Portmaster settings file (merge). Usage: portmaster-apply-settings.sh FILE
# Env: CORE, RESET=1 to replace all settings instead of merging
CORE="${CORE:-/usr/lib/portmaster/portmaster-core}"
FILE="$1"

if [ -z "$FILE" ] || [ ! -r "$FILE" ]; then
    echo "usage: $0 FILE (readable settings file)" >&2
    exit 2
fi
if [ ! -x "$CORE" ]; then
    echo "portmaster-core not found at $CORE" >&2
    exit 3
fi

if ! "$CORE" settings import "$FILE" --validate; then
    echo "validation failed, nothing imported" >&2
    exit 1
fi

if [ "${RESET:-0}" = "1" ]; then
    "$CORE" settings import "$FILE" --reset
else
    "$CORE" settings import "$FILE"
fi
rc=$?
[ "$rc" -eq 0 ] || echo "import failed (exit $rc)" >&2
exit "$rc"
