#!/bin/sh
# Export Portmaster settings to DIR/portmaster-settings-<host>-<date>.yaml, keep the last KEEP (default 14).
# Usage: portmaster-backup.sh DIR
CORE="${CORE:-/usr/lib/portmaster/portmaster-core}"
KEEP="${KEEP:-14}"
DIR="$1"

if [ -z "$DIR" ]; then
    echo "usage: $0 DIR" >&2
    exit 2
fi
if [ ! -x "$CORE" ]; then
    echo "portmaster-core not found at $CORE" >&2
    exit 3
fi
case "$KEEP" in
    ''|*[!0-9]*) echo "KEEP must be a number" >&2; exit 2 ;;
esac

umask 077
mkdir -p "$DIR" || exit 1
host=$(hostname 2>/dev/null || echo unknown)
out="$DIR/portmaster-settings-$host-$(date +%Y%m%d-%H%M%S).yaml"

if ! "$CORE" settings export --format yaml -o "$out"; then
    echo "export failed" >&2
    rm -f "$out"
    exit 1
fi
echo "wrote $out"

# prune: names sort chronologically
n=0
for f in $(ls -1 "$DIR"/portmaster-settings-"$host"-*.yaml 2>/dev/null | sort -r); do
    n=$((n + 1))
    [ "$n" -gt "$KEEP" ] && rm -f "$f"
done
exit 0
