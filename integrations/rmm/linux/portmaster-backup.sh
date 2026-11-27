#!/bin/sh
# Back up the Portmaster settings and all local app profiles to
# DIR/portmaster-backup-<host>-<date>/ (portmaster-core backup create), keep the last KEEP (default 14).
# Restore: portmaster-core backup restore DIR/portmaster-backup-<host>-<date>
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
out="$DIR/portmaster-backup-$host-$(date +%Y%m%d-%H%M%S)"

# A failed profile export still writes the backup (exit 1 names the profile);
# a backup without manifest was not written at all.
"$CORE" backup create "$out"
rc=$?
if [ ! -f "$out/manifest.json" ]; then
    echo "backup failed" >&2
    exit 1
fi

# prune: names sort chronologically
n=0
for d in $(ls -1d "$DIR"/portmaster-backup-"$host"-* 2>/dev/null | sort -r); do
    n=$((n + 1))
    [ "$n" -gt "$KEEP" ] && rm -rf "$d"
done
exit $rc
