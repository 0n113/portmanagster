#!/bin/bash
# Checks portmaster_rules.xml with wazuh-logtest in a Wazuh manager container (podman or docker).
# Usage: integrations/siem/wazuh/test/test-rules.sh [image]
# events.tsv: expected rule ID <TAB> log line. Also checks the frequency rule 100804.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="${1:-docker.io/wazuh/wazuh-manager:4.14.1}"
ctr="$(command -v podman || command -v docker)"
name="pm-wazuh-test-$$"

cleanup() { "$ctr" rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$ctr" run -d --name "$name" "$image" >/dev/null
for _ in $(seq 1 60); do
	"$ctr" exec "$name" pgrep -x wazuh-analysisd >/dev/null 2>&1 && break
	sleep 3
done
"$ctr" cp "$here/../portmaster_rules.xml" "$name:/var/ossec/etc/rules/portmaster_rules.xml"
"$ctr" exec "$name" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
for _ in $(seq 1 30); do
	"$ctr" exec "$name" sh -c 'echo test | /var/ossec/bin/wazuh-logtest' >/dev/null 2>&1 && break
	sleep 2
done

logtest() { "$ctr" exec -i "$name" /var/ossec/bin/wazuh-logtest 2>&1; }
rule_of() { printf '%s\n' "$1" | logtest | sed -n '/Phase 3/,$p' | sed -n "s/^\s*id: '\([0-9]*\)'.*/\1/p" | head -1; }

fail=0
while IFS=$'\t' read -r want line; do
	got="$(rule_of "$line")"
	if [[ "$got" == "$want" ]]; then
		echo "PASS $want ${line:0:70}"
	else
		echo "FAIL want $want got ${got:-none}: ${line:0:70}"
		fail=1
	fi
done < "$here/events.tsv"

# 21 blocked connections of one app in one session must trigger 100804 once.
burst="$(for i in $(seq 1 21); do
	printf '{"time":"2026-01-01T00:00:%02dZ","host":"h","id":"b%d","verdict":"blocked","reason":"outgoing connections blocked","direction":"outbound","app":"burst","protocol":6,"remoteIP":"5.6.7.%d"}\n' "$i" "$i" "$i"
done | logtest | grep -c "id: '100804'" || true)"
if [[ "$burst" == 1 ]]; then echo "PASS 100804 frequency"; else echo "FAIL 100804 fired $burst times"; fail=1; fi

[[ $fail == 0 ]] && echo "ALL RULE TESTS PASSED"
exit $fail
