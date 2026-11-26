#!/usr/bin/env bash
# Integration smoke test of portmaster-core on Linux. Runs inside the test VM
# as root (see test-linux.sh):
#
#   sudo bash smoke.sh ./portmaster-core
#
# Starts the real service with packet interception and checks that it
# intercepts and filters traffic, answers its API, shuts down cleanly and that
# a crashed instance can be recovered. Exits non-zero if any check fails.
set -uo pipefail

CORE="$(realpath "${1:?usage: smoke.sh PORTMASTER_CORE}")"
WORK=/tmp/pm-smoke
DATA="$WORK/data"
LOG="$WORK/core.log"
API=http://127.0.0.1:817/api/v1
ALLOWED=example.com
BLOCKED=example.org
# A name whose CNAME points outside the blocked zone (safing/portmaster#2306).
CNAME_BLOCKED=tr.archive.ubuntu.com
CNAME_ZONE=ubuntu.com
# A tracker on the default filter lists.
TRACKER=doubleclick.net

failures=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; ((failures++)); }
check() { # check DESCRIPTION COMMAND...
	local desc="$1"
	shift
	if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
step() { printf '\n== %s\n' "$*"; }

rules_present() { iptables-save 2>/dev/null | grep -q PORTMASTER || ip6tables-save 2>/dev/null | grep -q PORTMASTER; }
https_ok() { curl -sS -o /dev/null --max-time 15 "https://$1/"; }
http_ok() { curl -sS -o /dev/null --max-time 15 "http://$1/"; }
resolves() { getent ahostsv4 "$1" | grep -qv '^0\.0\.0\.0'; }
api_ready() { curl -sf --max-time 5 "$API/ready"; }
core_pid=""

start_core() {
	"$CORE" --data-dir "$DATA" --log-stdout --log info \
		--allowed-clients "$(realpath "$(command -v curl)")" \
		--allowed-clients "$CORE" >>"$LOG" 2>&1 &
	core_pid=$!
	local waited=0
	until api_ready >/dev/null 2>&1; do
		sleep 2
		((waited += 2))
		((waited % 30 == 0)) && echo "  waiting for portmaster-core (${waited}s): $(tail -1 "$LOG" | cut -c1-120)"
		if ! kill -0 "$core_pid" 2>/dev/null; then
			echo "portmaster-core exited during start; last log lines:"
			tail -30 "$LOG"
			return 1
		fi
		if ((waited >= 300)); then
			echo "portmaster-core not ready after ${waited}s; last log lines:"
			tail -30 "$LOG"
			return 1
		fi
	done
	echo "  portmaster-core ready after ${waited}s (pid $core_pid)"
}

netquery_count() { # netquery_count DOMAIN
	curl -sf --max-time 10 -X POST "$API/netquery/query" -H 'Content-Type: application/json' \
		-d "{\"query\":{\"domain\":{\"\$like\":\"%$1%\"}},\"select\":[\"id\",\"verdict\"],\"pageSize\":50}" |
		jq '.results | length'
}

rm -rf "$WORK" && mkdir -p "$DATA"

step "Before start"
check "no Portmaster rules installed" bash -c '! { iptables-save | grep -q PORTMASTER; }'
check "https://$ALLOWED reachable" https_ok "$ALLOWED"
check "http://$CNAME_BLOCKED reachable" http_ok "$CNAME_BLOCKED"

# Block one domain and allow incoming SSH (the test is controlled over SSH)
# in the global settings.
write_config() {
	printf '{"filter":{"endpoints":[%s],"serviceEndpoints":["+ * TCP/22"]}}\n' "$1" >"$DATA/config.json"
}
write_config "\"- $BLOCKED\",\"- .$CNAME_ZONE\""

step "Boot guard"
# portmaster-boot-guard.service runs this before the network is configured.
check "boot guard is set" "$CORE" boot-guard
check "boot guard blocks the network" bash -c "! curl -sS -o /dev/null --max-time 5 https://$ALLOWED/"
check "boot guard allows loopback" bash -c "python3 -m http.server -b 127.0.0.1 18999 >/dev/null 2>&1 & p=\$!; sleep 1; curl -s -o /dev/null --max-time 5 http://127.0.0.1:18999/; rc=\$?; kill \$p; exit \$rc"

step "Start"
if ! start_core; then
	fail "portmaster-core starts and reports ready"
	exit 1
fi
pass "portmaster-core starts and reports ready"
check "interception rules installed" rules_present
check "the core removed the boot guard" bash -c '! { iptables-save; ip6tables-save; } | grep -q PORTMASTER-BOOT'
check "nfqueue bound" bash -c 'grep -q . /proc/net/netfilter/nfnetlink_queue'
check "systemd-resolved cache flushed" grep -q 'flushed the systemd-resolved cache' "$LOG"

step "Filtering"
check "$ALLOWED resolves" resolves "$ALLOWED"
check "https://$ALLOWED reachable" https_ok "$ALLOWED"
# Fedora resolves names through systemd-resolved, so the per-app rule applies
# to the connection, not to the DNS query.
echo "  info: $BLOCKED resolves through systemd-resolved: $(resolves "$BLOCKED" && echo yes || echo no)"
check "https://$BLOCKED is blocked" bash -c "! curl -sS -o /dev/null --max-time 10 https://$BLOCKED/"
check "http://$CNAME_BLOCKED is blocked by the rule for .$CNAME_ZONE (CNAME outside the zone)" bash -c "! curl -sS -o /dev/null --max-time 10 http://$CNAME_BLOCKED/"
# A blocked connection must fail at once, not by timeout (safing/portmaster#1981).
block_start=$(date +%s%N)
curl -sS -o /dev/null --max-time 40 "http://$CNAME_BLOCKED/" >/dev/null 2>&1
block_rc=$?
block_ms=$((($(date +%s%N) - block_start) / 1000000))
check "a blocked connection fails at once, not by timeout (${block_ms}ms, curl exit code $block_rc)" test "$block_rc" -ne 0 -a "$block_ms" -lt 5000
check "Portmaster nameserver answers" bash -c "dig +short +time=5 +tries=1 $ALLOWED @127.0.0.1 | grep -q ."

step "Forwarded traffic"
# A network namespace behind NAT stands for a VM or container: its traffic
# passes the FORWARD chain of the host.
guest() { nsenter --net=/run/netns/pmguest "$@"; }
ip netns add pmguest
ip link add pmfwd0 type veth peer name pmfwd1
ip link set pmfwd1 netns pmguest
ip addr add 10.77.0.1/24 dev pmfwd0
ip link set pmfwd0 up
guest ip addr add 10.77.0.2/24 dev pmfwd1
guest ip link set pmfwd1 up
guest ip link set lo up
guest ip route add default via 10.77.0.1
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -j MASQUERADE
# The guest does not resolve names itself; the host resolved both names
# above, so the Portmaster knows the domains of their IPs.
allowed_ip=$(getent ahostsv4 "$ALLOWED" | awk 'NR==1 {print $1}')
blocked_ip=$(getent ahostsv4 "$BLOCKED" | awk 'NR==1 {print $1}')
check "forwarded https://$ALLOWED reachable" guest curl -sS -o /dev/null --max-time 15 --resolve "$ALLOWED:443:$allowed_ip" "https://$ALLOWED/"
check "forwarded https://$BLOCKED is blocked" bash -c "! nsenter --net=/run/netns/pmguest curl -sS -o /dev/null --max-time 10 --resolve $BLOCKED:443:$blocked_ip https://$BLOCKED/"
check "the forwarded connection is attributed to Forwarded Traffic" bash -c "for i in 1 2 3 4 5; do grep -q 'Forwarded:.*$BLOCKED.*blocked' '$LOG' && exit 0; sleep 1; done; exit 1"
# Software like Docker accepts forwarded packets before the Portmaster rules
# in the filter table; blocks must still apply.
iptables -I FORWARD 1 -j ACCEPT
check "forwarded block holds with an ACCEPT rule before the Portmaster" bash -c "! nsenter --net=/run/netns/pmguest curl -sS -o /dev/null --max-time 10 --resolve $BLOCKED:443:$blocked_ip https://$BLOCKED/"
check "forwarded https://$ALLOWED still reachable" guest curl -sS -o /dev/null --max-time 15 --resolve "$ALLOWED:443:$allowed_ip" "https://$ALLOWED/"
iptables -D FORWARD 1
sleep 3 # let netquery save the connections
n=$(curl -sf --max-time 10 -X POST "$API/netquery/query" -H 'Content-Type: application/json' \
	-d '{"query":{"profile":{"$like":"%_forwarded"}},"select":["id"],"pageSize":50}' | jq '.results | length' 2>/dev/null || echo 0)
if [[ "$n" =~ ^[0-9]+$ ]] && ((n > 0)); then pass "netquery lists forwarded connections ($n)"; else fail "netquery lists forwarded connections (got '$n')"; fi

step "Filter lists"
# Downloading, decoding and storing the lists covers the intel updater, the
# list decoder and the SQLite cache database.
waited=0
until grep -q 'rebuilt bloom filters' "$LOG" || ((waited >= 240)); do
	sleep 5
	((waited += 5))
done
check "filter lists loaded (${waited}s)" grep -q 'rebuilt bloom filters' "$LOG"
check "https://$TRACKER is blocked by the filter lists" bash -c "! curl -sS -o /dev/null --max-time 10 https://$TRACKER/"
# The block is logged by the nameserver or the filter, whichever sees it
# first, and the log is written asynchronously.
check "the block names the filter lists" bash -c "for i in 1 2 3 4 5; do grep -q '$TRACKER\\. in activated lists' '$LOG' && exit 0; sleep 1; done; exit 1"

step "API"
check "ping endpoint" curl -sf --max-time 5 "$API/ping"
sleep 3 # let netquery save the connections
n=$(netquery_count "$ALLOWED" 2>/dev/null || echo 0)
if [[ "$n" =~ ^[0-9]+$ ]] && ((n > 0)); then pass "netquery lists connections to $ALLOWED ($n)"; else fail "netquery lists connections to $ALLOWED (got '$n')"; fi
code=$(python3 -c "
import urllib.request, urllib.error
req = urllib.request.Request('$API/netquery/query', data=b'{}', method='POST')
try:
    print(urllib.request.urlopen(req, timeout=10).status)
except urllib.error.HTTPError as e:
    print(e.code)
" 2>/dev/null)
if [[ "$code" == 403 || "$code" == 401 ]]; then pass "API denies an unauthorized local client ($code)"; else fail "API denies an unauthorized local client (got '$code')"; fi
# app/auth identifies the calling process and waits for the user to answer
# the prompt; without the process (safing/portmaster#2302 B1) it fails at once.
auth_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API/app/auth?app-name=vmtest&read=user&write=user&ttl=1h")
if [[ "$auth_code" == 000 ]]; then pass "app/auth identifies the caller and waits for the prompt"; else fail "app/auth identifies the caller and waits for the prompt (got HTTP $auth_code)"; fi

step "Settings sync"
# The settings and profile commands of portmaster-core, used by Ansible and
# RMM tools. The test binary is not in /usr/lib/portmaster, so it is allowed
# by --allowed-clients; a copy elsewhere must be denied.
check "settings export (json)" bash -c "'$CORE' settings export --format json -o '$WORK/settings.json' && jq -e '.type == \"settings\"' '$WORK/settings.json'"
printf 'type: settings\nconfig:\n  filter:\n    askTimeout: 33\n' >"$WORK/import.yaml"
check "settings import --validate leaves the value" bash -c "'$CORE' settings import --validate '$WORK/import.yaml' && ! '$CORE' settings export --format json --key filter/askTimeout | jq -e '.config.filter.askTimeout == 33'"
check "settings import sets the value" bash -c "'$CORE' settings import '$WORK/import.yaml' && '$CORE' settings export --format json --key filter/askTimeout | jq -e '.config.filter.askTimeout == 33'"
check "settings import without --reset keeps other settings" bash -c "printf 'type: settings\nconfig:\n  filter:\n    askWithSystemNotifications: false\n' | '$CORE' settings import - && '$CORE' settings export --format json | jq -e '.config.filter.askTimeout == 33 and .config.filter.askWithSystemNotifications == false'"
check "settings import from stdin (json)" bash -c "echo '{\"type\":\"settings\",\"config\":{\"filter\":{\"askTimeout\":44}}}' | '$CORE' settings import - && '$CORE' settings export --key filter/askTimeout | grep -q 'askTimeout: 44'"
check "settings import rejects unknown keys" bash -c "! printf 'type: settings\nconfig:\n  nope:\n    nothing: 1\n' | '$CORE' settings import -"
check "settings import --reset restores the default" bash -c "'$CORE' settings import --reset '$WORK/settings.json' && ! '$CORE' settings export --format json --key filter/askTimeout | jq -e '.config.filter.askTimeout == 44'"
check "profile export of a special profile" bash -c "'$CORE' profile export local/_forwarded --format json | jq -e '.type == \"profile\"'"
cp "$CORE" "$WORK/other-core"
check "a copy outside the allowed paths is denied" bash -c "! '$WORK/other-core' settings export"

step "Status"
check "status reports ready and interception active" bash -c "'$CORE' status | jq -e '.ready and .interception and .filtering and (.problems | type == \"array\")'"
status_line=$("$CORE" status --check --max-intel-age 0)
status_rc=$?
echo "  $status_line"
if [[ $status_rc -le 1 && "$status_line" =~ ^(OK|WARNING): ]]; then pass "status --check is OK or WARNING (rc $status_rc)"; else fail "status --check is OK or WARNING (rc $status_rc)"; fi

step "Rule order"
# Software like Docker or a VPN client inserts its rules at the top of the
# chains later on; the core must move its jump rules back.
iptables -I OUTPUT 1 -m comment --comment pm-smoke -j ACCEPT
waited=0
until iptables -S OUTPUT | sed -n 2p | grep -q PORTMASTER-FILTER || ((waited >= 90)); do
	sleep 5
	((waited += 5))
done
check "jump rule moved back to the top of filter OUTPUT (${waited}s)" bash -c "iptables -S OUTPUT | sed -n 2p | grep -q PORTMASTER-FILTER"
iptables -D OUTPUT -m comment --comment pm-smoke -j ACCEPT

step "Load"
load_pids=()
for i in $(seq 1 40); do
	curl -s -o /dev/null --max-time 10 "https://$ALLOWED/?n=$i" &
	load_pids+=($!)
done
wait "${load_pids[@]}" # not "wait" alone, which would wait for portmaster-core
check "service alive after 40 parallel connections" kill -0 "$core_pid"
check "https://$ALLOWED still reachable" https_ok "$ALLOWED"

step "Bandwidth"
# Several requests over one kept-alive connection, so that the connection
# is open long enough for the eBPF bandwidth monitor to sample it.
curl -s -o /dev/null --max-time 20 --rate 2/s "https://$ALLOWED/?bw=[1-8]" || true
sleep 3 # let the bandwidth updates reach netquery
bw=$(curl -sf --max-time 10 -X POST "$API/netquery/query" -H 'Content-Type: application/json' \
	-d "{\"query\":{\"domain\":{\"\$like\":\"%$ALLOWED%\"}},\"select\":[\"bytes_received\",\"bytes_sent\"],\"pageSize\":100}" |
	jq '[.results[] | (.bytes_received // 0) + (.bytes_sent // 0)] | add // 0' 2>/dev/null || echo 0)
if [[ "$bw" =~ ^[0-9]+$ ]] && ((bw > 0)); then pass "eBPF bandwidth data recorded ($bw bytes)"; else fail "eBPF bandwidth data recorded (got '$bw')"; fi

step "Shutdown"
kill -TERM "$core_pid"
stopped=0
for _ in $(seq 1 60); do
	if ! kill -0 "$core_pid" 2>/dev/null; then stopped=1; break; fi
	sleep 1
done
if ((stopped)); then pass "portmaster-core stops within 60s"; else fail "portmaster-core stops within 60s"; kill -9 "$core_pid"; fi
wait "$core_pid" 2>/dev/null
rc=$?
if ((rc == 0)); then pass "exit code 0"; else fail "exit code $rc"; fi
check "interception rules removed" bash -c '! { iptables-save | grep -q PORTMASTER; }'
check "https://$ALLOWED reachable without Portmaster" https_ok "$ALLOWED"
"$CORE" status --check >/dev/null 2>&1
rc=$?
if ((rc == 3)); then pass "status --check is UNKNOWN when stopped"; else fail "status --check is UNKNOWN when stopped (rc $rc)"; fi

step "Crash recovery"
write_config ""
if start_core; then
	kill -9 "$core_pid"
	wait "$core_pid" 2>/dev/null
	if rules_present; then
		echo "  info: rules remain after a crash; reachable meanwhile: $(https_ok "$ALLOWED" && echo yes || echo no)"
		check "forwarded traffic is blocked while the core is down" bash -c "! nsenter --net=/run/netns/pmguest curl -sS -o /dev/null --max-time 10 --resolve $ALLOWED:443:$allowed_ip https://$ALLOWED/"
	else
		echo "  info: no rules left after a crash"
	fi
	"$CORE" boot-guard >>"$LOG" 2>&1
	"$CORE" recover-iptables >>"$LOG" 2>&1
	check "recover-iptables removes the rules and the boot guard" bash -c '! { iptables-save; ip6tables-save; } | grep -q PORTMASTER'
	check "https://$ALLOWED reachable after recovery" https_ok "$ALLOWED"
else
	fail "portmaster-core restarts with existing data"
fi

step "Log"
panics=$(grep -c -E '^panic:|fatal error:|DATA RACE' "$LOG" || true)
if ((panics == 0)); then pass "no panics in the log"; else fail "$panics panics in the log"; fi
errors=$(grep -cE ' (ERR|CRT) ' "$LOG" || true)
echo "  log: $(wc -l <"$LOG") lines"
if ((errors == 0)); then
	pass "no errors in the log"
else
	fail "$errors errors in the log"
	grep -E ' (ERR|CRT) ' "$LOG" | head -10 | cut -c1-200
fi

if ((failures > 0)); then
	echo "  last log lines:"
	tail -40 "$LOG" | sed 's/^/    /'
fi
echo
if ((failures == 0)); then echo "SMOKE TEST PASSED"; else echo "SMOKE TEST FAILED: $failures checks"; fi
((failures == 0))
