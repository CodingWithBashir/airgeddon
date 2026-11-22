#!/usr/bin/env bash
#Everything except temporary snapshot fixtures is mocked; no firewall command is run.
#shellcheck disable=SC2034,SC2329
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#shellcheck source=/dev/null
source ./airgeddon.sh
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
system_tmpdir="${tmp}/"
routing_tmp_file=snapshot
iptables_nftables=1
iptables_cmd=mockfw
calls=()
debug_print() { :; }
control_routing_status() { calls+=(forwarding); }
is_last_airgeddon_instance() { [[ ${last_instance:-1} = 1 ]]; }
clean_initialize_iptables_nftables() { calls+=(global_cleanup); }
clean_this_instance_iptables_nftables() { calls+=(instance_cleanup); }
restore_iptables_nftables() { calls+=(restore); return "${restore_status:-0}"; }
mockfw() { [[ $1 = --check && $2 = -f ]]; calls+=(validate); return "${validation_status:-0}"; }
mockfw-restore() { [[ $# = 1 && $1 = --test ]]; calls+=(validate); return "${validation_status:-0}"; }

for iptables_nftables in 1 0; do
	calls=()
	printf 'mock snapshot' > "$tmp/snapshot"
	clean_routing_rules
	[[ ${calls[*]} = 'forwarding validate global_cleanup restore' && ! -e $tmp/snapshot ]]
done
calls=()
printf 'mock snapshot' > "$tmp/snapshot"
restore_status=1
if clean_routing_rules 2> /dev/null; then exit 1; fi
[[ -s $tmp/snapshot && ${calls[*]} = 'forwarding validate global_cleanup restore' ]]
restore_status=0
validation_status=1
calls=()
if clean_routing_rules 2> /dev/null; then exit 1; fi
[[ -s $tmp/snapshot && ${calls[*]} = 'forwarding validate instance_cleanup' ]]
validation_status=0
for bad in missing empty symlink; do
	calls=()
	routing_tmp_file=$bad
	case $bad in empty) : > "$tmp/empty" ;; symlink) ln -s "$tmp/snapshot" "$tmp/symlink" ;; esac
	if clean_routing_rules 2> /dev/null; then exit 1; fi
	[[ ${calls[*]} = 'forwarding instance_cleanup' ]]
done
last_instance=0
calls=()
clean_routing_rules
[[ ${calls[*]} = 'forwarding instance_cleanup' && -s $tmp/snapshot ]]
printf '%s\n' 'PASS: firewall validation before global cleanup, failure snapshot retention and instance-only fallback'
