#!/usr/bin/env bash
#Application state and restoration functions are mocked, never host networking.
#shellcheck disable=SC2034,SC2329
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#shellcheck source=/dev/null
source ./airgeddon.sh
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
calls=()
clean_routing_rules() { calls+=(routing); return 1; }
clean_this_instance_iptables_nftables() { calls+=(instance_rules); }
control_routing_status() { calls+=(forwarding); }
mock_airmon() { calls+=(monitor); }
restore_spoofed_macs() { calls+=(mac); }
is_last_airgeddon_instance() { [[ ${last_instance:-1} = 1 ]]; }
mock_nm() { calls+=(network_manager); }
clean_tmpfiles() { calls+=(temporary_files); }
kill_pid_and_children_recursive() { calls+=(unexpected_kill); }

#Not armed during partial startup or lab CLI operations.
emergency_exit_cleanup
[[ ${#calls[@]} = 0 ]]
airgeddon_cleanup_ready=1
airgeddon_cleanup_complete=0
routing_modified=1
system_tmpdir="${tmp}/"
routing_tmp_file=snapshot
printf 'mock snapshot' > "$tmp/snapshot"
airgeddon_instance_name=ag123
ifacemode=Monitor
interface=mock0
airmon=mock_airmon
spoofed_mac=1
nm_processes_killed=1
networkmanager_cmd=mock_nm
tmpdir="${tmp}/"  #not a recognized instance path: never recursively removed
et_processes=(0 1 abc)
emergency_exit_cleanup 2> "$tmp/warnings"
[[ ${calls[*]} = 'routing monitor mac network_manager' ]]
grep -q 'Routing restoration reported a failure' "$tmp/warnings"
#Failure in one step does not prevent subsequent recovery steps or cause double cleanup.
emergency_exit_cleanup
[[ ${calls[*]} = 'routing monitor mac network_manager' ]]

#Missing/untrusted snapshots must not trigger global firewall restoration or flushing.
for snapshot in missing symlink; do
	airgeddon_cleanup_complete=0
	calls=()
	routing_tmp_file=$snapshot
	if [[ $snapshot = symlink ]]; then ln -s "$tmp/snapshot" "$tmp/symlink"; fi
	ifacemode=Managed
	spoofed_mac=0
	nm_processes_killed=0
	emergency_exit_cleanup 2> /dev/null
	[[ ${calls[*]} = 'instance_rules forwarding' ]]
done
#Never restart NetworkManager while another registered session still needs it stopped.
airgeddon_cleanup_complete=0
calls=()
routing_modified=0
nm_processes_killed=1
last_instance=0
emergency_exit_cleanup 2> /dev/null
[[ ${#calls[@]} = 0 ]]

#Exercise actual shell traps in isolated child shells, not in the test runner.
set +e
bash -c 'source ./airgeddon.sh; airgeddon_cleanup_ready=1; trap '\''emergency_exit_handler "$?"'\'' EXIT; exit 7' 2> "$tmp/exit"
status=$?
set -e
[[ $status = 7 ]]
[[ $(grep -c 'Emergency cleanup:' "$tmp/exit") = 1 ]]
set +e
bash -c 'source ./airgeddon.sh; airgeddon_cleanup_ready=1; trap emergency_term_handler TERM; trap '\''emergency_exit_handler "$?"'\'' EXIT; kill -TERM "$BASHPID"; exit 99' 2> "$tmp/term"
status=$?
set -e
[[ $status = 143 ]]
[[ $(grep -c 'Emergency cleanup:' "$tmp/term") = 1 ]]
printf '%s\n' 'PASS: guarded emergency cleanup, failure continuation, snapshot safety, multiple sessions, TERM and EXIT status'
