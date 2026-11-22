#!/usr/bin/env bash
#Application globals and mocks are used indirectly by the sourced workflow.
#shellcheck disable=SC2034,SC2329
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#shellcheck source=/dev/null
source ./airgeddon.sh
#shellcheck source=scripts/dragon_status.sh
source scripts/dragon_status.sh

AIRGEDDON_DRAGON_UI=on
output=$(dragon_status_preview)
[[ $output = *'PREVIEW ONLY'* && $output = *'Initialization of portals'* ]]
[[ $output = *'DRAGON STATUS CONSOLE'* && $output != *$'\033'* ]]
[[ $output = *'not verified service readiness'* ]]
for AIRGEDDON_DRAGON_UI in off false 0; do
	[[ -z $(dragon_status_banner) ]]
	[[ -z $(dragon_status_line STAGE 'Should not be visible') ]]
done
AIRGEDDON_DRAGON_UI=on
NO_COLOR=''
[[ $(dragon_status_line STAGE 'plain output') != *$'\033'* ]]
unset NO_COLOR
[[ $(dragon_status_line INVALID 'literal %s text') = '[DRAGON / INFO] literal %s text' ]]

#The cosmetic integration must preserve the original operational call sequence.
#All service/network functions are mocks: no wireless operation or service is launched.
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
scriptfolder="${PWD}/"
tmpdir="${tmp}/"
webdir='portal/'
dos_pursuit_mode=0
calls=()
debug_print() { :; }
set_hostapd_config() { calls+=(hostapd_config); }
launch_fake_ap() { calls+=(ap); }
set_network_interface_data() { calls+=(interface); }
set_dhcp_config() { calls+=(dhcp_config); }
set_std_internet_routing_rules() { calls+=(routing); }
launch_dhcp_server() { calls+=(dhcp); }
exec_et_deauth() { calls+=(existing_control); }
set_et_control_script() { calls+=(control_script); }
launch_et_control_window() { calls+=(control_window); }
launch_dns_blackhole() { calls+=(dns); }
set_webserver_config() { calls+=(web_config); }
set_captive_portal_page() { calls+=(page); }
launch_webserver() { calls+=(web); }
write_et_processes() { calls+=(processes); }
language_strings() { :; }
kill_et_windows() { calls+=(stop); }
restore_et_interface() { calls+=(restore); }
clean_tmpfiles() { calls+=(cleanup); }
expected='hostapd_config ap interface dhcp_config routing dhcp existing_control control_script control_window dns web_config page web processes stop restore cleanup'
exec_et_captive_portal_attack > "$tmp/output"
[[ ${calls[*]} = "$expected" ]]
grep -q 'Initialization of portals' "$tmp/output"
grep -q 'Check the control window and service logs' "$tmp/output"

#Disabled UI still executes exactly the same mocked workflow, without dragon output.
AIRGEDDON_DRAGON_UI=off
calls=()
exec_et_captive_portal_attack > "$tmp/output"
[[ ${calls[*]} = "$expected" ]]
if grep -q DRAGON "$tmp/output"; then
	echo 'Disabled theme emitted dragon output.'; exit 1
fi
#CLI preview must remain independent of root, graphics and hardware.
bash airgeddon.sh --lab dragon > "$tmp/preview"
grep -q 'PREVIEW ONLY' "$tmp/preview"
printf '%s\n' 'PASS: dragon preview, plain output, opt-out and unchanged mocked workflow sequence'
