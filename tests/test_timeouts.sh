#!/usr/bin/env bash
#Mocks and globals are consumed by functions sourced from the application.
#shellcheck disable=SC2034,SC2329,SC2218
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#Sourcing must not launch the program, touch networking, or install signal traps.
traps_before=$(trap -p)
#shellcheck source=/dev/null
source ./airgeddon.sh
[[ $(trap -p) = "$traps_before" ]]

for value in '' 1 9 10 25 100 2400 39999 40000; do
	valid_timeout_seconds "$value" || { printf 'Rejected valid timeout: %s\n' "$value"; exit 1; }
done
#Keep hostile input literal.
#shellcheck disable=SC2016
for value in 0 00 01 40001 99999 100000 -1 +1 1.5 ' 1' '1 ' '1e2' '1;true' '$(true)' '999999999999999999999'; do
	if valid_timeout_seconds "$value"; then
		printf 'Accepted invalid timeout: %s\n' "$value"
		exit 1
	fi
done

#Replace UI functions. No network, subprocess capture or root access is needed.
debug_print() { :; }
language_strings() { :; }
read_timeout() {
	timeout=${mock_inputs[$mock_index]}
	mock_index=$((mock_index + 1))
}
contexts=(wps_standard wps_pixiedust capture_handshake_decloak capture_pmkid capture_identities certificates_analysis wpa3_downgrade wpa3_mfp_analysis)
variables=(timeout_secs_per_pin timeout_secs_per_pixiedust timeout_capture_handshake_decloak timeout_capture_pmkid timeout_capture_identities timeout_certificates_analysis timeout_wpa3_downgrade timeout_wpa3_mfp_analysis)
for i in "${!contexts[@]}"; do
	mock_inputs=(0 40001 40000)
	mock_index=0
	ask_timeout "${contexts[$i]}" > /dev/null
	variable=${variables[$i]}
	[[ ${!variable} = 40000 && $mock_index = 3 ]]
	mock_inputs=('')
	mock_index=0
	ask_timeout "${contexts[$i]}" > /dev/null
	[[ ${!variable} = 40000 ]]
	mock_inputs=(1)
	mock_index=0
	ask_timeout "${contexts[$i]}" > /dev/null
	[[ ${!variable} = 1 ]]
done
if ask_timeout unknown; then
	echo 'Unknown timeout context was accepted.'; exit 1
fi
read_timeout() { return 1; }
if ask_timeout wps_standard; then
	echo 'EOF did not cancel timeout input.'; exit 1
fi

#Recovery is opt-in, including when stdin is closed.
recovery_calls=0
personal_decrypt_menu() { recovery_calls=$((recovery_calls + 1)); }
offer_saved_capture_recovery <<< '' > /dev/null
[[ $recovery_calls = 0 ]]
offer_saved_capture_recovery <<< 'yes' > /dev/null
[[ $recovery_calls = 1 ]]
offer_saved_capture_recovery < /dev/null > /dev/null
[[ $recovery_calls = 1 ]]
#The capture save must succeed before a recovery handoff can be offered.
interruptible_capture_wait() { return 0; }
handshake_capture_check() { :; }
check_bssid_in_captured_file() { return 0; }
read_path() { enteredpath='/unused/authorized capture.cap'; validpath=0; }
cp() { return "${copy_status}"; }
offer_saved_capture_recovery() { recovery_calls=$((recovery_calls + 1)); }
AIRGEDDON_WINDOWS_HANDLING=tmux
sleeptimeattack=1
processidcapture=123
processidattack=124
return_to_handshake_pmkid_decloaking_tools_menu=0
bssid='00:11:22:33:44:55'
default_save_path=/unused/
tmpdir=/unused/
copy_status=1
recovery_calls=0
if launch_handshake_capture > /dev/null 2>&1; then
	echo 'Failed capture save was reported as success.'; exit 1
fi
[[ $recovery_calls = 0 ]]
copy_status=0
launch_handshake_capture > /dev/null
[[ $recovery_calls = 1 && $return_to_handshake_pmkid_decloaking_tools_menu = 1 ]]
printf '%s\n' 'PASS: timeouts, defaults, EOF, source safety, save failures and recovery consent'
