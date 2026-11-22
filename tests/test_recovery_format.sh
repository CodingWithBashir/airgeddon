#!/usr/bin/env bash
#All recovery/conversion commands are mocks; never tests actual credentials/radios.
#Globals and mocks are consumed by the sourced application and helper module.
#Dollar expressions below are intentional literal injection-test inputs.
#shellcheck disable=SC2034,SC2329,SC2016
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#shellcheck source=/dev/null
source ./airgeddon.sh
#shellcheck source=scripts/recovery_format.sh
source scripts/recovery_format.sh
scriptfolder="${PWD}/"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
export FORMAT_TEST_DIR=$tmp

airgeddon_parse_recovery_format '{OC43DE32}'
[[ $recovery_format_mask = '?u?u?d?d?u?u?d?d' && $recovery_format_crunch = ',,%%,,%%' ]]
[[ $recovery_format_length = 8 && $recovery_format_keyspace = 4569760000 && $recovery_format_capped = 0 ]]
airgeddon_parse_recovery_format '{abcd1234}'
[[ $recovery_format_mask = '?l?l?l?l?d?d?d?d' && $recovery_format_crunch = '@@@@%%%%' ]]
airgeddon_parse_recovery_format "{$(printf 'A%.0s' {1..63})}"
[[ $recovery_format_length = 63 && $recovery_format_capped = 1 && $recovery_format_keyspace = 1000000000000000000 ]]
for bad in '' '{}' '{1234567}' '{1234567890123456789012345678901234567890123456789012345678901234}' \
	'OC43DE32' '{{OC43DE32}}' '{OC43 DE32}' '{OC43DE3!}' '{éC43DE32}' \
	'{?u?u?d?d}' '{ABCDEFGH;touch BAD}' '{$(touch BAD)}' $'{ABCD12\n34}'; do
	if airgeddon_parse_recovery_format "$bad"; then echo 'Invalid format accepted'; exit 1; fi
	[[ -z $recovery_format_mask && $recovery_format_length = 0 ]]
done
[[ ! -e BAD ]]

#Keep dangerous filenames literal in the new execution path, which never evals.
tmpdir="$tmp/"
hashcat_tmp_file='hash $(touch BAD) input'
hashcat_pot_tmp='hashcat pot'
hashcat_output_file='hashcat output'
aircrack_pot_tmp='aircrack pot'
enteredpath="$tmp/capture \$(touch BAD).cap"
bssid='02:00:00:00:00:01'
hashcat_handshake_cracking_plugin=22000
hashcat_pmkid_cracking_plugin=16800
hashcat_cmd_fix=' -D 1 -w 3'
language=ENGLISH
handshake_detected_for_offline_decryption=1
pmkid_detected_for_offline_decryption=0
: > "$tmp/events"

debug_print() { :; }
language_strings() { printf 'message %s\n' "$2" >> "$tmp/events"; }
manage_asking_for_captured_hashes_file() { printf 'evidence\n' >> "$tmp/events"; }
select_wpa_bssid_target_from_captured_file() { return "${target_status:-0}"; }
convert_cap_to_hashcat_format() { return "${convert_status:-0}"; }
validate_hashcat_pmkid_version() { return 0; }
check_hashcat_hashes_format() { first_hash_line=synthetic; return 0; }
manage_asking_for_dictionary_file() { printf 'dictionary\n' >> "$tmp/events"; }
manage_asking_for_rule_file() { printf 'rules\n' >> "$tmp/events"; }
set_minlength_and_maxlength() { printf 'lengths\n' >> "$tmp/events"; }
set_charset() { charset_option=1; printf 'charset\n' >> "$tmp/events"; }
exec_aircrack_dictionary_attack() { printf 'original\n' >> "$tmp/events"; }
exec_aircrack_bruteforce_attack() { printf 'original\n' >> "$tmp/events"; }
exec_hashcat_dictionary_attack() { printf 'original\n' >> "$tmp/events"; }
exec_hashcat_bruteforce_attack() { printf 'original\n' >> "$tmp/events"; }
exec_hashcat_rulebased_attack() { printf 'original\n' >> "$tmp/events"; }
manage_hashcat_pot() { printf 'manage hashcat\n' >> "$tmp/events"; }
manage_aircrack_pot() { printf 'manage aircrack\n' >> "$tmp/events"; }
hashcat() {
	printf '%s\n' "$@" > "$tmp/hashcat-argv"
	[[ $1 = -m && $3 = -a && $4 = 3 && $5 = "${tmpdir}${hashcat_tmp_file}" && $6 = '?u?u?d?d?u?u?d?d' ]] || return 99
	[[ $* != *--increment* ]]
	printf 'format hashcat\n' >> "$tmp/events"
	return "${hashcat_status:-0}"
}
crunch() {
	[[ $# = 4 && $1 = 8 && $2 = 8 && $3 = -t && $4 = ',,%%,,%%' ]] || return 99
	printf 'format crunch\n' >> "$tmp/events"
	printf '%s\n' 'SYNTHETIC_CANDIDATE_NOT_A_REAL_PASSWORD'
	return "${crunch_status:-0}"
}
aircrack-ng() {
	[[ $# = 9 && $1 = -a && $2 = 2 && $3 = -b && $4 = "$bssid" && $5 = -l && $6 = "${tmpdir}${aircrack_pot_tmp}" && $7 = -w && $8 = - && $9 = "$enteredpath" ]] || return 99
	cat > "$tmp/streamed"
	printf 'format aircrack\n' >> "$tmp/events"
}

for option in aircrack_dictionary_attack_option aircrack_bruteforce_attack_option \
	hashcat_dictionary_attack_option hashcat_bruteforce_attack_option hashcat_rulebased_attack_option; do
	#Blank input follows the old path, without starting either format backend.
	: > "$tmp/events"
	"$option" personal_handshake_pmkid_capture <<< '' > /dev/null
	grep -qx original "$tmp/events"
	if grep -q '^format ' "$tmp/events"; then echo 'Blank input launched format recovery'; exit 1; fi

	#A confirmed format bypasses dictionary/rules/length/charset prompts.
	: > "$tmp/events"
	"$option" personal_handshake_pmkid_capture <<< $'{OC43DE32}\ny' > /dev/null || :
	if grep -Eq '^(dictionary|rules|lengths|charset|original)$' "$tmp/events"; then echo 'Format fell back to original workflow'; exit 1; fi
	[[ $(grep -c '^manage ' "$tmp/events") = 1 ]]
	if [[ $option = aircrack* ]]; then
		grep -qx 'format aircrack' "$tmp/events"
		grep -qx 'format crunch' "$tmp/events"
	else
		grep -qx 'format hashcat' "$tmp/events"
		[[ $(tail -4 "$tmp/hashcat-argv") = $'-D\n1\n-w\n3' ]]
	fi
done
[[ ! -e BAD ]]

#Cancellation, missing input, rejected targets and parser retries never launch jobs.
for input in $'{OC43DE32}\nn' '{OC43DE32}' ''; do
	: > "$tmp/events"
	if [[ -n $input ]]; then
		airgeddon_optional_recovery_format personal_handshake_pmkid_capture hashcat <<< "$input" > /dev/null || :
	else
		airgeddon_optional_recovery_format personal_handshake_pmkid_capture hashcat < /dev/null > /dev/null || :
	fi
	[[ ! -s $tmp/events ]]
done
: > "$tmp/events"
airgeddon_optional_recovery_format personal_handshake_pmkid_capture hashcat <<< $'{BAD;}\n\n' > /dev/null 2>&1
[[ ! -s $tmp/events ]]
target_status=1
aircrack_dictionary_attack_option personal_handshake_pmkid_capture < /dev/null > "$tmp/rejected"
if grep -q 'Optional password format' "$tmp/rejected"; then echo 'Prompt before target validation'; exit 1; fi
target_status=0

#Unavailable optional Crunch cannot silently launch an unrestricted fallback.
command() {
	if [[ $* = '-v crunch' ]]; then return 1; fi
	builtin command "$@"
}
: > "$tmp/events"
airgeddon_optional_recovery_format personal_handshake_pmkid_capture aircrack <<< $'{OC43DE32}\ny' > /dev/null 2>&1 || :
[[ ! -s $tmp/events ]]
unset -f command

#Failures/exhaustion are distinct and stale pot data cannot imply success.
for hashcat_status in 1 2; do
	: > "$tmp/events"
	printf 'stale result\n' > "${tmpdir}${hashcat_pot_tmp}"
	airgeddon_optional_recovery_format personal_handshake_pmkid_hash hashcat <<< $'{OC43DE32}\ny' > /dev/null 2>&1 || :
	[[ ! -e ${tmpdir}${hashcat_pot_tmp} ]]
	if ((hashcat_status == 1)); then
		grep -qx 'manage hashcat' "$tmp/events"
	else
		if grep -q '^manage ' "$tmp/events"; then echo 'Failed job managed as success'; exit 1; fi
	fi
done
hashcat_status=0
: > "$tmp/events"
airgeddon_optional_recovery_format enterprise hashcat < /dev/null
[[ ! -s $tmp/events ]]

#Explicit masks retain fixed characters and escape custom question marks.
airgeddon_parse_recovery_format 'mask:HOME?d?d?d?d'
[[ $recovery_format_mask = 'HOME?d?d?d?d' && $recovery_format_keyspace = 10000 && -z $recovery_format_crunch ]]
recovery_format_custom_input='AB?'
airgeddon_parse_recovery_format 'mask:HOME000?1'
[[ $recovery_format_custom = 'AB??' && $recovery_format_keyspace = 3 ]]
printf '%s\n' 'PASS: optional recovery formats, legacy fallback, validation, literal argv and backend/error handling'
