#!/usr/bin/env bash
#Globals are consumed by sourced application functions and command mocks.
#shellcheck disable=SC2034,SC2329
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#shellcheck source=/dev/null
source ./airgeddon.sh
debug_print() { :; }
#Exercise the real lazy loader without probing the host during tests.
scriptfolder="${PWD}/"
hashcat_version=6.2
airgeddon_hashcat_backend=unknown
AIRGEDDON_CPU_PROFILE=off
set_hashcat_parameters
declare -F airgeddon_configure_cpu_profile > /dev/null
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

#Do not confuse descriptive text, skipped GPU names or a mixed backend with CPU-only.
[[ $(airgeddon_parse_hashcat_backend <<< 'Type...........: CPU') = cpu ]]
[[ $(airgeddon_parse_hashcat_backend <<< '  Device Type: CPU') = cpu ]]
[[ $(airgeddon_parse_hashcat_backend <<< $'Type: CPU\nType: GPU') = accelerated ]]
[[ $(airgeddon_parse_hashcat_backend <<< 'Type: CPU, GPU') = accelerated ]]
[[ $(airgeddon_parse_hashcat_backend <<< 'Type: Accelerator') = accelerated ]]
[[ $(airgeddon_parse_hashcat_backend <<< 'Name: CPU driver not found') = unknown ]]
[[ $(airgeddon_parse_hashcat_backend <<< '') = unknown ]]

#Only a successful, bounded -I device probe is allowed. Never launch real recovery.
hashcat() {
	[[ $# = 1 && $1 = -I && $LC_ALL = C ]] || return 99
	printf 'probe\n' >> "$tmp/probes"
	printf '%s\n' "$mock_backend"
	return "${mock_hashcat_status:-0}"
}
timeout() {
	[[ $# = 4 && $1 = --kill-after=2 && $2 = 8 && $3 = hashcat && $4 = -I ]] || return 99
	if [[ ${mock_timeout_status:-0} != 0 ]]; then
		return "$mock_timeout_status"
	fi
	shift 2
	"$@"
}
reset_probe() {
	unset airgeddon_backend_cache_key airgeddon_cpu_notice_shown
	: > "$tmp/probes"
	mock_hashcat_status=0
	mock_timeout_status=0
}
assert_single_probe() { [[ $(wc -l < "$tmp/probes") = 1 ]]; }

hashcat_version=6.2
AIRGEDDON_CPU_PROFILE=auto
mock_backend='Type...........: CPU'
reset_probe
set_hashcat_parameters 2> /dev/null
[[ $hashcat_cmd_fix = ' -D 1 -w 3' ]]
#Repeated calls reconstruct options without duplicating flags or probing again.
set_hashcat_parameters 2> /dev/null
[[ $hashcat_cmd_fix = ' -D 1 -w 3' ]]
assert_single_probe
[[ $hashcat_cmd_fix != *--force* && $hashcat_cmd_fix != *' -O'* ]]

AIRGEDDON_CPU_PROFILE=balanced
set_hashcat_parameters 2> /dev/null
[[ $hashcat_cmd_fix = ' -D 1 -w 2' ]]
assert_single_probe

AIRGEDDON_CPU_PROFILE=off
reset_probe
set_hashcat_parameters
[[ $hashcat_cmd_fix = ' -D 2,1 --force' && ! -s $tmp/probes ]]
AIRGEDDON_CPU_PROFILE=invalid
set_hashcat_parameters 2> /dev/null
[[ $hashcat_cmd_fix = ' -D 2,1 --force' && ! -s $tmp/probes ]]

AIRGEDDON_CPU_PROFILE=auto
for mock_backend in 'Type: GPU' $'Type: CPU\nType: GPU' '' 'unrecognized output'; do
	reset_probe
	set_hashcat_parameters
	[[ $hashcat_cmd_fix = ' -D 2,1 --force' ]]
	assert_single_probe
done

#A failed probe must never enable tuning, even if it emitted CPU-looking partial output.
mock_backend='Type: CPU'
reset_probe
mock_hashcat_status=1
set_hashcat_parameters
set_hashcat_parameters
[[ $hashcat_cmd_fix = ' -D 2,1 --force' && $airgeddon_hashcat_backend = unknown ]]
assert_single_probe
reset_probe
mock_timeout_status=124
set_hashcat_parameters
[[ $airgeddon_hashcat_backend = unknown && $hashcat_cmd_fix = ' -D 2,1 --force' ]]

#Older versions retain their required options; pre-v3 gets no unsupported flags or probe.
reset_probe
hashcat_version=3.2
set_hashcat_parameters 2> /dev/null
[[ $hashcat_cmd_fix = ' --weak-hash-threshold 0 -D 1 -w 3' ]]
assert_single_probe
hashcat_version=2.0
reset_probe
set_hashcat_parameters
[[ -z $hashcat_cmd_fix && ! -s $tmp/probes ]]
printf '%s\n' 'PASS: CPU profiles, mixed/GPU fallback, failed probes, caching and legacy versions'
