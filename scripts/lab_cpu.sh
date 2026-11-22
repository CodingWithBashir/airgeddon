#!/usr/bin/env bash
#CPU-only Hashcat tuning. No benchmarks, recovery jobs, global thread limits or system changes.

#Only backend Type fields are authoritative; a display adapter in lspci is not enough.
airgeddon_parse_hashcat_backend() {
	local line
	local type
	local cpu=0
	local other=0
	while IFS= read -r line; do
		if [[ $line =~ ^[[:space:]]*(Type|Device[[:space:]]Type)[.[:space:]]*:[[:space:]]*(.+)$ ]]; then
			type=${BASH_REMATCH[2]^^}
			if [[ $type =~ ^CPU[[:space:]]*$ ]]; then
				cpu=1
			else
				other=1
			fi
		fi
	done
	if ((cpu == 1 && other == 0)); then
		printf '%s\n' cpu
	elif ((other == 1)); then
		printf '%s\n' accelerated
	else
		printf '%s\n' unknown
	fi
}

#Cache failures as well as success, so unavailable drivers do not cause repeated probes.
airgeddon_detect_hashcat_backend() {
	local executable
	local key
	local info
	executable=$(command -v hashcat 2> /dev/null) || executable=missing
	key="${executable}|${hashcat_version:-unknown}"
	if [[ ${airgeddon_backend_cache_key:-} = "$key" ]]; then
		return 0
	fi
	airgeddon_backend_cache_key=$key
	airgeddon_hashcat_backend=unknown
	if [[ $executable = missing ]] || ! command -v timeout > /dev/null 2>&1; then
		return 0
	fi
	if info=$(LC_ALL=C timeout --kill-after=2 8 hashcat -I 2> /dev/null); then
		airgeddon_hashcat_backend=$(airgeddon_parse_hashcat_backend <<< "$info")
	fi
}

#The caller constructs its ordinary version-compatible options before applying this profile.
airgeddon_configure_cpu_profile() {
	local profile=${AIRGEDDON_CPU_PROFILE:-auto}
	local workload
	case "$profile" in
		off) return 0 ;;
		auto) workload=3 ;;
		balanced) workload=2 ;;
		*)
			printf '%s\n' 'Invalid AIRGEDDON_CPU_PROFILE; use auto, balanced or off. CPU tuning skipped.' >&2
			return 0
		;;
	esac
	airgeddon_detect_hashcat_backend
	if [[ ${airgeddon_hashcat_backend:-unknown} != cpu ]]; then
		return 0
	fi
	#Replace the existing device selection, never create two conflicting -D options.
	hashcat_cmd_fix=${hashcat_cmd_fix/ -D 2,1/}
	#Do not suppress driver/runtime warnings in the CPU profile.
	hashcat_cmd_fix=${hashcat_cmd_fix/ --force/}
	hashcat_cmd_fix+=" -D 1 -w ${workload}"
	if [[ ${airgeddon_cpu_notice_shown:-} != "$profile" ]]; then
		printf 'CPU-only Hashcat backend detected: workload profile %s. Higher CPU load; speed gains are hardware-dependent.\n' "$workload" >&2
		printf '%s\n' 'Use AIRGEDDON_CPU_PROFILE=balanced for responsiveness, or off to disable tuning.' >&2
		airgeddon_cpu_notice_shown=$profile
	fi
}

#Explicit diagnostic command; not run on ordinary startup or by the tool inventory.
airgeddon_cpu_report() {
	local logical_cpus=unknown
	if command -v nproc > /dev/null 2>&1; then
		logical_cpus=$(nproc 2> /dev/null) || logical_cpus=unknown
	fi
	airgeddon_detect_hashcat_backend
	printf 'Available logical CPUs: %s\nHashcat backend: %s\n' "$logical_cpus" "$airgeddon_hashcat_backend"
	printf 'CPU profile setting: %s\n' "${AIRGEDDON_CPU_PROFILE:-auto}"
	printf '%s\n' 'CPU tuning applies only to detected CPU-only Hashcat backends in the existing recovery menus.' \
		'No benchmark or password recovery was run. GPU and unknown backends keep their existing settings.'
}
