#!/usr/bin/env bash
#Local, read-only assessment helpers. Never scan, transmit packets, or run recovery jobs.

lab_health_report() {
	local processes='' sockets='' name port
	printf '%s\n' 'Local service-health snapshot (system-wide, not instance ownership or protocol readiness).'
	if command -v timeout > /dev/null 2>&1 && command -v ps > /dev/null 2>&1 && command -v grep > /dev/null 2>&1 && processes=$(timeout --kill-after=2 5 ps -eo comm= 2> /dev/null); then
		for name in hostapd hostapd-wpe hostapd-mana dnsmasq kea-dhcp4 lighttpd; do
			if grep -Fxq "$name" <<< "$processes"; then
				printf '[OBSERVED] %s process\n' "$name"
			else
				printf '[NOT OBSERVED] %s process\n' "$name"
			fi
		done
	else
		printf '%s\n' '[UNKNOWN] Process inventory unavailable or timed out.'
	fi
	if command -v timeout > /dev/null 2>&1 && command -v ss > /dev/null 2>&1 && command -v awk > /dev/null 2>&1 && sockets=$(timeout --kill-after=2 5 ss -H -lntu 2> /dev/null); then
		for port in 53 67 80 443; do
			if awk -v port="$port" '{n=split($5,p,":"); if (p[n]==port) found=1} END {exit !found}' <<< "$sockets"; then
				printf '[LISTENER] Local TCP/UDP port %s; owner and application response unverified\n' "$port"
			else
				printf '[NO LISTENER OBSERVED] Local TCP/UDP port %s\n' "$port"
			fi
		done
	else
		printf '%s\n' '[UNKNOWN] Socket inventory unavailable or timed out.'
	fi
	printf '%s\n' 'Custom ports are not included. Check service logs for errors; no traffic probe was sent.'
}

lab_hardware_report() {
	local capabilities
	printf '%s\n' 'Wireless capability summary (read-only; no scan or mode change).'
	lab_require_tool timeout && lab_require_tool iw && lab_require_tool awk || return 1
	if ! capabilities=$(LC_ALL=C timeout --kill-after=2 8 iw list 2> /dev/null); then
		printf '%s\n' 'Capability query failed or timed out; driver access may be unavailable.' >&2
		return 1
	fi
	#Allowlist aggregate fields; never print device identifiers, addresses or raw driver output.
	awk '
		/^[[:space:]]*Wiphy / {phys++}
		/^[[:space:]]*\* monitor[[:space:]]*$/ {monitor=1}
		/^[[:space:]]*\* AP[[:space:]]*$/ {ap=1}
		/^[[:space:]]*\* managed[[:space:]]*$/ {managed=1}
		END {
			printf "Physical radio entries: %d\n", phys
			printf "Monitor mode advertised: %s\n", monitor ? "yes" : "not observed"
			printf "AP mode advertised: %s\n", ap ? "yes" : "not observed"
			printf "Managed mode advertised: %s\n", managed ? "yes" : "not observed"
		}
	' <<< "$capabilities"
	printf '%s\n' 'Aggregated across radios. Advertised modes do not prove injection, concurrency, permissions or driver stability.'
}

lab_capture_quality() {
	local input counts
	lab_validate_input "$1" || return 1
	lab_require_tool timeout && lab_require_tool tshark && lab_require_tool readlink && lab_require_tool awk || return 1
	input=$(readlink -f -- "$1") || return 1
	#Only protocol field values are requested, not addresses, SSIDs or payloads.
	if ! counts=$(set -o pipefail; LC_ALL=C timeout --kill-after=2 15 tshark -n -r "$input" -Y eapol -T fields -e frame.number 2> /dev/null | awk 'NF {n++} END {printf "%d", n}'); then
		printf '%s\n' 'Capture analysis failed or exceeded its budget; no quality verdict is available.' >&2
		return 1
	fi
	printf 'EAPOL frames observed: %s\n' "$counts"
	if ((counts == 0)); then
		printf '%s\n' 'No EAPOL evidence observed. This does not exclude a PMKID-only or other capture type.'
	else
		printf '%s\n' 'EAPOL evidence found; this alone does not prove a complete or usable WPA handshake.'
	fi
	printf '%s\n' 'Limitations: retransmissions, missing key messages, wrong target and unsupported formats need further validation.' \
		'Remediation: use WPA3 where supported, disable WPS, and choose a long, unique random passphrase.'
}

lab_training_demo() {
	printf '%s\n' 'OFFLINE TRAINING SIMULATION — no services, captures, credentials or network changes.'
	dragon_status_banner
	printf '%s\n' '[SIMULATED] Configuration prepared' '[SIMULATED] DHCP startup failed' \
		'[SIMULATED] Dashboard would report missing process/listener evidence, not READY' \
		'[SIMULATED] Cleanup requested for owned resources only' \
		'Exercise: explain why an open port or EAPOL packet is insufficient proof of readiness or recoverability.' \
		'No password-recovery job was started. All states above are fixed demonstration data.'
}

#Use a fixed-schema allowlist rather than attempting to scrub arbitrary secret-bearing logs.
lab_private_report() {
	local tool
	printf '%s\n' '# Local assessment diagnostic summary' \
		'Privacy: no raw logs, filenames, hostnames, SSIDs, addresses, credentials or candidate text included.' \
		'## Tool availability'
	for tool in iw tshark capinfos hashcat john timeout ss; do
		if command -v "$tool" > /dev/null 2>&1; then
			printf '%s: available\n' "$tool"
		else
			printf '%s: missing\n' "$tool"
		fi
	done
	printf '%s\n' '## Service observations'
	lab_health_report
	printf '%s\n' '## Limitations and recommendations' \
		'No active test or vulnerability verdict. Review locally before sharing.' \
		'Use WPA3 where possible, disable WPS, update firmware and use long random passphrases.' \
		'Isolate authorized training networks and retain sensitive evidence privately.'
}

lab_recovery_preflight() {
	local failed=0
	printf '%s\n' 'Authorized offline recovery preflight — no password recovery is launched.'
	lab_capture_quality "$1" || failed=1
	lab_wordlist_statistics "$2" || failed=1
	printf '%s\n' 'Choose your own target and dictionary in the existing recovery menu after reviewing these results.' \
		'No success probability or completion-time estimate is implied by these checks.'
	return "$failed"
}

#Stage in the destination directory, then publish with an atomic no-overwrite hard link.
#Unlike shell redirection, this cannot block by opening an existing FIFO or device.
lab_save_private_report() {
	local output=$1
	local staging directory
	if [[ -e $output || -L $output ]]; then
		printf '%s\n' 'Report destination already exists; nothing was overwritten.' >&2
		return 1
	fi
	directory=$(dirname -- "$output") || return 1
	staging=$(umask 077; mktemp -- "${directory}/.airgeddon-report.XXXXXX") || return 1
	if lab_private_report > "$staging" && ln -T -- "$staging" "$output"; then
		rm -f -- "$staging"
		printf 'Private report created: %q\n' "$output"
		return 0
	fi
	rm -f -- "$staging"
	printf '%s\n' 'Report could not be published; existing destinations are never overwritten.' >&2
	return 1
}
