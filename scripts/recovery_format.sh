#!/usr/bin/env bash
#Optional fixed-position formats for explicitly selected personal offline recovery.
#Never eval user input. The parser emits only built-in Hashcat/Crunch class tokens.
#The caller's local variables and the application's existing helpers consume outputs.
#shellcheck disable=SC2034,SC2154

airgeddon_parse_recovery_format() {
	local LC_ALL=C input=$1 body character radix index
	recovery_format_mask=''
	recovery_format_custom=''
	recovery_format_crunch=''
	recovery_format_length=0
	recovery_format_keyspace=1
	recovery_format_capped=0
	if [[ $input = mask:* ]]; then
		local compiled
		local -a fields=()
		command -v python3 > /dev/null 2>&1 || return 2
		compiled=$(python3 "${BASH_SOURCE[0]%/*}/operations.py" format-builder "$input" --charset1 "${recovery_format_custom_input:-}" --shell) || return 2
		mapfile -t fields <<< "$compiled"
		recovery_format_mask=${fields[0]}
		recovery_format_length=${fields[1]}
		recovery_format_keyspace=${fields[2]}
		recovery_format_custom=${fields[3]:-}
		return 0
	fi
	[[ $input = \{*\} && ${#input} -ge 10 && ${#input} -le 65 ]] || return 2
	body=${input:1:${#input}-2}
	[[ $body != *[!a-zA-Z0-9]* ]] || return 2
	for ((index=0; index < ${#body}; index++)); do
		character=${body:index:1}
		case $character in
			[A-Z]) recovery_format_mask+='?u'; recovery_format_crunch+=','; radix=26 ;;
			[a-z]) recovery_format_mask+='?l'; recovery_format_crunch+='@'; radix=26 ;;
			[0-9]) recovery_format_mask+='?d'; recovery_format_crunch+='%'; radix=10 ;;
		esac
		#Saturate before multiplication, rather than overflowing shell integers.
		if ((recovery_format_keyspace > 1000000000000000000 / radix)); then
			recovery_format_keyspace=1000000000000000000
			recovery_format_capped=1
		else
			recovery_format_keyspace=$((recovery_format_keyspace * radix))
		fi
	done
	recovery_format_length=${#body}
}

airgeddon_exec_recovery_format() {
	local backend=$1 mode=$2 status
	local -a options=() pipeline_status=()
	if [[ $backend = hashcat ]]; then
		local plugin
		case $mode in
			personal_handshake_pmkid_capture) plugin=$hashcat_handshake_cracking_plugin ;;
			personal_handshake_pmkid_hash) plugin=$hashcat_pmkid_cracking_plugin ;;
			*) return 2 ;;
		esac
		#These are application-generated version/backend flags, not shell syntax.
		read -r -a options <<< "${hashcat_cmd_fix:-}"
		[[ -z ${recovery_format_custom:-} ]] || options+=(-1 "$recovery_format_custom")
		rm -f -- "${tmpdir}${hashcat_pot_tmp}" || return 2
		hashcat -m "$plugin" -a 3 "${tmpdir}${hashcat_tmp_file}" "$recovery_format_mask" \
			--potfile-disable -o "${tmpdir}${hashcat_pot_tmp}" "${options[@]}" | tee "${tmpdir}${hashcat_output_file}"
		pipeline_status=("${PIPESTATUS[@]}")
		status=${pipeline_status[0]}
		#Hashcat status 1 means exhausted, not an execution error.
		((pipeline_status[1] == 0 && (status == 0 || status == 1))) || return 2
	elif [[ $backend = aircrack && $mode = personal_handshake_pmkid_capture ]]; then
		rm -f -- "${tmpdir}${aircrack_pot_tmp}" || return 2
		crunch "$recovery_format_length" "$recovery_format_length" -t "$recovery_format_crunch" | \
			aircrack-ng -a 2 -b "$bssid" -l "${tmpdir}${aircrack_pot_tmp}" -w - "$enteredpath"
		pipeline_status=("${PIPESTATUS[@]}")
		#SIGPIPE is normal when aircrack stops consuming after finding a candidate.
		((pipeline_status[1] == 0 && (pipeline_status[0] == 0 || pipeline_status[0] == 141))) || return 2
	else
		return 2
	fi
	language_strings "${language}" 115 read
}

airgeddon_optional_recovery_format() {
	#Return 0 ONLY to continue the original workflow (blank/enterprise).
	#Return nonzero after a handled format job, cancellation or any failure, so
	#callers never silently fall back to an unrestricted/dictionary attack.
	local mode=$1 backend=$2 input confirmation
	local recovery_format_mask='' recovery_format_crunch='' recovery_format_length=0
	local recovery_format_keyspace=1 recovery_format_capped=0
	local recovery_format_custom='' recovery_format_custom_input=''
	case $mode in
		personal_handshake_pmkid_capture|personal_handshake_pmkid_hash) ;;
		*) return 0 ;;
	esac
	printf '\n%s\n' \
		'Optional password format for this authorized offline recovery job.' \
		'Enter {example}: uppercase letters mean A-Z, lowercase mean a-z, digits mean 0-9.' \
		'Example: {OC43DE32} means ?u?u?d?d?u?u?d?d, NOT that exact password.' \
		'Braces are delimiters. Or use mask:HOME?d?d?d?d for fixed text plus unknown positions.' \
		'Masks support ?u ?l ?d ?s ?a, ?? for literal ?, and ?1 for a custom character set.' \
		'Formats describe 8-63 printable ASCII characters. Explicit masks require Hashcat and Python 3.9+.' \
		'A format REPLACES the selected dictionary/rules/length settings with a fixed-length search.' \
		'Press Enter to skip. No format is saved for the next job.'
	while true; do
		IFS= read -rp 'Optional format: ' input || return 1
		[[ -n $input ]] || return 0
		recovery_format_custom_input=''
		if [[ $input = mask:*'?1'* ]]; then
			IFS= read -rp 'Custom characters for ?1 (literal characters): ' recovery_format_custom_input || return 1
		fi
		if ! airgeddon_parse_recovery_format "$input"; then
			printf '%s\n' 'Invalid format. Use {8-63 ASCII letters/digits}, mask: with 8-63 positions, or Enter to skip.' >&2
			continue
		fi
		break
	done
	input=''
	if [[ -e $recovery_format_mask || ( -n ${recovery_format_custom:-} && -e $recovery_format_custom ) ]]; then
		printf '%s\n' 'The mask or custom set matches an existing filename, which Hashcat could interpret as a file. No job was started.' >&2
		return 1
	fi
	if [[ $backend = aircrack && -z $recovery_format_crunch ]]; then
		printf '%s\n' 'Explicit masks require a Hashcat option; no Aircrack recovery or fallback was started.' >&2
		return 1
	fi
	if [[ $backend = aircrack ]] && ! command -v crunch > /dev/null 2>&1; then
		printf '%s\n' 'This Aircrack format search requires Crunch. No recovery was started.' >&2
		return 1
	fi
	printf 'Fixed-length pattern: %s (%s characters).\n' "$recovery_format_mask" "$recovery_format_length"
	if ((recovery_format_capped)); then
		printf '%s\n' 'Search space: at least 1,000,000,000,000,000,000 candidates.'
	else
		printf 'Search space: %s candidates.\n' "$recovery_format_keyspace"
	fi
	printf '%s\n' 'This can take a very long time. A matching format does not guarantee recovery.'
	IFS= read -rp 'Use this format instead of the selected recovery method? [y/N] ' confirmation || return 1
	case $confirmation in y|Y|yes|YES) ;; *) return 1 ;; esac
	language_strings "${language}" 190 yellow
	language_strings "${language}" 115 read || return 1
	if airgeddon_exec_recovery_format "$backend" "$mode"; then
		if [[ $backend = hashcat ]]; then
			manage_hashcat_pot "$mode"
		else
			manage_aircrack_pot
		fi
	else
		printf '%s\n' 'Format recovery failed or was interrupted. No automatic fallback was started.' >&2
	fi
	return 1
}
