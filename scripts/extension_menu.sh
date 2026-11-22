#!/usr/bin/env bash
#Shared terminal layout: native airgeddon title/separator/color helpers when available.
#No network operations are performed by menu rendering or navigation.
#Native helpers and traps consume these dynamically scoped menu/color variables.
#shellcheck disable=SC2034
#shellcheck source=scripts/extension_i18n.sh
source "${BASH_SOURCE[0]%/*}/extension_i18n.sh"

extension_color_enabled() {
	[[ -t 1 && ! ${NO_COLOR+x} && ${AIRGEDDON_BASIC_COLORS:-true} = true && ${TERM:-dumb} != dumb ]]
}

extension_title() {
	local label
	label=$(extension_text "$1")
	local kind=${2:-title}
	local width=80 symbol='*' body left right fill
	[[ $kind = separator ]] && { width=60; symbol='-'; }
	local columns=${COLUMNS:-80}
	[[ $columns =~ ^[0-9]{1,3}$ ]] || columns=80
	((columns < 24)) && columns=24
	((width > columns)) && width=$columns
	local max_label=$((width - 4))
	[[ $kind != separator ]] || max_label=$((width - 6))
	if ((${#label} > max_label)); then label="${label:0:$((max_label - 3))}..."; fi
	#Use the actual original renderer at its standard width, not a competing theme.
	if declare -F generate_dynamic_line > /dev/null && ((columns >= 80)); then
		if extension_color_enabled; then
			generate_dynamic_line "$label" "$kind"
		else
			local normal_color='' green_color_title='' blue_color='' cyan_color=''
			generate_dynamic_line "$label" "$kind"
		fi
		return
	fi
	[[ $kind = separator ]] && body=" ($label) " || body=" $label "
	left=$(((width - ${#body}) / 2))
	((left < 1)) && left=1
	right=$((width - ${#body} - left))
	((right < 1)) && right=1
	if extension_color_enabled; then
		if [[ $kind = title ]]; then printf '\033[0;32m'; else printf '\033[1;34m'; fi
	fi
	printf -v fill '%*s' "$left" ''
	printf '%s%s' "${fill// /$symbol}" "$body"
	printf -v fill '%*s' "$right" ''
	printf '%s' "${fill// /$symbol}"
	if extension_color_enabled; then printf '\033[0m'; fi
	printf '\n'
}

extension_wrapped() {
	local label=$1 prefix=${2:-} continuation=${3:-} columns=${COLUMNS:-80} available chunk
	[[ $columns =~ ^[0-9]{1,3}$ ]] || columns=80
	((columns < 24)) && columns=24
	while true; do
		available=$((columns - ${#prefix}))
		((${#label} > available)) || break
		chunk=${label:0:available}
		[[ $chunk != *' '* ]] || chunk=${chunk% *}
		[[ -n $chunk ]] || chunk=${label:0:available}
		printf '%s%s\n' "$prefix" "$chunk"
		label=${label:${#chunk}}
		label=${label# }
		prefix=$continuation
	done
	printf '%s%s\n' "$prefix" "$label"
}

extension_option() {
	local prefix
	printf -v prefix '%-4s' "$1."
	extension_wrapped "$(extension_text "$2")" "$prefix" '    '
}

extension_notice() {
	local message
	message=$(extension_wrapped "$(extension_text "$1")")
	if extension_color_enabled && declare -F echo_yellow > /dev/null; then
		echo_yellow "$message"
	else
		printf '%s\n' "$message"
	fi
}

extension_invalid_selection() {
	if declare -F language_strings > /dev/null; then
		if ! extension_color_enabled; then local normal_color='' red_color=''; fi
		language_strings "${language:-ENGLISH}" 76 red
	else
		extension_notice 'Invalid selection.'
	fi
}

extension_report_action() {
	local input output
	IFS= read -rp 'Audit manifest JSON (file paths or file/baseline objects): ' input || return
	IFS= read -rp 'NEW Markdown report path: ' output || return
	extension_run audit-report "$input" "$output"
}

extension_header() {
	if ! extension_color_enabled; then
		local normal_color='' green_color='' white_color=''
	fi
	if [[ -t 1 && -t 0 && ${TERM:-dumb} != dumb ]]; then clear; fi
	extension_title "$1"
	printf '\n'
	extension_notice 'Local evidence/configuration research - authorized inputs only.'
	if declare -F language_strings > /dev/null; then
		language_strings "${language:-ENGLISH}" 47 green
	else
		printf '%s\n' "$(extension_text 'Select an option from menu:')"
	fi
	if declare -F print_simple_separator > /dev/null; then
		if extension_color_enabled; then
			print_simple_separator
		else
			local normal_color='' blue_color=''
			print_simple_separator
		fi
	else
		printf '%s\n' '---------'
	fi
	extension_option 0 'Return'
}

extension_pause() {
	printf '\n'
	if declare -F language_strings > /dev/null; then
		language_strings "${language:-ENGLISH}" 115 read
	else
		IFS= read -rp "$(extension_text 'Press [Enter] to continue: ')" _extension_pause || return 1
	fi
}

extension_run() {
	local extension_root="${BASH_SOURCE[0]%/*}"
	if ! command -v python3 > /dev/null 2>&1; then
		printf '%s\n' 'Advanced tools require Python 3.9 or newer.' >&2
		return 2
	fi
	python3 "$extension_root/research.py" "$@"
}

extension_operations() {
	command -v python3 > /dev/null 2>&1 || { extension_notice 'Python 3.9+ is required.'; return 2; }
	python3 "${BASH_SOURCE[0]%/*}/operations.py" "$@"
}

extension_file_action() {
	local command=$1 input baseline
	local hint='Authorized capture file: '
	case $command in
		wpa-analysis|sae-analysis|wps-assessment) hint='Your self-contained hostapd configuration: ' ;;
		pmkid-forensics|pmkid-analyze) hint='Authorized PMKID text export: ' ;;
		wordlist-analyze) hint='Your local wordlist: ' ;;
	esac
	IFS= read -rp "$hint" input || return 1
	if [[ $command = rogue-ap ]]; then
		IFS= read -rp 'Approved AP baseline JSON (Enter if unavailable): ' baseline || return 1
		if [[ -n $baseline ]]; then
			extension_run "$command" "$input" --baseline "$baseline" --text
		else
			extension_run "$command" "$input" --text
		fi
	else
		extension_run "$command" "$input" --text
	fi
}

extension_evidence_menu() {
	local selection input output
	while true; do
		extension_header 'Evidence Management'
		extension_option 1 'Fingerprint actual evidence (SHA-256)'
		extension_option 2 'Create a new private evidence record'
		extension_option 3 'Verify evidence against a saved record'
		IFS= read -rp '> ' selection || return
		[[ $selection = 0 ]] && return 0
		case $selection in
			1|2|3)
				IFS= read -rp 'Evidence file: ' input || return
				case $selection in
					1) extension_run evidence "$input" --text ;;
					2)
						IFS= read -rp 'NEW evidence record path: ' output || return
						extension_run evidence "$input" --record "$output" --text
					;;
					3)
						IFS= read -rp 'Saved evidence record path: ' output || return
						extension_run evidence-verify "$input" "$output" --text
					;;
				esac
				;;
			*) extension_invalid_selection ;;
		esac
		extension_pause || return
	done
}

extension_category_menu() {
	local category=$1 selection command
	local -a labels commands
	case $category in
		1)
			labels=('WPA/WPA2 Analysis' 'WPA3-SAE Analysis' 'PMKID Forensics' 'EAPOL Analysis')
			commands=(wpa-analysis sae-analysis pmkid-forensics eapol-analysis)
			;;
		2)
			labels=('WPS Assessment' 'Enterprise EAP Analysis' 'Authentication Diagnostics')
			commands=(wps-assessment enterprise-eap auth-diagnostics)
			;;
		3)
			labels=('802.11 Frame Analysis' 'PMF Analysis' 'Wi-Fi 6/7 Analysis')
			commands=(frame-analysis pmf-analysis wifi-generation)
			;;
		4)
			labels=('Rogue AP Detection' 'Evil Twin Detection' 'Client Threat Analysis')
			commands=(rogue-ap evil-twin client-threat)
			;;
		5)
			labels=('Handshake Validation' 'PMKID File Analysis' 'Evidence Management')
			commands=(handshake-validate pmkid-analyze evidence-menu)
			;;
		*) return 1 ;;
	esac
	local -a headings=('WPA SECURITY RESEARCH' 'AUTHENTICATION RESEARCH' 'WIRELESS PROTOCOL RESEARCH' 'WIRELESS THREAT RESEARCH' 'CAPTURE FORENSICS')
	while true; do
		extension_header "${headings[$((category - 1))]}"
		local i
		for i in "${!labels[@]}"; do extension_option "$((i + 1))" "${labels[$i]}"; done
		IFS= read -rp '> ' selection || return
		[[ $selection = 0 ]] && return 0
		if [[ $selection =~ ^[1-4]$ ]] && ((selection <= ${#commands[@]})); then
			command=${commands[$((selection - 1))]}
			if [[ $command = evidence-menu ]]; then
				extension_evidence_menu
			else
				extension_file_action "$command"
				extension_pause || return
			fi
		else
			extension_invalid_selection
			extension_pause || return
		fi
	done
}

advanced_extension_menu() {
	local current_menu=advanced_extension_menu
	local selection
	while true; do
		extension_header 'AIRGEDDON ADVANCED EXTENSION'
		extension_option 1 'WPA SECURITY RESEARCH'
		extension_option 2 'AUTHENTICATION RESEARCH'
		extension_option 3 'WIRELESS PROTOCOL RESEARCH'
		extension_option 4 'WIRELESS THREAT RESEARCH'
		extension_option 5 'CAPTURE FORENSICS'
		extension_title 'Evidence and reports' separator
		extension_option 6 'Evidence, audits and report tools'
		printf '\n'
		extension_notice 'Actions process real inputs. No simulated success or automatic attack.'
		IFS= read -rp '> ' selection || return
		case $selection in
			0) return 0 ;;
			1|2|3|4|5) extension_category_menu "$selection" ;;
			6) extension_tools_menu ;;
			*) extension_invalid_selection; extension_pause || return ;;
		esac
	done
}

extension_tools_menu() {
	#shellcheck source=scripts/operations_menu.sh
	source "${BASH_SOURCE[0]%/*}/operations_menu.sh"
	local current_menu=research_tools_menu
	local selection
	while true; do
		extension_header 'Evidence, audits and reports'
		extension_option 1 'Evidence Management'
		extension_option 2 'Audit Report Generator (supports approved-AP baselines)'
		extension_option 3 'Wordlist Analyzer'
		extension_option 4 'Password Strength Auditor (hidden prompt)'
		extension_option 5 'Recovery preflight checks'
		extension_option 6 'Password Format Builder'
		extension_option 7 'Managed offline recovery jobs'
		extension_option 8 'Private case folders'
		IFS= read -rp '> ' selection || return
		case $selection in
			0) return 0 ;;
			1) extension_evidence_menu; continue ;;
			2) extension_report_action ;;
			3) extension_file_action wordlist-analyze ;;
			4) extension_run password-audit --text ;;
			5) extension_preflight_action ;;
			6) extension_format_builder ;;
			7) extension_job_menu; continue ;;
			8) extension_case_menu; continue ;;
			*) extension_invalid_selection ;;
		esac
		extension_pause || return
	done
}

extension_laboratory_menu() {
	local current_menu=laboratory_menu
	local selection input second
	while true; do
		extension_header 'Assessment laboratory'
		extension_title 'Diagnostics' separator
		extension_option 1 'Tool readiness report'
		extension_option 2 'Capture metadata'
		extension_option 3 'Wordlist statistics'
		extension_option 4 'Existing offline recovery menu'
		extension_option 5 'CPU/backend profile report'
		extension_option 6 'Dragon display preview (explicit simulation)'
		extension_option 7 'Local service-health snapshot'
		extension_option 8 'Wireless hardware capability summary'
		extension_option 9 'EAPOL evidence count'
		extension_title 'Training and reports' separator
		extension_option 10 'Offline training (explicit simulation)'
		extension_option 11 'Private diagnostic summary on stdout'
		extension_option 12 'Capture/wordlist preflight'
		extension_title 'Advanced research' separator
		extension_option 13 'AIRGEDDON ADVANCED EXTENSION'
		extension_option 14 'Wordlist Analyzer'
		extension_option 15 'Password Strength Auditor (hidden prompt)'
		extension_option 16 'Audit Report Generator (real output file)'
		IFS= read -rp '> ' selection || return
		case $selection in
			0) return 0 ;;
			4)
				if declare -F personal_decrypt_menu > /dev/null; then personal_decrypt_menu; else extension_notice 'Open the interactive application for recovery menus.'; fi
				continue
				;;
			13) advanced_extension_menu; continue ;;
			14) extension_file_action wordlist-analyze ;;
			15) extension_run password-audit --text ;;
			16) extension_report_action ;;
			1|2|3|5|6|7|8|9|10|11|12)
				local -a actions=('' tools capture wordlist '' performance dragon health hardware quality train report preflight)
				local action=${actions[$selection]}
				local -a arguments=("$action")
				if [[ $selection = 2 || $selection = 3 || $selection = 9 || $selection = 12 ]]; then
					IFS= read -rp 'Authorized local file: ' input || return
					arguments+=("$input")
				fi
				if [[ $selection = 12 ]]; then
					IFS= read -rp 'Your local wordlist: ' second || return
					arguments+=("$second")
				fi
				bash "${BASH_SOURCE[0]%/*}/lab.sh" "${arguments[@]}"
				;;
			*) extension_invalid_selection ;;
		esac
		extension_pause || return
	done
}
