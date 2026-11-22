#!/usr/bin/env bash
#Shared native-styled operations menus. No action starts merely by opening a menu.

extension_format_builder() {
	local spec custom=''
	IFS= read -rp "$(extension_text 'Format ({example} or mask:HOME?d?d?d?d): ')" spec || return
	if [[ $spec = mask:*'?1'* ]]; then IFS= read -rp "$(extension_text 'Custom characters for ?1: ')" custom || return; fi
	extension_operations format-builder "$spec" --charset1 "$custom"
}

extension_preflight_action() {
	local input output wordlist spec custom=''
	IFS= read -rp "$(extension_text 'Authorized mode-22000 hash export: ')" input || return
	IFS= read -rp "$(extension_text 'Existing output directory: ')" output || return
	IFS= read -rp "$(extension_text 'Wordlist (Enter to use a format): ')" wordlist || return
	if [[ -n $wordlist ]]; then
		extension_operations recovery-preflight "$input" "$output" --wordlist "$wordlist"
	else
		IFS= read -rp "$(extension_text 'Format ({example} or mask:): ')" spec || return
		if [[ $spec = mask:*'?1'* ]]; then IFS= read -rp "$(extension_text 'Custom characters for ?1: ')" custom || return; fi
		extension_operations recovery-preflight "$input" "$output" --format "$spec" --charset1 "$custom"
	fi
}

extension_job_menu() {
	local selection input directory name wordlist spec custom workload runtime confirmation
	local -a arguments
	while true; do
		extension_header 'Managed offline recovery jobs'
		extension_option 1 'Create a named private profile (does not start recovery)'
		extension_option 2 'Start a created job (explicit confirmation)'
		extension_option 3 'Resume an interrupted job with a verified checkpoint'
		extension_option 4 'Show saved progress/status'
		IFS= read -rp "$(extension_text '> ')" selection || return
		case $selection in
			0) return 0 ;;
			1)
				IFS= read -rp "$(extension_text 'Authorized mode-22000 hash export: ')" input || return
				IFS= read -rp "$(extension_text 'NEW private job directory: ')" directory || return
				IFS= read -rp "$(extension_text 'Job name (letters, digits, _ or -): ')" name || return
				IFS= read -rp "$(extension_text 'Wordlist (Enter to use a format): ')" wordlist || return
				arguments=(job-create "$input" "$directory" --name "$name")
				if [[ -n $wordlist ]]; then arguments+=(--wordlist "$wordlist"); else
					IFS= read -rp "$(extension_text 'Format ({example} or mask:): ')" spec || return
					custom=''
					if [[ $spec = mask:*'?1'* ]]; then IFS= read -rp "$(extension_text 'Custom characters for ?1: ')" custom || return; fi
					arguments+=(--format "$spec" --charset1 "$custom")
				fi
				IFS= read -rp "$(extension_text 'Workload 1-3 (Enter = 2; not a hard CPU percentage cap): ')" workload || return
				IFS= read -rp "$(extension_text 'Runtime per attempt, seconds (Enter = 3600): ')" runtime || return
				extension_operations "${arguments[@]}" --workload "${workload:-2}" --runtime "${runtime:-3600}"
				;;
			2|3|4)
				IFS= read -rp "$(extension_text 'Private job directory: ')" directory || return
				if [[ $selection = 4 ]]; then extension_operations job-status "$directory"; else
					IFS= read -rp "$(extension_text 'Start authorized offline recovery now? [y/N] ')" confirmation || return
					case $confirmation in y|Y|yes|YES)
						if [[ $selection = 2 ]]; then extension_operations job-run "$directory" --yes; else extension_operations job-resume "$directory" --yes; fi
					;; esac
				fi
				;;
			*) extension_invalid_selection ;;
		esac
		extension_pause || return
	done
}

extension_case_menu() {
	local selection directory file
	while true; do
		extension_header 'Private case folders'
		extension_option 1 'Create case: report, fingerprints, settings and tool versions'
		extension_option 2 'Export only the generated redacted report'
		IFS= read -rp "$(extension_text '> ')" selection || return
		[[ $selection = 0 ]] && return 0
		case $selection in
			1|2)
				IFS= read -rp "$(extension_text 'Case directory (NEW for creation): ')" directory || return
				if [[ $selection = 1 ]]; then
					IFS= read -rp "$(extension_text 'Audit manifest JSON: ')" file || return
					extension_operations case-create "$directory" "$file"
				else
					IFS= read -rp "$(extension_text 'NEW exported Markdown report: ')" file || return
					extension_operations case-export "$directory" "$file"
				fi
				;;
			*) extension_invalid_selection ;;
		esac
		extension_pause || return
	done
}
