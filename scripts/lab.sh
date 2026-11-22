#!/usr/bin/env bash
#Local laboratory entry point. Analyzes real inputs and saves explicitly requested reports.
#Does not capture traffic, crack passwords or install tools.

lab_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
#shellcheck source=scripts/lab_tools.sh
source "${lab_root}/lab_tools.sh"
#shellcheck source=scripts/lab_files.sh
source "${lab_root}/lab_files.sh"
#shellcheck source=scripts/lab_cpu.sh
source "${lab_root}/lab_cpu.sh"
#shellcheck source=scripts/dragon_status.sh
source "${lab_root}/dragon_status.sh"
#shellcheck source=scripts/lab_assessment.sh
source "${lab_root}/lab_assessment.sh"
#shellcheck source=scripts/extension_menu.sh
source "${lab_root}/extension_menu.sh"

lab_usage() {
	printf '%s\n' \
		'airgeddon laboratory — maintained by BashirMonZ' \
		'Usage: bash airgeddon.sh --lab COMMAND [FILE]' \
		'  tools          Report required and optional tool availability; never installs anything.' \
		'  performance    Report CPU count and Hashcat backend (bounded device probe; no benchmark).' \
		'  dragon         Preview the dragon status console; starts no services.' \
		'  capture FILE   Read capture metadata using capinfos (15-second budget).' \
		'  wordlist FILE  Count candidate lengths without printing passwords (15-second budget).' \
		'  health         Local process/listener observations; no active network probe.' \
		'  hardware       Aggregate advertised wireless modes; no scan or mode change.' \
		'  quality FILE   Count EAPOL evidence; not a complete-handshake verdict.' \
		'  train          Fixed offline simulation; no wireless tools or credentials.' \
		'  preflight CAPTURE WORDLIST  Run read-only quality/statistics checks; never starts recovery.' \
		'  report [FILE]  Allowlisted diagnostic summary; refuses to overwrite a file.' \
		'  advanced       Open the real Advanced Extension menus (no root required).' \
		'  laboratory     Open the styled local laboratory menus.' \
		'  research-tools Evidence records, wordlist/password audits and baseline-aware reports.' \
		'  wpa-analysis FILE | sae-analysis FILE | wps-assessment FILE  Hostapd checks.' \
		'  enterprise-eap FILE | auth-diagnostics FILE | frame-analysis FILE  Capture analysis.' \
		'  pmf-analysis FILE | wifi-generation FILE | eapol-analysis FILE  Capture analysis.' \
		'  rogue-ap FILE [--baseline JSON] | evil-twin FILE | client-threat FILE  Indicators.' \
		'  handshake-validate FILE | pmkid-forensics FILE | pmkid-analyze FILE  Forensics.' \
		'  evidence FILE [--record NEWFILE] | evidence-verify FILE RECORD  Evidence management.' \
		'  wordlist-analyze FILE | password-audit [--stdin]  Local audits.' \
		'  audit-report MANIFEST [NEWFILE]  Generate an actual private report.' \
		'  Add --text to analysis commands for terminal-friendly output (JSON is the CLI default).' \
		'Only assess files and networks you own or are authorized to test.' \
		'Password recovery remains an explicit choice in the existing offline recovery menu.' \
		'Longer capture timeouts do not increase cracking speed or guarantee recovery.' \
		'Windows support — coming soon (native Windows is not supported).'
}

lab_main() {
	case "${1:-help}" in
		tools)
			[[ $# -eq 1 ]] || { lab_usage >&2; return 2; }
			lab_tools_report
		;;
		performance)
			[[ $# -eq 1 ]] || { lab_usage >&2; return 2; }
			airgeddon_cpu_report
		;;
		dragon)
			[[ $# -eq 1 ]] || { lab_usage >&2; return 2; }
			dragon_status_preview
		;;
		health|hardware|train)
			[[ $# -eq 1 ]] || { lab_usage >&2; return 2; }
			case "$1" in
				health) lab_health_report ;;
				hardware) lab_hardware_report ;;
				train) lab_training_demo ;;
			esac
		;;
		report)
			[[ $# -le 2 ]] || { lab_usage >&2; return 2; }
			if [[ $# -eq 1 ]]; then
				lab_private_report
			else
				lab_save_private_report "$2"
			fi
		;;
		preflight)
			[[ $# -eq 3 ]] || { lab_usage >&2; return 2; }
			lab_recovery_preflight "$2" "$3"
		;;
		quality)
			[[ $# -eq 2 ]] || { lab_usage >&2; return 2; }
			lab_capture_quality "$2"
		;;
		capture|wordlist)
			[[ $# -eq 2 ]] || { lab_usage >&2; return 2; }
			if [[ $1 = capture ]]; then
				lab_capture_metadata "$2"
			else
				lab_wordlist_statistics "$2"
			fi
		;;
		advanced|laboratory|research-tools)
			[[ $# -eq 1 ]] || { lab_usage >&2; return 2; }
			case $1 in
				advanced) advanced_extension_menu ;;
				laboratory) extension_laboratory_menu ;;
				research-tools) extension_tools_menu ;;
			esac
		;;
		wpa-analysis|sae-analysis|wps-assessment|enterprise-eap|auth-diagnostics|frame-analysis|pmf-analysis|wifi-generation|eapol-analysis|rogue-ap|evil-twin|client-threat|handshake-validate|pmkid-forensics|pmkid-analyze|wordlist-analyze|password-audit|evidence|evidence-verify|audit-report|wpa2-audit|wpa3-audit)
			extension_run "$@"
		;;
		help|--help|-h) lab_usage ;;
		*) lab_usage >&2; return 2 ;;
	esac
}

if [[ ${BASH_SOURCE[0]} = "$0" ]]; then
	lab_main "$@"
fi
