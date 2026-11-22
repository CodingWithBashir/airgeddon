#!/usr/bin/env bash
#Read-only laboratory entry point. Does not capture traffic, crack passwords or install tools.

lab_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
#shellcheck source=scripts/lab_tools.sh
source "${lab_root}/lab_tools.sh"
#shellcheck source=scripts/lab_files.sh
source "${lab_root}/lab_files.sh"
#shellcheck source=scripts/lab_cpu.sh
source "${lab_root}/lab_cpu.sh"
#shellcheck source=scripts/dragon_status.sh
source "${lab_root}/dragon_status.sh"

lab_usage() {
	printf '%s\n' \
		'airgeddon laboratory — maintained by BashirMonZ' \
		'Usage: bash airgeddon.sh --lab [tools|performance|dragon|capture FILE|wordlist FILE|help]' \
		'  tools          Report required and optional tool availability; never installs anything.' \
		'  performance    Report CPU count and Hashcat backend (bounded device probe; no benchmark).' \
		'  dragon         Preview the dragon status console; starts no services.' \
		'  capture FILE   Read capture metadata using capinfos (15-second budget).' \
		'  wordlist FILE  Count candidate lengths without printing passwords (15-second budget).' \
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
		capture|wordlist)
			[[ $# -eq 2 ]] || { lab_usage >&2; return 2; }
			if [[ $1 = capture ]]; then
				lab_capture_metadata "$2"
			else
				lab_wordlist_statistics "$2"
			fi
		;;
		help|--help|-h) lab_usage ;;
		*) lab_usage >&2; return 2 ;;
	esac
}

if [[ ${BASH_SOURCE[0]} = "$0" ]]; then
	lab_main "$@"
fi
