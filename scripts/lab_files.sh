#!/usr/bin/env bash
#Read-only file diagnostics. Never print wordlist contents or modify input files.

lab_require_tool() {
	command -v "$1" > /dev/null 2>&1 && return 0
	printf 'Missing dependency: %s. Install it using your distribution package manager.\n' "$1" >&2
	return 1
}

lab_validate_input() {
	if [[ ! -f $1 || ! -r $1 || ! -s $1 ]]; then
		printf '%s\n' 'Input must be a readable, nonempty regular file.' >&2
		return 1
	fi
}

lab_capture_metadata() {
	local input
	lab_validate_input "$1" || return 1
	lab_require_tool readlink && lab_require_tool timeout && lab_require_tool capinfos || return 1
	input=$(readlink -f -- "$1") || return 1
	printf '%s\n' 'Read-only capture metadata; this does not certify a usable handshake.'
	if timeout --kill-after=2 15 capinfos -c -s -a -e "$input"; then
		return 0
	fi
	printf '%s\n' 'Capture inspection failed or exceeded its 15-second budget.' >&2
	return 1
}

lab_wordlist_statistics() {
	lab_validate_input "$1" || return 1
	lab_require_tool timeout && lab_require_tool awk || return 1
	printf '%s\n' 'Read-only wordlist statistics; candidate contents are not displayed.'
	#The single-quoted program is awk code, not shell expansion.
	#shellcheck disable=SC2016
	if LC_ALL=C timeout --kill-after=2 15 awk '
		{
			sub(/\r$/, "")
			n = length($0)
			total++
			if (n == 0) empty++
			if (n >= 8 && n <= 63) passphrases++
			if (n == 64 && $0 !~ /[^0-9a-fA-F]/) hexkeys++
		}
		END {
			printf "Entries: %d\nEmpty entries: %d\n", total, empty
			printf "8–63 byte candidates: %d\n64-character hex candidates: %d\n", passphrases, hexkeys
		}
	' < "$1"; then
		printf '%s\n' 'Counts are byte-based and do not predict success or time to recovery.'
		return 0
	fi
	printf '%s\n' 'Statistics failed or exceeded the 15-second budget; any counts shown may be partial.' >&2
	return 1
}
