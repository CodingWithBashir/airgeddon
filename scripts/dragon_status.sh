#!/usr/bin/env bash
#Cosmetic, static status output only. Never launches services or modifies network state.

dragon_status_enabled() {
	case ${AIRGEDDON_DRAGON_UI:-on} in
		off|false|0) return 1 ;;
		*) return 0 ;;
	esac
}

dragon_status_line() {
	dragon_status_enabled || return 0
	local state=$1
	local message=$2
	local color=''
	local reset=''
	case "$state" in
		INIT|STAGE|INFO|STOP|PREVIEW) ;;
		*) state=INFO ;;
	esac
	#Logs and redirected output stay plain; NO_COLOR takes precedence over theme colors.
	if [[ -t 1 && ! ${NO_COLOR+x} && ${AIRGEDDON_BASIC_COLORS:-true} = true && ${TERM:-dumb} != dumb ]]; then
		color=$'\033[36m'
		reset=$'\033[0m'
	fi
	printf '%s[DRAGON / %s]%s %s\n' "$color" "$state" "$reset" "$message"
}

dragon_status_banner() {
	dragon_status_enabled || return 0
	#Backslashes at the ends of these single-quoted strings are literal ASCII art.
	#shellcheck disable=SC1003
	printf '%s\n' \
		'                      / \  //\' \
		'       |\___/|       /   \//  \\' \
		'       /0  0  \__   /    //   | \ \' \
		'      /     /  \/__/    //    |  \  \' \
		'      @_^_@/   \/_     //     |   \   \' \
		'      //_^_/     \/_  //      |    \    \' \
		'   ( //) |        \///       |     \     \' \
		' ( / /) _|_ /   )  //        |      \    _\' \
		'( // /) /,_ _ _/  ( ; -.     |    _ _\.-~' \
		'(( / / )) ,-{        _      `-.|.-~-.           .-~' \
		'(( // / ))  /\      /                 ~-. _ .-~' \
		'(( /// ))  /. `.__.-~' \
		'' \
		'   BASHIRMONZ  |  DRAGON STATUS CONSOLE' \
		'   Authorized laboratory use only.'
	dragon_status_line INIT 'Initialization of portals'
	dragon_status_line INFO 'Stage messages describe requested operations, not verified service readiness.'
}

dragon_status_preview() {
	printf '%s\n' 'PREVIEW ONLY — no portal, wireless operation or service will be started.'
	dragon_status_banner
	dragon_status_line PREVIEW 'Preparing portal workspace and configuration'
	dragon_status_line PREVIEW 'Starting access point, DHCP, DNS and web services'
	dragon_status_line PREVIEW 'Opening the existing control window'
	dragon_status_line PREVIEW 'Shutdown and restoration messages appear during the existing cleanup flow'
}
