#!/usr/bin/env bash
#Mocks and globals are consumed by sourced read-only functions.
#shellcheck disable=SC2034,SC2329
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
#shellcheck source=scripts/lab.sh
source scripts/lab.sh
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
fixture="$tmp/private capture.cap"
printf 'fixture' > "$fixture"
printf 'password123\n' > "$tmp/dictionary"

#All OS inventories/parsers below are mocked; they may return secret-bearing noise.
ps() { printf '%s\n' hostapd dnsmasq 'SECRET_PASSWORD=do-not-share'; }
ss() { printf '%s\n' 'tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:*' 'udp UNCONN 0 0 [::]:53 [::]:*'; }
iw() {
	[[ $# = 1 && $1 = list ]] || return 90
	printf '%s\n' 'Wiphy secret-radio-name' '  * monitor' '  * AP' '  * managed' 'SECRET_PASSWORD=do-not-share'
	return "${iw_status:-0}"
}
tshark() {

	#There are nine argv fields: enforce the exact read-only field-selection command.
	[[ $# = 9 && $1 = -n && $2 = -r && $3 = "$fixture" && $4 = -Y && $5 = eapol && $6 = -T && $7 = fields && $8 = -e && $9 = frame.number ]] || return 99
	printf '%s' "${frames:-}"
	return "${tshark_status:-0}"
}
timeout() {
	[[ $1 = --kill-after=2 && $2 =~ ^(5|8|15)$ ]] || return 91
	shift 2
	"$@"
}
output=$(lab_health_report)
[[ $output = *'[OBSERVED] hostapd'* && $output = *'[NOT OBSERVED] lighttpd'* ]]
[[ $output = *'[LISTENER] Local TCP/UDP port 80'* && $output = *'[LISTENER] Local TCP/UDP port 53'* ]]
[[ $output != *SECRET_PASSWORD* && $output != *127.0.0.1* ]]
output=$(lab_hardware_report)
[[ $output = *'Physical radio entries: 1'* && $output = *'AP mode advertised: yes'* ]]
[[ $output != *secret-radio* && $output != *SECRET_PASSWORD* ]]
iw_status=1
if lab_hardware_report > /dev/null 2>&1; then exit 1; fi
iw_status=0
frames=$'1\n5\n9\n'
output=$(lab_capture_quality "$fixture")
[[ $output = *'EAPOL frames observed: 3'* && $output = *'does not prove'* ]]
frames=''
output=$(lab_capture_quality "$fixture")
[[ $output = *'No EAPOL evidence observed'* ]]
tshark_status=1
if lab_capture_quality "$fixture" > /dev/null 2>&1; then exit 1; fi
if lab_recovery_preflight "$fixture" "$tmp/dictionary" > /dev/null 2>&1; then exit 1; fi
tshark_status=0
lab_recovery_preflight "$fixture" "$tmp/dictionary" > /dev/null
lab_main report "$tmp/report.md" > /dev/null
[[ $(stat -c %a "$tmp/report.md") = 600 ]]
if grep -Eq 'SECRET_PASSWORD|secret-radio|private capture|127.0.0.1|password123' "$tmp/report.md"; then
	echo 'Unexpected sensitive data in allowlisted report.'; exit 1
fi
before=$(sha256sum "$tmp/report.md")
if lab_main report "$tmp/report.md" > /dev/null 2>&1; then exit 1; fi
[[ $(sha256sum "$tmp/report.md") = "$before" ]]
mkfifo "$tmp/report.fifo"
if lab_main report "$tmp/report.fifo" > /dev/null 2>&1; then exit 1; fi
ln -s "$tmp/report.md" "$tmp/symlink.md"
if lab_main report "$tmp/symlink.md" > /dev/null 2>&1; then exit 1; fi
#A training demo must not invoke an OS tool, parser, benchmark or recovery function.
ps() { return 99; }; ss() { return 99; }; iw() { return 99; }; tshark() { return 99; }
output=$(lab_training_demo)
[[ $output = *'OFFLINE TRAINING SIMULATION'* && $output = *'[SIMULATED]'* ]]
output=$(lab_health_report)
[[ $output = *'[UNKNOWN] Process inventory'* && $output = *'[UNKNOWN] Socket inventory'* ]]
printf '%s\n' 'PASS: local health, hardware summaries, EAPOL limitations, preflight, private reports and offline training'
