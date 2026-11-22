#!/usr/bin/env bash
#Synthetic files and piped navigation only: never runs radio/recovery tools.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
root=$PWD
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

#Walk every research section and evidence management without running an action.
printf '1\n0\n2\n0\n3\n0\n4\n0\n5\n3\n0\n0\n0\n' | bash airgeddon.sh --lab advanced > "$tmp/menu"
for label in 'WPA/WPA2 Analysis' 'WPA3-SAE Analysis' 'PMKID Forensics' 'EAPOL Analysis' \
	'WPS Assessment' 'Enterprise EAP Analysis' 'Authentication Diagnostics' \
	'802.11 Frame Analysis' 'PMF Analysis' 'Wi-Fi 6/7 Analysis' \
	'Rogue AP Detection' 'Evil Twin Detection' 'Client Threat Analysis' \
	'Handshake Validation' 'PMKID File Analysis' 'Evidence Management'; do
	grep -qF "$label" "$tmp/menu"
done
grep -q '^1\.  WPA SECURITY RESEARCH$' "$tmp/menu"
if grep -q $'\033' "$tmp/menu"; then echo 'Redirected menu contains ANSI'; exit 1; fi
printf '13\n0\n0\n' | bash airgeddon.sh --lab laboratory > "$tmp/lab"
grep -q '^12\. Capture/wordlist preflight$' "$tmp/lab"
grep -q '^16\. Audit Report Generator' "$tmp/lab"

#Actual file creation through the public CLI, plus privacy and mismatch status.
printf 'original bytes' > "$tmp/input"
bash airgeddon.sh --lab evidence "$tmp/input" --record "$tmp/record" > "$tmp/result"
bash airgeddon.sh --lab evidence-verify "$tmp/input" "$tmp/record" > /dev/null
printf 'changed' >> "$tmp/input"
if bash airgeddon.sh --lab evidence-verify "$tmp/input" "$tmp/record" > /dev/null; then
	echo 'Evidence mismatch returned success'; exit 1
fi
printf 'password123!\n' | bash airgeddon.sh --lab password-audit --stdin > "$tmp/password"
grep -q '"status": "weak"' "$tmp/password"
if grep -q 'password123' "$tmp/password"; then echo 'Secret leaked'; exit 1; fi
printf 'wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\nsae_pwe=2\nsae_password=N8!pL7-kR4#vZ2\n' > "$tmp/hostapd.conf"
printf '1\n2\n%s\n\n0\n0\n' "$tmp/hostapd.conf" | bash airgeddon.sh --lab advanced > "$tmp/action"
grep -q 'Status: no_flagged_issues' "$tmp/action"
if grep -q 'N8!' "$tmp/action"; then echo 'Config secret leaked'; exit 1; fi
(cd "$tmp" && bash "$root/airgeddon.sh" --lab sae-analysis hostapd.conf --text > /dev/null)

#The interactive route actually uses airgeddon's own renderer, not just a mock.
bash -c 'source ./airgeddon.sh; source ./scripts/extension_menu.sh; initialize_colors; extension_title "AIRGEDDON ADVANCED EXTENSION"' > "$tmp/native"
grep -q 'AIRGEDDON ADVANCED EXTENSION' "$tmp/native"
if grep -q $'\033' "$tmp/native"; then echo 'Native redirected title contains ANSI'; exit 1; fi
#Utilities are available directly, through Advanced section 6, and through
#the main application's new entry point. Reports are actual private files.
printf '6\n1\n0\n0\n0\n' | bash airgeddon.sh --lab advanced > "$tmp/utilities"
grep -q 'Evidence, audits and reports' "$tmp/utilities"
printf '%s\n' '{"sae-analysis":{"file":"hostapd.conf"}}' > "$tmp/manifest.json"
printf '2\n%s\n%s\n\n0\n' "$tmp/manifest.json" "$tmp/new-report.md" | bash airgeddon.sh --lab research-tools > "$tmp/report-menu"
grep -q 'Status: no_flagged_issues' "$tmp/new-report.md"
grep -q 'Unavailable sections: 0' "$tmp/new-report.md"
[[ $(stat -c %a "$tmp/new-report.md") = 600 ]]
printf '0\n' | bash -c 'source ./airgeddon.sh; scriptfolder="$PWD/"; research_tools_menu' > "$tmp/direct"
grep -q 'Evidence, audits and reports' "$tmp/direct"
printf 'invalid\n\n0\n' | bash airgeddon.sh --lab advanced > "$tmp/invalid"
grep -q 'Invalid selection.' "$tmp/invalid"
bash -c 'source scripts/extension_menu.sh; language=SPANISH; language_strings() { printf "%s %s %s\n" "$@"; }; extension_invalid_selection' > "$tmp/localized"
grep -qx 'SPANISH 76 red' "$tmp/localized"
if grep -q $'\033' "$tmp/report-menu"; then echo 'Utilities output contains ANSI'; exit 1; fi

#New operations menus navigate without starting an engine.
printf '7\n0\n8\n0\n0\n' | bash airgeddon.sh --lab research-tools > "$tmp/operations-menu"
grep -q 'Managed offline recovery jobs' "$tmp/operations-menu"
grep -q 'Private case folders' "$tmp/operations-menu"
bash airgeddon.sh --lab format-builder 'mask:HOME?d?d?d?d' > "$tmp/format"
grep -q '"candidates": 10000' "$tmp/format"
AIRGEDDON_EXTENSION_LANGUAGE=GERMAN bash -c 'source scripts/extension_menu.sh; extension_option 7 "Managed offline recovery jobs"' > "$tmp/german"
grep -q 'Verwaltete Offline-Wiederherstellung' "$tmp/german"
COLUMNS=32 bash -c 'source scripts/extension_menu.sh; extension_title "A long title which must fit a narrow terminal"; extension_title "A long separator which must also fit" separator; extension_option 1 "A long option which should wrap on word boundaries"; extension_notice "A long notice which should wrap instead of overflowing"' > "$tmp/narrow"
awk 'length($0) > 32 {exit 1}' "$tmp/narrow"
printf '%s\n' 'PASS: extension hierarchy, native rendering, reports, localization delegation and secret handling'
