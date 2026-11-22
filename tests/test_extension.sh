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
printf '%s\n' 'PASS: extension hierarchy, native rendering, spacing, real CLI writes and secret handling'
