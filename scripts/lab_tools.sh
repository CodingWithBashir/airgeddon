#!/usr/bin/env bash
#Capability inventory only: detecting a tool does not certify its version or hardware support.

lab_tools_group() {
	local heading=$1
	local tool
	local present=0
	local missing=0
	shift
	printf '\n%s\n' "$heading"
	for tool in "$@"; do
		if command -v "$tool" > /dev/null 2>&1; then
			printf '  [available] %s\n' "$tool"
			present=$((present + 1))
		else
			printf '  [missing]   %s\n' "$tool"
			missing=$((missing + 1))
		fi
	done
	printf '  Available: %d; missing: %d\n' "$present" "$missing"
}

lab_tools_report() {
	printf '%s\n' 'Tool readiness report — no installation or tool execution performed.' \
		'Availability is not proof of driver, GPU, version or interface compatibility.'
	lab_tools_group 'Core wireless tools' iw awk airmon-ng airodump-ng aircrack-ng ip lspci ps
	lab_tools_group 'Window handling (choose one)' xterm tmux
	lab_tools_group 'Offline recovery and capture conversion (optional)' \
		hashcat john crunch hcxpcapngtool hcxhashtool hcxhash2cap wpaclean
	lab_tools_group 'Capture inspection and integrity (optional)' \
		capinfos tshark tcpdump editcap mergecap sha256sum file
	lab_tools_group 'Lab utilities' timeout stat readlink wc
	lab_tools_group 'Device and service diagnostics (optional)' \
		ethtool lsusb rfkill ss arping loginctl systemctl lshw lscpu
	lab_tools_group 'Access-point lab dependencies (optional)' \
		hostapd hostapd-wpe hostapd-mana dnsmasq kea-dhcp4 nft iptables lighttpd openssl
	lab_tools_group 'Maintenance and display helpers (optional)' \
		curl wget git shellcheck xdpyinfo xprop xset ccze play
	printf '\n%s\n' 'Install only what your chosen workflow requires, using trusted distribution packages.' \
		'No optional package is made mandatory by this report.'
}
