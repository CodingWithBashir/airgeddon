#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
for script in airgeddon.sh language_strings.sh plugins/*.sh scripts/*.sh tests/*.sh; do
	bash -n "$script"
done
bash tests/test_timeouts.sh
bash tests/test_lab.sh
bash tests/test_cpu_profile.sh
bash tests/test_dragon_status.sh
printf '%s\n' 'All hardware-free regression checks passed.'
