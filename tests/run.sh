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
bash tests/test_assessment.sh
bash tests/test_emergency_cleanup.sh
bash tests/test_firewall_cleanup.sh
bash tests/test_extension.sh
bash tests/test_recovery_format.sh
python3 tests/test_research.py
python3 tests/test_operations.py
python3 tests/test_tool_integration.py
python3 tests/test_research_integration.py
printf '%s\n' 'All hardware-free regression checks passed.'
