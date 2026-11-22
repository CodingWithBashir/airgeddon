#!/usr/bin/env python3
"""Installed-engine checks: info probes and tiny synthetic --stdout enumeration only."""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import operations as o


class ToolIntegrationTests(unittest.TestCase):
    def test_hashcat_version_mask_stdout_and_control_flags(self):
        if not shutil.which("hashcat"):
            self.skipTest("hashcat not installed; real engine checks not run")
        version = o.tool_version("hashcat")
        self.assertIsNotNone(version["version"])
        self.assertTrue(o.engine_capabilities())
        help_result = subprocess.run(
            ["hashcat", "--help"], capture_output=True, timeout=15, check=False
        )
        for flag in (
            b"--status-json",
            b"--restore-file-path",
            b"--runtime",
            b"--workload-profile",
        ):
            self.assertIn(flag, help_result.stdout)
        # Two synthetic candidates, no hash input, potfile, recovery or benchmark.
        result = subprocess.run(
            ["hashcat", "--quiet", "--stdout", "-a", "3", "-1", "AB", "HOME000?1"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(set(result.stdout.splitlines()), {b"HOME000A", b"HOME000B"})

    def test_crunch_tiny_fixed_pattern(self):
        if not shutil.which("crunch"):
            self.skipTest("crunch not installed; generator integration not run")
        self.assertIsNotNone(o.tool_version("crunch")["version"])
        result = subprocess.run(
            ["crunch", "8", "8", "-t", "HOME000%"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            set(result.stdout.splitlines()), {f"HOME000{i}".encode() for i in range(10)}
        )

    def test_aircrack_version_probe_only(self):
        if not shutil.which("aircrack-ng"):
            self.skipTest("aircrack-ng not installed; version integration not run")
        self.assertIsNotNone(o.tool_version("aircrack-ng")["version"])


if __name__ == "__main__":
    if os.environ.get("AIRGEDDON_REQUIRE_ENGINE_TESTS") == "1" and any(
        not shutil.which(name) for name in ("hashcat", "crunch", "aircrack-ng")
    ):
        raise SystemExit(
            "Required installed-engine integration cannot run: a recovery tool is missing."
        )
    unittest.main()
