#!/usr/bin/env python3
"""Private synthetic fixtures and an executable fake engine; never real recovery."""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import operations as o
import research as r

REAL_TOOL_VERSION = o.tool_version


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "hash $(literal).22000"
        self.source.write_text(
            "WPA*01*" + "a" * 32 + "*020000000001*020000000002*74657374***\n"
        )
        self.words = self.root / "words"
        self.words.write_text("SYNTHETIC_CANDIDATE_ONLY\n")
        self.addCleanup(patch.stopall)
        patch.object(o, "engine_capabilities", return_value=True).start()
        patch.object(
            o, "tool_version", return_value={"available": True, "version": "6.2.6"}
        ).start()

    def profile(self, name="job", **kwargs):
        directory = self.root / name
        o.create_profile(
            directory,
            name,
            self.source,
            **({"spec": "mask:HOME000?1", "custom": "AB"} | kwargs),
        )
        return directory

    def engine(self):
        tool = self.root / "hashcat"
        tool.write_text(
            f"#!{sys.executable}\n"
            + """
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('v6.2.6')
    sys.exit(0)
Path('argv.json').write_text(json.dumps(args))
assert '--force' not in args and '--increment' not in args
assert '--status-json' in args and '--runtime' in args
assert '-w' in args
print(json.dumps({'progress':[1,2], 'estimated_stop':int(time.time())+5, 'devices':[{'speed':25,'device_name':'PRIVATE_DEVICE'}], 'target':'PRIVATE_TARGET'}), flush=True)
if os.environ.get('FAKE_INTERRUPT') == '1':
    Path('session.restore').write_bytes(b'SYNTHETIC_CHECKPOINT')
    sys.exit(2)
Path('results.txt').write_text('SYNTHETIC_RESULT_NOT_A_REAL_PASSWORD')
sys.exit(int(os.environ.get('FAKE_EXIT', '0')))
"""
        )
        tool.chmod(0o700)
        patch.object(o.shutil, "which", return_value=str(tool)).start()
        return tool

    def test_formats_fixed_classes_symbols_custom_and_big_keyspace(self):
        self.assertEqual(o.format_spec("{OC43DE32}")["candidates"], 4569760000)
        self.assertEqual(o.format_spec("mask:HOME?d?d?d?d")["mask"], "HOME?d?d?d?d")
        self.assertEqual(o.format_spec("mask:HOME000?1", "AAB?")["candidates"], 3)
        self.assertEqual(o.format_spec("mask:HOME000?1", "AAB?")["custom"], "AB??")
        self.assertEqual(o.format_spec("mask:HOME000??")["characters"], 8)
        self.assertEqual(o.format_spec("mask:HOME000?s")["candidates"], 33)
        self.assertEqual(o.format_spec("mask:" + "?a" * 63)["candidates"], 95**63)
        for spec in (
            "mask:short",
            "mask:--restore",
            "mask:1234567?",
            "mask:1234567?9",
            "mask:1234567?1",
            "mask:1234567\n",
            "{1234567!}",
            "unmarked",
            "mask:" + "a" * 64,
        ):
            with self.subTest(spec=spec), self.assertRaises(r.ResearchError):
                o.format_spec(spec)

    def test_preflight_validates_inputs_space_and_tools_without_recovery(self):
        check = o.preflight(self.source, self.root, wordlist=self.words)
        self.assertEqual(check["status"], "ready_for_explicit_start")
        self.assertEqual(check["records"], 1)
        with patch.object(
            o, "tool_version", return_value={"available": False, "version": None}
        ):
            self.assertEqual(
                o.preflight(self.source, self.root, spec="mask:HOME0000")["status"],
                "blocked",
            )
        with (
            patch.object(
                o.shutil, "disk_usage", return_value=type("Disk", (), {"free": 1})()
            ),
            self.assertRaises(r.ResearchError),
        ):
            o.preflight(self.source, self.root, spec="mask:HOME0000")
        for options in ({}, {"wordlist": self.words, "spec": "mask:HOME0000"}):
            with self.assertRaises(r.ResearchError):
                o.preflight(self.source, self.root, **options)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(r.ResearchError):
            o.preflight(fifo, self.root, spec="mask:HOME0000")

    def test_bounded_real_subprocess_version_probe(self):
        tool = self.root / "version-tool"
        tool.write_text(
            f"#!{sys.executable}\nimport sys\nassert sys.argv[1:] == ['--version']\nprint('v6.2.6')\n"
        )
        tool.chmod(0o700)
        with patch.object(o.shutil, "which", return_value=str(tool)):
            self.assertEqual(
                REAL_TOOL_VERSION("hashcat"), {"available": True, "version": "6.2.6"}
            )
        with patch.object(o.shutil, "which", return_value=None):
            self.assertEqual(
                REAL_TOOL_VERSION("hashcat"), {"available": False, "version": None}
            )

    def test_preflight_rejects_bad_hashes(self):
        for content in (
            "pcap bytes",
            "WPA*02*wrong",
            "#comments only\n",
            self.source.read_text().replace("020000000001", "ffffffffffff"),
        ):
            bad = self.root / "bad"
            bad.write_text(content)
            with self.assertRaises(r.ResearchError):
                o.hash_input(bad)

    def test_profiles_are_private_named_and_no_clobber(self):
        directory = self.profile()
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for file in directory.iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        _, profile = o.load_profile(directory)
        self.assertEqual(profile["name"], "job")
        with self.assertRaises(FileExistsError):
            o.create_profile(directory, "job", self.source, spec="mask:HOME0000")
        with self.assertRaises(r.ResearchError):
            o.create_profile(
                self.root / "invalid", "../bad", self.source, spec="mask:HOME0000"
            )
        directory.chmod(0o755)
        with self.assertRaises(r.ResearchError):
            o.load_profile(directory)

    def test_job_confirmation_fingerprints_and_profile_edit_guard(self):
        directory = self.profile()
        with self.assertRaises(r.ResearchError):
            o.run_job(directory)
        snapshot = directory / "input.22000"
        snapshot.write_text(snapshot.read_text() + "\n")
        with self.assertRaisesRegex(r.ResearchError, "snapshot changed"):
            o.run_job(directory, confirmed=True)
        self.source.write_text(self.source.read_text().rstrip() + "\n")
        profile = directory / "profile.json"
        profile.write_text(profile.read_text().replace("HOME000", "TEST000"))
        with self.assertRaisesRegex(r.ResearchError, "Profile changed"):
            o.run_job(directory, confirmed=True)

    def test_fake_engine_progress_resume_and_no_sensitive_stdout(self):
        directory = self.profile()
        self.engine()
        self.source.unlink()  # Saved jobs do not depend on the application temporary capture/export.
        output = io.StringIO()
        with (
            patch.dict(os.environ, {"FAKE_INTERRUPT": "1"}),
            contextlib.redirect_stdout(output),
        ):
            state = o.run_job(directory, confirmed=True)
        self.assertEqual(state["status"], "interrupted")
        self.assertTrue(state["checkpoint_available"])
        self.assertEqual(state["progress"], [1, 2])
        self.assertNotIn("PRIVATE_", output.getvalue())
        self.assertNotIn("profile_digest", output.getvalue())
        with contextlib.redirect_stdout(output):
            resumed = o.run_job(directory, resume=True, confirmed=True)
        self.assertEqual(resumed["status"], "cracked")
        self.assertTrue(resumed["resumed"])
        self.assertIn("--restore", json.loads((directory / "argv.json").read_text()))
        self.assertEqual(
            stat.S_IMODE((directory / "results.txt").stat().st_mode), 0o600
        )
        with self.assertRaises(r.ResearchError):
            o.run_job(directory, resume=True, confirmed=True)

    def test_runtime_bound_and_engine_errors_do_not_imply_success(self):
        directory = self.profile(runtime=1)
        self.engine()
        with (
            patch.object(o.time, "monotonic", side_effect=[0, 20, 20]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            state = o.run_job(directory, confirmed=True)
        self.assertEqual(state["status"], "interrupted")
        second = self.profile("engine-error")
        with (
            patch.dict(os.environ, {"FAKE_EXIT": "99"}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            state = o.run_job(second, confirmed=True)
        self.assertEqual(state["status"], "engine_error")
        with self.assertRaises(r.ResearchError):
            o.run_job(second, confirmed=True)

    def test_modified_checkpoint_is_not_resumed(self):
        directory = self.profile()
        self.engine()
        with (
            patch.dict(os.environ, {"FAKE_INTERRUPT": "1"}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            o.run_job(directory, confirmed=True)
        (directory / "session.restore").write_bytes(b"changed")
        with self.assertRaisesRegex(r.ResearchError, "Checkpoint"):
            o.run_job(directory, resume=True, confirmed=True)

    def test_job_lock_is_exclusive(self):
        directory = self.profile()
        with o.job_lock(directory), self.assertRaisesRegex(r.ResearchError, "locked"):
            o.run_job(directory, confirmed=True)

    def test_progress_whitelists_and_bounds(self):
        data = o.safe_progress(
            {
                "progress": [5, 10],
                "devices": [{"speed": 30, "device_name": "PRIVATE"}],
                "guess": "PRIVATE",
                "estimated_stop": 1,
            }
        )
        self.assertEqual(data["candidates_per_second"], 30)
        self.assertNotIn("PRIVATE", json.dumps(data))
        self.assertEqual(
            o.safe_progress(
                {
                    "progress": [-1, "x"],
                    "devices": [{"speed": float("nan")}, {"speed": float("inf")}],
                }
            ),
            {},
        )
        with self.assertRaises(r.ResearchError):
            o.public_state({"status": "PRIVATE"})

    def test_case_bundle_redacted_export_and_integrity(self):
        config = self.root / "hostapd.conf"
        config.write_text(
            "wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\nsae_pwe=2\nsae_password=PRIVATE_CREDENTIAL\n"
        )
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"sae-analysis": "hostapd.conf"}))
        directory = self.root / "case"
        o.case_create(directory, manifest)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(
            {p.name for p in directory.iterdir()},
            {
                "settings.json",
                "case.json",
                "evidence.json",
                "versions.json",
                "report.md",
            },
        )
        export = self.root / "export.md"
        o.case_export(directory, export)
        self.assertNotIn(str(self.root), export.read_text())
        self.assertNotIn("PRIVATE_CREDENTIAL", export.read_text())
        self.assertEqual(stat.S_IMODE(export.stat().st_mode), 0o600)
        with self.assertRaises(r.ResearchError):
            o.case_export(directory, export)
        (directory / "report.md").write_text("PRIVATE_EDITED_REPORT")
        with self.assertRaises(r.ResearchError):
            o.case_export(directory, self.root / "refused.md")
        self.assertFalse((self.root / "refused.md").exists())


if __name__ == "__main__":
    unittest.main()
