#!/usr/bin/env python3
"""Synthetic local inputs only: no radio, network or recovery jobs."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("research", ROOT / "scripts/research.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.input = self.put("input file $(literal)", b"synthetic bytes\n")
        self.config = self.put(
            "hostapd.conf",
            "wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\nsae_pwe=2\nsae_password=N8!pL7-kR4#vZ2\nwps_state=0\n",
        )

    def put(self, name, content):
        path = self.root / name
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def call(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = r.main([str(arg) for arg in arguments])
        return status, out.getvalue(), err.getvalue()

    def test_config_routes_and_secrets(self):
        before = self.config.read_bytes()
        for mode in r.CONFIG_MODES:
            data = r.analyze(mode, self.config)
            self.assertNotIn("N8!", json.dumps(data))
        self.assertEqual(
            r.analyze("sae-analysis", self.config)["status"], "no_flagged_issues"
        )
        self.assertEqual(before, self.config.read_bytes())
        self.assertEqual(self.call("wpa3-audit", self.config)[0], 0)
        weak = self.put(
            "weak",
            "wpa=3\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nwpa_passphrase=password123\nwps_state=2\n",
        )
        self.assertEqual(r.analyze("wpa-analysis", weak)["status"], "issues_found")
        self.assertEqual(r.analyze("wps-assessment", weak)["status"], "review")

    def test_config_preserves_credential_whitespace(self):
        template = "wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nieee80211w=2\n"
        seed = ("N8!pL7-kR4#vZ2" * 5)[:63]
        for secret in (" " + seed, seed + " ", "\t" + seed, seed + "\t", "é" * 32):
            with self.subTest(secret_bytes=len(secret.encode())):
                path = self.put(
                    "whitespace.conf", template + "wpa_passphrase=" + secret + "\r\n"
                )
                original = path.read_bytes()
                self.assertEqual(r.config_input(path)["wpa_passphrase"], secret)
                data = r.analyze("wpa-analysis", path)
                self.assertEqual(data["status"], "issues_found")
                self.assertTrue(any("8-63 byte" in item for item in data["findings"]))
                self.assertNotIn(seed, json.dumps(data))
                self.assertEqual(path.read_bytes(), original)
        for key, secret in (
            ("wpa_passphrase", "  ab#cd\t "),
            ("wpa_psk", " " + "a" * 64),
            ("sae_password", "  a\v\f\u0085b |id=test"),
        ):
            path = self.put("exact.conf", template + key + "=" + secret + "\n")
            self.assertEqual(r.config_input(path)[key], secret)
        path = self.put("invalid-psk.conf", template + "wpa_psk= " + "a" * 64 + "\n")
        self.assertEqual(r.analyze("wpa-analysis", path)["status"], "issues_found")
        path = self.put(
            "valid-spaces.conf", template + "wpa_passphrase= " + seed[:61] + " \n"
        )
        self.assertEqual(r.analyze("wpa-analysis", path)["status"], "no_flagged_issues")

    def test_config_refuses_ambiguous_or_invalid_inputs(self):
        for text in (
            "wpa=2\nwpa=3",
            "wpa=2\ninclude=secret",
            "wpa=2\nbss=test",
            "#!/bin/bash",
            "ssid=x",
            "wpa=2\nwps_state=no",
        ):
            with self.subTest(text=text), self.assertRaises(r.ResearchError):
                r.analyze("wpa-analysis", self.put("invalid", text))

    def test_enterprise_is_not_sae(self):
        path = self.put(
            "enterprise", self.config.read_text().replace("SAE", "WPA-EAP-SUITE-B-192")
        )
        self.assertEqual(r.analyze("sae-analysis", path)["status"], "issues_found")

    def test_pmkid_formats_duplicates_invalid_and_ignored(self):
        fields = "a" * 32 + "*020000000001*020000000002*74657374"
        export = self.put(
            "pmkid",
            fields
            + "\nWPA*01*"
            + fields.upper()
            + "***\nmalformed\nWPA*02*unassessed\n",
        )
        for mode in r.PMKID_MODES:
            data = r.analyze(mode, export)
            self.assertEqual(
                data["metrics"],
                {
                    "valid_format_records": 2,
                    "invalid_records": 1,
                    "duplicates": 1,
                    "eapol_records_not_analyzed": 1,
                },
            )
            self.assertNotIn("74657374", json.dumps(data))
        invalid = self.put("badmac", "a" * 32 + "*ffffffffffff*020000000002*74")
        self.assertEqual(
            r.analyze("pmkid-analyze", invalid)["metrics"]["invalid_records"], 1
        )

    def test_wordlist_counts_bytes_and_preserves_input(self):
        content = b"password123\r\npassword123\n\n short \n\xff\n"
        path = self.put("list", content)
        data = r.analyze("wordlist-analyze", path)
        self.assertEqual(
            data["metrics"],
            {
                "entries": 5,
                "duplicates": 1,
                "empty_entries": 1,
                "passphrase_length_entries": 2,
                "invalid_utf8_entries": 1,
                "edge_whitespace_entries": 1,
            },
        )
        self.assertNotIn("password123", json.dumps(data))
        self.assertEqual(path.read_bytes(), content)

    def test_password_heuristics(self):
        self.assertTrue(r.strength("password123!")["weak_heuristic"])
        self.assertTrue(r.strength("abcdabcdabcdabcd")["weak_heuristic"])
        self.assertFalse(r.strength("N8!pL7-kR4#vZ2")["weak_heuristic"])
        self.assertEqual(self.call("password-audit")[0], 2)

    def test_hash_record_verify_and_no_clobber(self):
        record = self.root / "record.json"
        status, out, _ = self.call("evidence", self.input, "--record", record)
        self.assertEqual(status, 0)
        document = json.loads(record.read_text())
        self.assertEqual(
            document["sha256"], hashlib.sha256(self.input.read_bytes()).hexdigest()
        )
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertEqual(json.loads(out)["status"], "record_created")
        self.assertEqual(self.call("evidence-verify", self.input, record)[0], 0)
        self.assertEqual(self.call("evidence", self.input, "--record", record)[0], 2)
        self.input.write_bytes(b"changed")
        status, out, _ = self.call("evidence-verify", self.input, record)
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(out)["status"], "mismatch")
        self.assertEqual(list(self.root.glob(".airgeddon-evidence-*")), [])

    def test_symlink_output_is_not_followed(self):
        link = self.root / "link"
        link.symlink_to(self.input)
        with self.assertRaises(r.ResearchError):
            r.publish_private(link, "overwrite")
        self.assertEqual(self.input.read_bytes(), b"synthetic bytes\n")

    def test_input_budgets_devices_and_json(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (fifo, self.root, self.root / "absent", Path("/dev/zero")):
            with self.subTest(path=path), self.assertRaises(r.ResearchError):
                r.small_input(path)
        with self.assertRaises(r.ResearchError):
            r.small_input(self.input, 1)
        with self.assertRaises(r.ResearchError):
            r.json_input(self.put("dup.json", '{"a":1,"a":2}'))
        with patch.object(r, "MAX_EVIDENCE", 1), self.assertRaises(r.ResearchError):
            r.evidence_digest(self.input)

    def handshake(self):
        ap, client = "02:00:00:00:00:01", "02:00:00:00:00:02"
        return [
            [
                str(i),
                str(100 + i),
                ap if i % 2 else client,
                client if i % 2 else ap,
                str(i),
                str(7 if i < 3 else 8),
            ]
            for i in range(1, 5)
        ]

    def test_handshake_conservative_structure(self):
        rows = self.handshake()
        for mode in ("handshake-validate", "eapol-analysis"):
            self.assertEqual(
                r.handshake_rows(rows, mode)["metrics"]["structural_candidates"], 1
            )
            self.assertEqual(r.handshake_rows(rows[:3], mode)["status"], "inconclusive")
        for index, column, value in (
            (3, 5, "9"),
            (3, 2, "02:00:00:00:00:03"),
            (3, 1, "1000"),
            (3, 1, "nan"),
            (0, 2, "ff:ff:ff:ff:ff:ff"),
        ):
            modified = [row[:] for row in rows]
            modified[index][column] = value
            self.assertEqual(
                r.handshake_rows(modified, "handshake-validate")["status"],
                "inconclusive",
            )

    def test_handshake_repeated_stages_preserve_valid_prefixes(self):
        original = self.handshake()
        rows = []
        for index, message in enumerate((1, 2, 1, 3, 3, 4), 1):
            row = original[message - 1][:]
            row[:2] = [str(index), str(100 + index)]
            rows.append(row)
        data = r.handshake_rows(rows, "handshake-validate")
        self.assertEqual(data["status"], "candidate")
        self.assertEqual(data["metrics"]["structural_candidates"], 1)
        self.assertEqual(data["metrics"]["repeated_stage_rows"], 2)
        self.assertEqual(data["metrics"]["message_1"], 2)
        # Tolerating duplicates must not weaken peer, replay or timing checks.
        for column, value in ((1, "1000"), (2, "02:00:00:00:00:03"), (5, "99")):
            modified = [row[:] for row in rows]
            modified[-1][column] = value
            self.assertEqual(
                r.handshake_rows(modified, "handshake-validate")["status"],
                "inconclusive",
            )
        self.assertEqual(
            r.handshake_rows(rows[:-1], "handshake-validate")["status"], "inconclusive"
        )

    def test_all_capture_routes(self):
        for mode in (
            r.TITLES.keys() - r.CONFIG_MODES - r.PMKID_MODES - {"wordlist-analyze"}
        ):

            def query(_path, _filter, fields):
                return [[""] * len(fields)]

            with (
                self.subTest(mode=mode),
                patch.object(r, "query_capture", side_effect=query),
            ):
                data = r.analyze(mode, self.input)
                self.assertEqual(data["analysis"], r.TITLES[mode])
                self.assertTrue(data["limitations"])
        with patch.object(
            r, "query_capture", return_value=[["1", "1", "4"], ["2", "4", ""]]
        ):
            data = r.analyze("enterprise-eap", self.input)
            self.assertEqual(data["status"], "review")
            self.assertEqual(data["metrics"]["failure_frames"], 1)
        with patch.object(
            r, "query_capture", return_value=[["1", "35,36,106,107,108"]]
        ):
            self.assertEqual(
                r.analyze("wifi-generation", self.input)["metrics"][
                    "eht_capability_frames"
                ],
                1,
            )
        with patch.object(r, "query_capture", return_value=[["0x000c", "0", "1", "1"]]):
            self.assertEqual(
                r.analyze("pmf-analysis", self.input)["metrics"][
                    "unprotected_disconnect_frames"
                ],
                1,
            )
        with patch.object(r, "query_capture", return_value=[["0", "12", "0", "1"]]):
            self.assertEqual(r.analyze("client-threat", self.input)["status"], "review")

    def test_ap_indicators_baseline_and_privacy(self):
        rows = [
            ["02:00:00:00:00:01", "private_ssid", "1", "8", "4"],
            ["02:00:00:00:00:02", "private_ssid", "0", "", ""],
        ]
        self.assertEqual(
            r.ap_indicators(rows, "rogue-ap", None)["status"], "baseline_required"
        )
        baseline = self.put("baseline", '{"approved_bssids":["02:00:00:00:00:01"]}')
        data = r.ap_indicators(rows, "rogue-ap", baseline)
        self.assertEqual(data["metrics"]["not_in_baseline_aps"], 1)
        self.assertNotIn("02:00:", json.dumps(data))
        self.assertNotIn("private_ssid", json.dumps(data))
        self.assertEqual(r.ap_indicators(rows, "evil-twin", None)["status"], "review")
        with self.assertRaises(r.ResearchError):
            r.ap_indicators(
                rows, "rogue-ap", self.put("badbaseline", '{"approved_bssids":[]}')
            )

    def test_report_real_outputs_and_unavailable_sections(self):
        manifest = self.put(
            "manifest.json",
            json.dumps({"sae-analysis": "hostapd.conf", "pmkid-analyze": "missing"}),
        )
        output = self.root / "audit.md"
        self.assertEqual(self.call("audit-report", manifest, output)[0], 0)
        text = output.read_text()
        self.assertIn("WPA3-SAE Analysis", text)
        self.assertIn("not_assessed", text)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("N8!", text)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(self.call("audit-report", manifest, output)[0], 2)
        with self.assertRaises(r.ResearchError):
            r.audit_report(self.put("invalidmanifest", '{"unknown":"hostapd.conf"}'))

    def test_report_baseline_objects_and_relative_paths(self):
        folder = self.root / "nested"
        folder.mkdir()
        baseline = folder / "approved.json"
        baseline.write_text('{"approved_bssids":["02:00:00:00:00:01"]}')
        manifest = folder / "report.json"
        manifest.write_text(
            json.dumps(
                {
                    "rogue-ap": {
                        "file": "../" + self.input.name,
                        "baseline": "approved.json",
                    },
                    "sae-analysis": {"file": "../hostapd.conf"},
                }
            )
        )
        rows = [
            ["02:00:00:00:00:01", "PRIVATE_SSID", "1", "8", "4"],
            ["02:00:00:00:00:02", "PRIVATE_SSID", "0", "", ""],
        ]
        with patch.object(r, "query_capture", return_value=rows) as query:
            text = r.audit_report(manifest)
        self.assertEqual(query.call_args.args[0], folder / ("../" + self.input.name))
        self.assertIn("not in baseline aps: 1", text)
        self.assertIn("Unavailable sections: 0", text)
        self.assertNotIn("baseline_required", text)
        self.assertNotIn("PRIVATE_SSID", text)
        self.assertNotIn(str(self.root), text)
        baseline.unlink()
        with patch.object(r, "query_capture", return_value=rows):
            text = r.audit_report(manifest)
        self.assertIn("not_assessed", text)
        self.assertIn("Unavailable sections: 1", text)

    def test_report_rejects_ambiguous_options_before_analysis(self):
        for value in (
            {"file": ""},
            {"file": "capture", "baseline": None},
            {"file": "capture", "baseline": ""},
            {"file": "capture", "unknown": "x"},
            {"baseline": "baseline"},
            {"file": True},
        ):
            with self.subTest(value=value), self.assertRaises(r.ResearchError):
                r.manifest_entries({"rogue-ap": value})
        with self.assertRaises(r.ResearchError):
            r.manifest_entries(
                {"frame-analysis": {"file": "capture", "baseline": "baseline"}}
            )
        self.assertEqual(
            r.manifest_entries({"frame-analysis": "capture"}),
            [("frame-analysis", "capture", None)],
        )

    def test_line_budgets_and_private_io_failures(self):
        for content in (b"x" * 8193, b"\n" * 100001):
            with self.assertRaises(r.ResearchError):
                r.bounded_lines(content)
        self.assertEqual(r.bounded_lines(b"x\r\ny\n"), [b"x", b"y"])
        with patch.object(r, "analyze", side_effect=OSError("SECRET_INPUT_PATH")):
            code, out, err = self.call("wordlist-analyze", self.input)
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET_INPUT_PATH", out + err)

    def test_real_subprocess_contract_failure_and_output_budget(self):
        # An executable fixture exercises Popen, inherited descriptor, fields,
        # literal input handling and output limits. It is NOT a tshark validation.
        tool = self.put(
            "tshark",
            f"#!{sys.executable}\n"
            + """
import os, sys
args = sys.argv[1:]
assert args[:2] == ['-n', '-r']
assert args[3:8] == ['-c', '20000', '-Y', 'wlan', '-T']
with open(args[2], 'rb') as stream:
    assert stream.read() == b'synthetic bytes\\n'
mode = os.environ.get('FIXTURE_MODE', '')
diagnostics = {
    'fail': 'SECRET',
    'unsupported': "Some fields aren't valid: SECRET_FIELD",
    'invalid': "The file SECRET_INPUT isn't a capture file in a format TShark understands.",
    'truncated': 'The file SECRET_INPUT appears to have been cut short in the middle of a packet.',
    'permissions': 'SECRET_INPUT: Permission denied',
}
if mode in diagnostics:
    print(diagnostics[mode], file=sys.stderr)
    sys.exit(1)
if mode == 'stderr-large':
    sys.stderr.buffer.write(b'SECRET' * 12000)
else:
    print('PRIVATE_WARNING', file=sys.stderr)
if mode == 'large':
    sys.stdout.buffer.write(b'x' * (4 * 1024 * 1024 + 1))
else:
    print('1\\t2')
""",
        )
        tool.chmod(0o700)
        with patch.object(r.shutil, "which", return_value=str(tool)):
            self.assertEqual(
                r.query_capture(self.input, "wlan", ["frame.number", "wlan.fc.type"]),
                [["1", "2"]],
            )
            # A selector that expires immediately exercises timeout cleanup
            # without delaying the suite or leaving the child running.
            with patch.object(r.selectors, "DefaultSelector") as selector:
                selector.return_value.__enter__.return_value.select.return_value = []
                with self.assertRaises(r.ResearchError) as caught:
                    r.query_capture(
                        self.input, "wlan", ["frame.number", "wlan.fc.type"]
                    )
                self.assertIn("15-second", str(caught.exception))
            for mode, expected in (
                ("fail", "failed to inspect"),
                ("large", "4 MiB"),
                ("unsupported", "dissector fields"),
                ("invalid", "supported capture file"),
                ("truncated", "truncated"),
                ("permissions", "permissions"),
                ("stderr-large", "64 KiB"),
            ):
                with (
                    patch.dict(os.environ, {"FIXTURE_MODE": mode}),
                    self.assertRaises(r.ResearchError) as caught,
                ):
                    r.query_capture(
                        self.input, "wlan", ["frame.number", "wlan.fc.type"]
                    )
                self.assertNotIn("SECRET", str(caught.exception))
                self.assertIn(expected, str(caught.exception))
        with (
            patch.object(r.shutil, "which", return_value=None),
            self.assertRaises(r.ResearchError),
        ):
            r.query_capture(self.input, "wlan", [])


if __name__ == "__main__":
    unittest.main()
