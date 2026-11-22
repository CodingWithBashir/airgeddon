#!/usr/bin/env python3
"""Offline integration with real tshark and generated PCAP/PCAPNG byte fixtures.

No packets are transmitted. All addresses, SSIDs and key material are synthetic;
EAPOL messages are structural test inputs, not cryptographically valid evidence.
Set AIRGEDDON_REQUIRE_TSHARK_TESTS=1 in CI to make a missing tshark a failure.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("research", ROOT / "scripts/research.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

TSHARK = shutil.which("tshark")
AP = bytes.fromhex("020000000001")
OTHER_AP = bytes.fromhex("020000000003")
CLIENT = bytes.fromhex("020000000002")
SSID = b"synthetic-private-ssid"


def wlan_header(control, destination, source, bssid):
    return struct.pack("<HH6s6s6sH", control, 0, destination, source, bssid, 0)


def element(number, body):
    return bytes((number, len(body))) + body


def beacon(ap, secure):
    fixed = struct.pack("<QHH", 0, 100, 0x0011 if secure else 0x0001)
    tags = element(0, SSID) + element(1, b"\x82\x84\x8b\x96")
    if secure:
        # RSN v1, CCMP group/pairwise cipher, PSK AKM, PMF capable+required.
        rsn = bytes.fromhex("0100000fac040100000fac040100000fac02c000")
        tags += element(48, rsn)
    return wlan_header(0x0080, b"\xff" * 6, ap, ap) + fixed + tags


def eapol_frame(body, packet_type, from_ap):
    # FromDS: SA is addr3 (AP); ToDS: SA is addr2 (client).
    header = (
        wlan_header(0x0208, CLIENT, AP, AP)
        if from_ap
        else wlan_header(0x0108, AP, CLIENT, AP)
    )
    snap = bytes.fromhex("aaaa03000000888e")
    return header + snap + struct.pack("!BBH", 2, packet_type, len(body)) + body


def key_message(message):
    flags = {1: 0x008A, 2: 0x010A, 3: 0x13CA, 4: 0x030A}
    nonce = bytes((message,)) * 32 if message != 4 else b"\0" * 32
    body = struct.pack(
        "!BHHQ", 2, flags[message], 16 if message != 4 else 0, 7 if message < 3 else 8
    )
    body += nonce + b"\0" * (16 + 8 + 8 + 16) + struct.pack("!H", 0)
    return eapol_frame(body, 3, message in {1, 3})


def packets():
    frames = [beacon(AP, True), beacon(OTHER_AP, False)]
    frames += [wlan_header(0x00C0, CLIENT, AP, AP) + struct.pack("<H", 7)]
    frames += [key_message(message) for message in range(1, 5)]
    # A complete EAP-MD5 request structure followed by EAP Failure.
    request = struct.pack("!BBHBB", 1, 1, 22, 4, 16) + b"\0" * 16
    frames += [
        eapol_frame(request, 0, True),
        eapol_frame(struct.pack("!BBH", 4, 1, 4), 0, True),
    ]
    return frames


def pcap(frames):
    # DLT_IEEE802_11; all frames use increasing timestamps one second apart.
    output = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    for index, frame in enumerate(frames, 1):
        output += (
            struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)) + frame
        )
    return output


def pcapng(frames):
    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    output = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    output += block(1, struct.pack("<HHI", 105, 0, 65535))
    for index, frame in enumerate(frames, 1):
        stamp = (1700000000 + index) * 1000000
        body = struct.pack(
            "<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame)
        )
        output += block(6, body + frame)
    return output


@unittest.skipUnless(
    TSHARK, "tshark is not installed; real-dissector integration was not run"
)
class TsharkIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        frames = packets()
        self.captures = []
        for suffix, encode in (("pcap", pcap), ("pcapng", pcapng)):
            path = self.root / ("synthetic capture $(literal)." + suffix)
            path.write_bytes(encode(frames))
            self.captures.append(path)

    def assert_private(self, data):
        serialized = json.dumps(data)
        self.assertNotIn(SSID.decode(), serialized)
        self.assertNotIn("02:00:00:00:00:", serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_all_capture_routes_pcap_and_pcapng(self):
        baseline = self.root / "baseline.json"
        baseline.write_text('{"approved_bssids":["02:00:00:00:00:01"]}')
        modes = r.TITLES.keys() - r.CONFIG_MODES - r.PMKID_MODES - {"wordlist-analyze"}
        for path in self.captures:
            before = hashlib.sha256(path.read_bytes()).digest()
            for mode in sorted(modes):
                with self.subTest(format=path.suffix, mode=mode):
                    data = r.analyze(
                        mode, path, baseline if mode == "rogue-ap" else None
                    )
                    self.assert_private(data)
                    metrics = data["metrics"]
                    if mode in {"handshake-validate", "eapol-analysis"}:
                        self.assertEqual(data["status"], "candidate")
                        self.assertEqual(metrics["structural_candidates"], 1)
                        self.assertEqual(
                            [metrics[f"message_{i}"] for i in range(1, 5)], [1, 1, 1, 1]
                        )
                    elif mode == "enterprise-eap":
                        self.assertEqual(metrics["md5_method_frames"], 1)
                        self.assertEqual(metrics["failure_frames"], 1)
                    elif mode == "rogue-ap":
                        self.assertEqual(metrics["observed_aps"], 2)
                        self.assertEqual(metrics["not_in_baseline_aps"], 1)
                    elif mode == "evil-twin":
                        self.assertEqual(
                            metrics["security_profile_divergence_groups"], 1
                        )
                    elif mode == "pmf-analysis":
                        self.assertEqual(metrics["pmf_required_advertisements"], 1)
                        self.assertEqual(metrics["unprotected_disconnect_frames"], 1)
                    else:
                        self.assertEqual(metrics["wireless_frames"], len(packets()))
                        if mode != "wifi-generation":
                            self.assertEqual(metrics["management_frames"], 3)
                        if mode in {"auth-diagnostics", "client-threat"}:
                            self.assertEqual(metrics["deauthentication_frames"], 1)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_partial_handshake_is_inconclusive(self):
        path = self.root / "partial.pcap"
        path.write_bytes(pcap([key_message(1), key_message(2)]))
        data = r.analyze("handshake-validate", path)
        self.assertEqual(data["status"], "inconclusive")
        self.assertEqual(data["metrics"]["structural_candidates"], 0)

    def test_malformed_capture_is_error(self):
        path = self.root / "invalid.pcap"
        path.write_bytes(b"not a capture\nPRIVATE_DIAGNOSTIC_MARKER")
        with self.assertRaises(r.ResearchError) as caught:
            r.analyze("frame-analysis", path)
        self.assertNotIn("PRIVATE_DIAGNOSTIC_MARKER", str(caught.exception))
        self.assertNotIn(str(path), str(caught.exception))

    def test_public_cli_and_report(self):
        output = subprocess.run(
            [
                "bash",
                str(ROOT / "airgeddon.sh"),
                "--lab",
                "handshake-validate",
                str(self.captures[0]),
            ],
            capture_output=True,
            timeout=25,
            check=False,
        )
        self.assertEqual(output.returncode, 0, output.stderr.decode())
        self.assertEqual(json.loads(output.stdout)["status"], "candidate")
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "frame-analysis": self.captures[1].name,
                    "handshake-validate": self.captures[0].name,
                }
            )
        )
        report = r.audit_report(manifest)
        self.assertIn("Status: candidate", report)
        self.assertNotIn("not_assessed", report)
        self.assertNotIn(SSID.decode(), report)


if __name__ == "__main__":
    if not TSHARK and os.environ.get("AIRGEDDON_REQUIRE_TSHARK_TESTS") == "1":
        raise SystemExit(
            "Required real-tshark integration cannot run: tshark is missing."
        )
    unittest.main()
