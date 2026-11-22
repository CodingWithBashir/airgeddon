#!/usr/bin/env python3
"""Functional local wireless research and evidence tools. Never executes input files."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

MAX_PACKETS = 20000
MAX_TEXT = 32 * 1024 * 1024
MAX_EVIDENCE = 512 * 1024 * 1024
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
TITLES = {
    "wpa-analysis": "WPA/WPA2 Analysis",
    "sae-analysis": "WPA3-SAE Analysis",
    "pmkid-forensics": "PMKID Forensics",
    "eapol-analysis": "EAPOL Analysis",
    "wps-assessment": "WPS Assessment",
    "enterprise-eap": "Enterprise EAP Analysis",
    "auth-diagnostics": "Authentication Diagnostics",
    "frame-analysis": "802.11 Frame Analysis",
    "pmf-analysis": "PMF Analysis",
    "wifi-generation": "Wi-Fi 6/7 Analysis",
    "rogue-ap": "Rogue AP Detection",
    "evil-twin": "Evil Twin Detection",
    "client-threat": "Client Threat Analysis",
    "handshake-validate": "Handshake Validation",
    "pmkid-analyze": "PMKID File Analysis",
    "wordlist-analyze": "Wordlist Analyzer",
}
CONFIG_MODES = {"wpa-analysis", "sae-analysis", "wps-assessment"}
PMKID_MODES = {"pmkid-forensics", "pmkid-analyze"}
LIMIT = "At most 20,000 input packets are inspected; partial captures and missing dissector fields limit conclusions."


class ResearchError(Exception):
    """Use static messages, never embed packet contents, secrets or input paths."""


def result(mode, metrics, findings, status="observed", limits=()):
    return {
        "analysis": TITLES.get(mode, mode),
        "status": status,
        "metrics": metrics,
        "findings": findings,
        "limitations": list(limits),
    }


def regular_input(path):
    try:
        stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb")
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            stream.close()
            raise ResearchError(
                "Input must be a readable regular file, not a device or pipe."
            )
        return stream
    except (OSError, ValueError, UnicodeError):
        raise ResearchError(
            "Input could not be opened as a readable regular file."
        ) from None


def small_input(path, maximum=MAX_TEXT):
    with regular_input(path) as stream:
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ResearchError("Input is empty or exceeds its size budget.")
    return data


def unique_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ResearchError("Duplicate JSON keys are not accepted.")
        output[key] = value
    return output


def json_input(path, maximum=1024 * 1024):
    try:
        return json.loads(small_input(path, maximum), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ResearchError("Expected a valid UTF-8 JSON document.") from None


def unicast(value):
    return (
        bool(MAC.fullmatch(value))
        and value.lower() != "00:00:00:00:00:00"
        and not int(value[:2], 16) & 1
    )


def numbers(cell):
    output = []
    for value in cell.split(","):
        try:
            number = int(value, 16) if value.startswith("0x") else int(value)
            if 0 <= number <= 2**64 - 1:
                output.append(number)
        except ValueError:
            pass
    return output


def query_capture(path, display_filter, fields):
    executable = shutil.which("tshark")
    if not executable:
        raise ResearchError(
            "Install a recent tshark to inspect capture files; no result was inferred."
        )
    # Pass the already validated descriptor so replacing a pathname cannot redirect
    # tshark to a device/FIFO. Both processes open the same regular-file evidence.
    with regular_input(path) as stream:
        if not stream.read(1):
            raise ResearchError("Capture is empty.")
        stream.seek(0)
        command = [
            executable,
            "-n",
            "-r",
            f"/dev/fd/{stream.fileno()}",
            "-c",
            str(MAX_PACKETS),
            "-Y",
            display_filter,
            "-T",
            "fields",
        ]
        for field in fields:
            command += ["-e", field]
        output = bytearray()
        try:
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(stream.fileno(),),
                env={**os.environ, "LC_ALL": "C"},
            ) as process:
                try:
                    deadline = time.monotonic() + 15
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0 or not selector.select(remaining):
                                raise ResearchError(
                                    "Capture inspection exceeded its 15-second budget."
                                )
                            chunk = os.read(process.stdout.fileno(), 65536)
                            if not chunk:
                                break
                            output.extend(chunk)
                            if len(output) > 4 * 1024 * 1024:
                                raise ResearchError(
                                    "Capture inspection exceeded its 4 MiB output budget."
                                )
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    if process.returncode:
                        raise ResearchError(
                            "Capture could not be inspected or required dissector fields are unsupported."
                        )
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            raise ResearchError(
                "Capture inspection failed or exceeded its 15-second budget."
            ) from None
    rows = [line.split("\t") for line in output.decode("utf-8", "replace").splitlines()]
    if len(rows) > MAX_PACKETS or any(len(row) != len(fields) for row in rows):
        raise ResearchError(
            "Incomplete or oversized capture-parser output; no result was inferred."
        )
    return rows


def handshake_rows(rows, mode):
    stages = {}
    complete = set()
    counts = Counter()
    malformed = 0
    for frame, timestamp, source, destination, message, counter in rows:
        try:
            frame, time, message, counter = (
                int(frame),
                float(timestamp),
                int(message),
                int(counter),
            )
            if not (
                0 < frame <= MAX_PACKETS
                and math.isfinite(time)
                and abs(time) < 1e12
                and message in {1, 2, 3, 4}
                and 0 <= counter < 2**64
                and unicast(source)
                and unicast(destination)
                and source.lower() != destination.lower()
            ):
                raise ValueError
        except ValueError:
            malformed += 1
            continue
        counts[message] += 1
        ap, client = (
            (source.lower(), destination.lower())
            if message in {1, 3}
            else (destination.lower(), source.lower())
        )
        key = (ap, client, counter if message in {1, 2} else counter - 1)
        state = stages.setdefault(key, {})
        previous = state.get(message - 1)
        if message == 1:
            state.clear()
            state[1] = (frame, time)
        elif previous and frame > previous[0] and 0 <= time - previous[1] <= 10:
            state[message] = (frame, time)
            if message == 4:
                complete.add(key)
    metrics = {
        "message_1": counts[1],
        "message_2": counts[2],
        "message_3": counts[3],
        "message_4": counts[4],
        "structural_candidates": len(complete),
        "unusable_rows": malformed,
    }
    return result(
        mode,
        metrics,
        [
            "Matching same-peer M1-M4 structure/replay/timing candidates were observed."
            if complete
            else "No complete candidate meeting conservative checks was observed."
        ],
        "candidate" if complete else "inconclusive",
        [
            LIMIT,
            "MICs, nonces, credentials, cryptographic authenticity and recoverability were not verified. Strict checks may miss valid partial/retransmitted exchanges.",
        ],
    )


def capture_analysis(mode, path, baseline=None):
    if mode in {"handshake-validate", "eapol-analysis"}:
        fields = [
            "frame.number",
            "frame.time_epoch",
            "wlan.sa",
            "wlan.da",
            "wlan_rsna_eapol.keydes.msgnr",
            "wlan_rsna_eapol.keydes.replay_counter",
        ]
        return handshake_rows(query_capture(path, "eapol", fields), mode)
    if mode == "enterprise-eap":
        rows = query_capture(path, "eap", ["frame.number", "eap.code", "eap.type"])
        codes, types = Counter(), Counter()
        for _, code, method in rows:
            codes.update(numbers(code))
            types.update(numbers(method))
        metrics = {
            "eap_frames": len(rows),
            "requests": codes[1],
            "responses": codes[2],
            "success_frames": codes[3],
            "failure_frames": codes[4],
            "tls_method_frames": types[13],
            "ttls_method_frames": types[21],
            "peap_method_frames": types[25],
            "md5_method_frames": types[4],
            "leap_method_frames": types[17],
        }
        return result(
            mode,
            metrics,
            [
                "EAP-MD5 or LEAP method evidence warrants review."
                if types[4] or types[17]
                else "EAP code and method evidence was counted without collecting identities."
            ],
            "review"
            if types[4] or types[17]
            else "observed"
            if rows
            else "inconclusive",
            [
                LIMIT,
                "Success/failure packets do not authenticate a server or prove credential correctness. Identities, certificates and tunnel contents are not extracted.",
            ],
        )
    if mode in {"rogue-ap", "evil-twin"}:
        rows = query_capture(
            path,
            "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5",
            [
                "wlan.bssid",
                "wlan.ssid",
                "wlan.fixed.capabilities.privacy",
                "wlan.rsn.akms.type",
                "wlan.rsn.pcs.type",
            ],
        )
        return ap_indicators(rows, mode, baseline)
    if mode == "wifi-generation":
        rows = query_capture(path, "wlan", ["frame.number", "wlan.ext_tag.number"])
        tags = [set(numbers(row[1])) for row in rows]
        metrics = {
            "wireless_frames": len(rows),
            "he_capability_frames": sum(35 in tag for tag in tags),
            "he_operation_frames": sum(36 in tag for tag in tags),
            "eht_capability_frames": sum(108 in tag for tag in tags),
            "eht_operation_frames": sum(106 in tag for tag in tags),
            "multi_link_element_frames": sum(107 in tag for tag in tags),
        }
        return result(
            mode,
            metrics,
            [
                "HE/EHT extension-element evidence was counted, not a Wi-Fi generation certificate."
            ],
            "observed"
            if any(tag & {35, 36, 106, 107, 108} for tag in tags)
            else "inconclusive",
            [
                LIMIT,
                "Advertised elements do not prove actual Wi-Fi 6/7 operation, throughput, interoperability or band support.",
            ],
        )
    if mode == "pmf-analysis":
        rows = query_capture(
            path,
            "wlan",
            [
                "wlan.fc.type_subtype",
                "wlan.fc.protected",
                "wlan.rsn.capabilities.mfpc",
                "wlan.rsn.capabilities.mfpr",
            ],
        )
        capable = required = unprotected = protected = inconsistent = 0
        for subtype, flag, mfpc, mfpr in rows:
            capable += 1 in numbers(mfpc)
            required += 1 in numbers(mfpr)
            inconsistent += 1 in numbers(mfpr) and 0 in numbers(mfpc)
            if set(numbers(subtype)) & {10, 12}:
                protected += 1 in numbers(flag)
                unprotected += 0 in numbers(flag)
        return result(
            mode,
            {
                "wireless_frames": len(rows),
                "pmf_capable_advertisements": capable,
                "pmf_required_advertisements": required,
                "unprotected_disconnect_frames": unprotected,
                "protected_disconnect_frames": protected,
                "inconsistent_advertisements": inconsistent,
            },
            [
                "PMF advertisement and disconnect-frame evidence was observed; confirm negotiated client policy separately."
            ],
            "review" if inconsistent else "observed" if rows else "inconclusive",
            [
                LIMIT,
                "Unprotected disconnect frames alone do not prove a PMF bypass or attack; no cryptographic protection check was performed.",
            ],
        )
    fields = [
        "wlan.fc.type",
        "wlan.fc.type_subtype",
        "wlan.fc.protected",
        "wlan.fc.retry",
    ]
    if mode == "auth-diagnostics":
        fields += ["wlan.fixed.status_code", "wlan.fixed.reason_code"]
    rows = query_capture(path, "wlan", fields)
    types, subtypes = Counter(), Counter()
    protected = retries = unprotected_disconnect = statuses = reasons = 0
    for row in rows:
        kind, subtype, protection, retry = row[:4]
        types.update(numbers(kind))
        subtypes.update(numbers(subtype))
        protected += 1 in numbers(protection)
        retries += 1 in numbers(retry)
        unprotected_disconnect += bool(
            set(numbers(subtype)) & {10, 12}
        ) and 0 in numbers(protection)
        if mode == "auth-diagnostics":
            statuses += any(value != 0 for value in numbers(row[4]))
            reasons += bool(numbers(row[5]))
    metrics = {
        "wireless_frames": len(rows),
        "management_frames": types[0],
        "control_frames": types[1],
        "data_frames": types[2],
        "protected_flag_frames": protected,
        "retry_flag_frames": retries,
    }
    if mode in {"auth-diagnostics", "client-threat"}:
        metrics.update(
            {
                "authentication_frames": subtypes[11],
                "deauthentication_frames": subtypes[12],
                "disassociation_frames": subtypes[10],
                "probe_request_frames": subtypes[4],
                "unprotected_disconnect_frames": unprotected_disconnect,
            }
        )
    if mode == "auth-diagnostics":
        metrics.update(
            {"nonzero_status_frames": statuses, "reason_code_frames": reasons}
        )
    return result(
        mode,
        metrics,
        [
            "Observed frames were counted without extracting client identities or payloads."
        ],
        "review"
        if mode == "client-threat" and unprotected_disconnect
        else "observed"
        if rows
        else "inconclusive",
        [
            LIMIT,
            "Retries, failures, probes and disconnects can be legitimate. Counts alone do not establish an attack, cause or affected client.",
        ],
    )


def ap_indicators(rows, mode, baseline):
    access_points = set()
    by_ssid = defaultdict(lambda: {"aps": set(), "profiles": set()})
    incomplete = 0
    for bssid, ssid, privacy, akms, ciphers in rows:
        bssid = bssid.lower()
        if not unicast(bssid):
            incomplete += 1
            continue
        access_points.add(bssid)
        if not ssid:
            continue
        group = by_ssid[hashlib.sha256(ssid.encode()).digest()]
        group["aps"].add(bssid)
        if numbers(privacy):
            group["profiles"].add(
                (
                    tuple(numbers(privacy)),
                    tuple(sorted(numbers(akms))),
                    tuple(sorted(numbers(ciphers))),
                )
            )
        else:
            incomplete += 1
    multiple = sum(len(group["aps"]) > 1 for group in by_ssid.values())
    divergent = sum(
        len(group["aps"]) > 1 and len(group["profiles"]) > 1
        for group in by_ssid.values()
    )
    metrics = {
        "observed_aps": len(access_points),
        "multi_ap_ssid_groups": multiple,
        "security_profile_divergence_groups": divergent,
        "incomplete_rows": incomplete,
    }
    if mode == "rogue-ap":
        if baseline is None:
            return result(
                mode,
                metrics,
                [
                    "An approved-AP baseline is required to identify unlisted access points."
                ],
                "baseline_required",
                [
                    LIMIT,
                    "No rogue verdict is possible from an SSID or multiple BSSIDs alone.",
                ],
            )
        document = json_input(baseline)
        if (
            not isinstance(document, dict)
            or set(document) != {"approved_bssids"}
            or not isinstance(document["approved_bssids"], list)
            or not 1 <= len(document["approved_bssids"]) <= 4096
            or not all(
                isinstance(value, str) and unicast(value)
                for value in document["approved_bssids"]
            )
        ):
            raise ResearchError(
                "Baseline must contain 1-4096 valid approved_bssids and no other keys."
            )
        unlisted = access_points - {
            value.lower() for value in document["approved_bssids"]
        }
        metrics["not_in_baseline_aps"] = len(unlisted)
        return result(
            mode,
            metrics,
            [
                "Unlisted AP evidence requires owner verification; it is not proof of a rogue device."
            ],
            "review" if unlisted else "observed" if access_points else "inconclusive",
            [
                LIMIT,
                "Incomplete baselines, address changes and spoofing can invalidate classification. Baseline and observed identifiers are not printed.",
            ],
        )
    return result(
        mode,
        metrics,
        [
            "Same-name APs with differing advertised security profiles warrant review."
            if divergent
            else "No differing same-name security profiles were established in the inspected sample."
        ],
        "review" if divergent else "inconclusive",
        [
            LIMIT,
            "Multiple APs are normal in managed networks. Profile changes may be legitimate; these indicators do not confirm or exclude an evil twin.",
        ],
    )


def config_input(path):
    try:
        text = small_input(path, 1024 * 1024).decode("utf-8")
    except UnicodeError:
        raise ResearchError("Expected a UTF-8 hostapd configuration.") from None
    known = {
        "wpa",
        "wpa_key_mgmt",
        "rsn_pairwise",
        "wpa_pairwise",
        "ieee80211w",
        "wps_state",
        "ap_setup_locked",
        "sae_pwe",
        "wpa_passphrase",
        "wpa_psk",
        "sae_password",
    }
    config = {}
    credentials = {"wpa_passphrase", "wpa_psk", "sae_password"}
    # Only LF/CRLF terminate configuration lines. Other whitespace may be part
    # of a credential and must not change the value/byte length being audited.
    for raw in text.split("\n"):
        line = raw.removesuffix("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise ResearchError(
                "Expected hostapd key=value syntax; input is never executed."
            )
        key, value = line.split("=", 1)
        key = key.strip()
        if key in {"bss", "include"}:
            raise ResearchError(
                "Supply one effective self-contained BSS configuration; includes and multiple BSS sections are not merged."
            )
        if key in known:
            if key in config:
                raise ResearchError(
                    "Duplicate assessed configuration keys are ambiguous."
                )
            config[key] = value if key in credentials else value.strip()
    if "wpa" not in config:
        raise ResearchError("An explicit hostapd wpa setting is required.")
    for key, allowed in {
        "wpa": {"0", "1", "2", "3"},
        "ieee80211w": {"0", "1", "2"},
        "wps_state": {"0", "1", "2"},
        "ap_setup_locked": {"0", "1"},
        "sae_pwe": {"0", "1", "2"},
    }.items():
        if key in config and config[key] not in allowed:
            raise ResearchError("An assessed hostapd setting has an unsupported value.")
    return config


def strength(secret):
    common = secret.casefold() in {
        "password",
        "password123",
        "password123!",
        "12345678",
        "qwerty123",
        "correcthorsebatterystaple",
    }
    repetition = len(set(secret)) <= 2 or bool(re.fullmatch(r"(.{1,4})\1{2,}", secret))
    sequence = any(
        value in secret.casefold() for value in ("123456", "abcdef", "qwerty")
    )
    return {
        "characters": len(secret),
        "utf8_bytes": len(secret.encode("utf-8")),
        "common_example_match": common,
        "repeated_pattern": repetition,
        "obvious_sequence": sequence,
        "weak_heuristic": len(secret) < 12 or common or repetition or sequence,
    }


def config_analysis(mode, path):
    config = config_input(path)
    issues, notes = [], []
    if mode == "wps-assessment":
        enabled = config.get("wps_state", "0") != "0"
        if enabled:
            issues.append(
                "WPS is configured as enabled; disable it for a hardened baseline."
            )
        if enabled and config.get("ap_setup_locked") != "1":
            notes.append(
                "Setup lock is not explicitly enabled; no rate-limit or PIN test was run."
            )
        return result(
            mode,
            {
                "wps_configured_enabled": enabled,
                "setup_lock_explicit": config.get("ap_setup_locked") == "1",
            },
            issues + notes
            or ["No enabled WPS setting was observed in this configuration."],
            "review" if enabled else "no_flagged_issues",
            [
                "Configuration inspection only, not live WPS discovery or a PIN attack. Defaults/runtime overrides require separate verification."
            ],
        )
    keys = set(config.get("wpa_key_mgmt", "").split())
    ciphers = set(config.get("rsn_pairwise", config.get("wpa_pairwise", "")).split())
    if config["wpa"] != "2":
        issues.append(
            "RSN-only operation is not explicitly configured; review WPA1/mixed-mode exposure."
        )
    if not ciphers or not ciphers <= {"CCMP", "CCMP-256", "GCMP", "GCMP-256"}:
        issues.append(
            "Explicit modern RSN ciphers were not established; review TKIP/WEP and defaults."
        )
    if config.get("wps_state", "0") != "0":
        issues.append("WPS is configured as enabled.")
    if mode == "sae-analysis":
        if (
            not keys
            or not keys <= {"SAE", "FT-SAE", "WPA-PSK", "FT-PSK", "WPA-EAP-SUITE-B-192"}
            or not keys & {"SAE", "FT-SAE"}
        ):
            issues.append(
                "SAE key management was not established; enterprise WPA3 is not SAE."
            )
        if config.get("ieee80211w") != "2":
            issues.append("PMF is not configured as required for a pure WPA3 baseline.")
        if keys & {"WPA-PSK", "FT-PSK"}:
            notes.append("WPA2/WPA3 transition mode is not a pure WPA3-only baseline.")
        if keys & {"SAE", "FT-SAE"} and config.get("sae_pwe") not in {"1", "2"}:
            notes.append("SAE hash-to-element support was not explicitly established.")
    else:
        recognized = {
            "WPA-PSK",
            "FT-PSK",
            "WPA-PSK-SHA256",
            "WPA-EAP",
            "FT-EAP",
            "WPA-EAP-SHA256",
        }
        if not keys & recognized or not keys <= recognized | {"SAE", "FT-SAE"}:
            issues.append(
                "Recognized WPA2 key management was not explicitly established."
            )
        if config.get("ieee80211w") not in {"1", "2"}:
            notes.append("PMF is not explicitly enabled; assess client support.")
    credentials = [
        config[key].split("|", 1)[0] if key == "sae_password" else config[key]
        for key in ("wpa_passphrase", "wpa_psk", "sae_password")
        if key in config
    ]
    if any(strength(secret)["weak_heuristic"] for secret in credentials):
        issues.append(
            "An inline credential triggered the local weak-password heuristic; replace it with a unique random value."
        )
    if (
        "wpa_passphrase" in config
        and not 8 <= len(config["wpa_passphrase"].encode()) <= 63
    ):
        issues.append(
            "The hostapd wpa_passphrase value is outside its 8-63 byte range."
        )
    if "wpa_psk" in config and not re.fullmatch(r"[0-9a-fA-F]{64}", config["wpa_psk"]):
        issues.append("The inline raw PSK is not 64 hexadecimal characters.")
    if not credentials:
        notes.append(
            "No inline shared credential was inspected; external/enterprise secrets are not resolved."
        )
    if "WPA-EAP-SUITE-B-192" in keys:
        notes.append(
            "Enterprise cipher suites and certificate policy require separate assessment."
        )
    return result(
        mode,
        {"flagged_issues": len(issues), "review_notes": len(notes)},
        issues + notes or ["No issues flagged by the supported static checklist."],
        "issues_found" if issues else "review" if notes else "no_flagged_issues",
        [
            "Configuration review is not a live network, interoperability, cryptographic or exploit test. Secrets and network identifiers are not printed."
        ],
    )


def bounded_lines(data):
    # Split only LF/CRLF without allocating millions of tiny objects first.
    lines = data.split(b"\n", 100001)
    if lines and lines[-1] == b"":
        lines.pop()
    if len(lines) > 100000 or any(len(line) > 8193 for line in lines):
        raise ResearchError(
            "Input exceeds 100,000 entries or an 8,192-byte line budget."
        )
    lines = [line.removesuffix(b"\r") for line in lines]
    if any(len(line) > 8192 for line in lines):
        raise ResearchError("Input exceeds the 8,192-byte line budget.")
    return lines


def pmkid_analysis(mode, path):
    lines = bounded_lines(small_input(path))
    valid = invalid = duplicate = ignored = 0
    seen = set()
    for raw in lines:
        if not raw.strip() or raw.startswith(b"#"):
            continue
        if len(raw) > 8192:
            raise ResearchError("PMKID line exceeds the supported size budget.")
        try:
            parts = raw.decode("ascii").split("*")
        except UnicodeError:
            raise ResearchError(
                "Expected an ASCII PMKID text export, not a binary capture."
            ) from None
        if parts[:2] == ["WPA", "02"]:
            ignored += 1
            continue
        fields = (
            parts[2:6]
            if len(parts) == 9 and parts[:2] == ["WPA", "01"] and not any(parts[6:])
            else parts
        )
        if len(fields) != 4:
            invalid += 1
            continue
        digest, ap, client, ssid = fields
        good = re.fullmatch(r"[0-9a-fA-F]{32}", digest) and digest != "0" * 32
        good = good and all(
            re.fullmatch(r"[0-9a-fA-F]{12}", value)
            and unicast(":".join(value[i : i + 2] for i in range(0, 12, 2)))
            for value in (ap, client)
        )
        good = (
            good
            and ap.lower() != client.lower()
            and len(ssid) <= 64
            and len(ssid) % 2 == 0
            and re.fullmatch(r"[0-9a-fA-F]*", ssid)
        )
        if not good:
            invalid += 1
            continue
        fingerprint = hashlib.sha256("*".join(fields).lower().encode()).digest()
        duplicate += fingerprint in seen
        seen.add(fingerprint)
        valid += 1
    if not (valid or invalid or ignored):
        raise ResearchError("No records found in the PMKID export.")
    return result(
        mode,
        {
            "valid_format_records": valid,
            "invalid_records": invalid,
            "duplicates": duplicate,
            "eapol_records_not_analyzed": ignored,
        },
        [
            "PMKID syntax and basic field sanity were checked without revealing identifiers or hashes."
        ],
        "structurally_valid" if valid and not invalid else "review",
        [
            "Only WPA*01 (22000) and legacy four-field text records are supported. Cryptographic authenticity and recoverability are not verified."
        ],
    )


def wordlist_analysis(path):
    total = duplicate = empty = eligible = encoding = whitespace = 0
    seen, salt = set(), os.urandom(16)
    data = small_input(path)
    lines = bounded_lines(data)
    for raw in lines:
        total += 1
        empty += not raw
        whitespace += raw != raw.strip()
        eligible += 8 <= len(raw) <= 63
        try:
            raw.decode("utf-8")
        except UnicodeError:
            encoding += 1
        digest = hashlib.sha256(salt + raw).digest()
        duplicate += digest in seen
        seen.add(digest)
    return result(
        "wordlist-analyze",
        {
            "entries": total,
            "duplicates": duplicate,
            "empty_entries": empty,
            "passphrase_length_entries": eligible,
            "invalid_utf8_entries": encoding,
            "edge_whitespace_entries": whitespace,
        },
        [
            "Candidate contents are never displayed; no generation, mutation or recovery job was run."
        ],
        "review" if duplicate or empty or encoding else "inspected",
        [
            "This is list hygiene, not a prediction of password-recovery success. Input budget: 32 MiB."
        ],
    )


def evidence_digest(path):
    digest, count = hashlib.sha256(), 0
    with regular_input(path) as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > MAX_EVIDENCE:
            raise ResearchError("Evidence exceeds the 512 MiB hashing budget.")
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_EVIDENCE:
                raise ResearchError(
                    "Evidence hashing budget exceeded; no record produced."
                )
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (
        after.st_size,
        after.st_mtime_ns,
    ) or count != after.st_size:
        raise ResearchError(
            "Evidence changed during hashing; no stable record produced."
        )
    return {
        "format": "airgeddon-evidence-v1",
        "algorithm": "SHA-256",
        "sha256": digest.hexdigest(),
        "bytes": count,
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
    }


def publish_private(path, text):
    temporary = None
    try:
        destination = Path(path)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=".airgeddon-evidence-",
            delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(text)
        os.link(temporary, destination, follow_symlinks=False)
    except (OSError, ValueError):
        raise ResearchError(
            "Output could not be created. Existing destinations are never overwritten; check directory permissions and hard-link support."
        ) from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def evidence_verify(path, record_path):
    record = json_input(record_path)
    if (
        not isinstance(record, dict)
        or set(record) != {"format", "algorithm", "sha256", "bytes", "recorded_utc"}
        or record.get("format") != "airgeddon-evidence-v1"
        or record.get("algorithm") != "SHA-256"
        or not isinstance(record.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
        or type(record.get("bytes")) is not int
        or not 0 <= record["bytes"] <= MAX_EVIDENCE
        or not isinstance(record.get("recorded_utc"), str)
    ):
        raise ResearchError("Unsupported evidence record schema.")
    actual = evidence_digest(path)
    match = actual["sha256"] == record["sha256"] and actual["bytes"] == record["bytes"]
    return result(
        "Evidence verification",
        {"matches_record": match},
        [
            "Digest and size match the supplied record."
            if match
            else "Evidence differs from the supplied digest or size."
        ],
        "match" if match else "mismatch",
        [
            "A matching digest is not proof of acquisition provenance, legal chain of custody or authenticity."
        ],
    )


def analyze(mode, path, baseline=None):
    if mode in CONFIG_MODES:
        return config_analysis(mode, path)
    if mode in PMKID_MODES:
        return pmkid_analysis(mode, path)
    if mode == "wordlist-analyze":
        return wordlist_analysis(path)
    return capture_analysis(mode, path, baseline)


def text_result(data):
    output = [data["analysis"], "Status: " + data["status"], "---------"]
    for key, value in data["metrics"].items():
        output.extend(textwrap.wrap(key.replace("_", " ") + ": " + str(value), 76))
    for heading in ("findings", "limitations"):
        output.append(heading.capitalize() + ":")
        for line in data[heading]:
            output.extend(
                textwrap.wrap(line, 76, initial_indent="  - ", subsequent_indent="    ")
            )
    return "\n".join(output)


def audit_report(manifest_path):
    manifest = json_input(manifest_path, 65536)
    if (
        not isinstance(manifest, dict)
        or not manifest
        or set(manifest) - TITLES.keys()
        or not all(
            isinstance(value, str) and value and "\0" not in value
            for value in manifest.values()
        )
    ):
        raise ResearchError(
            "Manifest must map supported analysis command names to local input paths."
        )
    try:
        base = Path(manifest_path).resolve().parent
    except (OSError, RuntimeError):
        raise ResearchError("Manifest directory could not be resolved.") from None
    sections = [
        "# AIRGEDDON ADVANCED EXTENSION",
        "",
        "Local evidence analysis only. Paths, credentials, packet payloads and peer identifiers are omitted.",
        "",
    ]
    for mode, value in manifest.items():
        try:
            data = analyze(mode, base / value)
        except ResearchError as error:
            data = result(mode, {}, [str(error)], "not_assessed")
        except OSError:
            data = result(
                mode, {}, ["A local input/output operation failed."], "not_assessed"
            )
        sections += [
            "## " + data["analysis"],
            "",
            "```text",
            text_result(data),
            "```",
            "",
        ]
    sections += [
        "## Recommendations",
        "Use WPA3 with required PMF where clients support it, disable WPS, update firmware and use unique random credentials.",
        "This report does not certify security, recoverability or live device compatibility. Review before sharing.",
        "",
    ]
    return "\n".join(sections)


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(
            2,
            "Invalid analysis arguments. Use --help; never pass passwords in command arguments.\n",
        )


def main(argv=None):
    parser = PrivateParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    aliases = {"wpa-analysis": ["wpa2-audit"], "sae-analysis": ["wpa3-audit"]}
    for command in TITLES:
        child = sub.add_parser(command, aliases=aliases.get(command, []))
        child.add_argument("file")
        child.add_argument("--text", action="store_true")
        if command == "rogue-ap":
            child.add_argument("--baseline")
    evidence = sub.add_parser("evidence")
    evidence.add_argument("file")
    evidence.add_argument("--record")
    evidence.add_argument("--text", action="store_true")
    verify = sub.add_parser("evidence-verify")
    verify.add_argument("file")
    verify.add_argument("record")
    verify.add_argument("--text", action="store_true")
    password = sub.add_parser("password-audit")
    password.add_argument("--stdin", action="store_true")
    password.add_argument("--text", action="store_true")
    report = sub.add_parser("audit-report")
    report.add_argument("manifest")
    report.add_argument("output", nargs="?")
    args = parser.parse_args(argv)
    args.command = {"wpa2-audit": "wpa-analysis", "wpa3-audit": "sae-analysis"}.get(
        args.command, args.command
    )
    try:
        if args.command in TITLES:
            data = analyze(args.command, args.file, getattr(args, "baseline", None))
        elif args.command == "evidence":
            record = evidence_digest(args.file)
            if args.record:
                publish_private(args.record, json.dumps(record, indent=2) + "\n")
            data = result(
                "Evidence Management",
                record,
                [
                    "SHA-256 was computed from the actual file bytes. Source evidence was not modified."
                ],
                "record_created" if args.record else "hashed",
                [
                    "The explicitly requested fingerprint can identify evidence; keep it private. Timestamp uses the local clock, not a trusted timestamp service."
                ],
            )
        elif args.command == "evidence-verify":
            data = evidence_verify(args.file, args.record)
        elif args.command == "password-audit":
            if args.stdin:
                raw = sys.stdin.buffer.readline(1026)
                if len(raw) > 1024:
                    raise ResearchError("Password exceeds the supported length budget.")
                secret = raw.rstrip(b"\n").removesuffix(b"\r").decode("utf-8")
            else:
                if not sys.stdin.isatty():
                    raise ResearchError(
                        "Use a hidden interactive prompt or explicitly select --stdin."
                    )
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    secret = getpass.getpass("Lab password (hidden): ")
                if len(secret.encode()) > 1024:
                    raise ResearchError("Password exceeds the supported length budget.")
            metrics = strength(secret)
            secret = None
            data = result(
                "Password Strength Auditor",
                metrics,
                ["Prefer long, unique randomly generated credentials."],
                "weak"
                if metrics["weak_heuristic"]
                else "not_flagged_by_local_heuristic",
                [
                    "No entropy, breach lookup, cracking-time estimate or strength guarantee. Python cannot guarantee secure memory erasure."
                ],
            )
        else:
            text = audit_report(args.manifest)
            if args.output:
                publish_private(args.output, text)
                print(
                    "Private audit report created without overwriting an existing file."
                )
            else:
                print(text, end="")
            return 0
        print(text_result(data) if args.text else json.dumps(data, indent=2))
        return 1 if data["status"] == "mismatch" else 0
    except ResearchError as error:
        print("Analysis unavailable: " + str(error), file=sys.stderr)
        return 2
    except OSError:
        print(
            "Analysis unavailable: a local input/output operation failed.",
            file=sys.stderr,
        )
        return 2
    except (UnicodeError, getpass.GetPassWarning):
        print(
            "Analysis unavailable: valid UTF-8 or a secure hidden prompt is required.",
            file=sys.stderr,
        )
        return 2
    except (KeyboardInterrupt, EOFError):
        print("Analysis cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    if sys.version_info < (3, 9):  # noqa: UP036 -- keep a clear error for older installations.
        raise SystemExit("Advanced research tools require Python 3.9 or newer.")
    raise SystemExit(main())
