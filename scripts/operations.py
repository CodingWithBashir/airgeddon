#!/usr/bin/env python3
"""Private offline recovery profiles, preflight checks, case bundles and jobs."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import research as r

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z")
CLASSES = {
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "d": "0123456789",
}
CLASSES["s"] = "".join(chr(i) for i in range(32, 127) if not chr(i).isalnum())
CLASSES["a"] = "".join(chr(i) for i in range(32, 127))
MIN_FREE = 64 * 1024 * 1024


def format_spec(spec, custom=""):
    if len(spec) > 256 or any(ord(c) < 32 or ord(c) > 126 for c in spec + custom):
        raise r.ResearchError(
            "Formats and custom characters must be printable ASCII within the format budget."
        )
    if len(custom) > 95:
        raise r.ResearchError("Custom character set exceeds 95 characters.")
    custom = "".join(dict.fromkeys(custom))
    mask, count, length, crunch = "", 1, 0, ""
    if spec.startswith("{") and spec.endswith("}"):
        body = spec[1:-1]
        if not body or not body.isalnum() or custom:
            raise r.ResearchError(
                "Brace examples accept ASCII letters/digits only; use mask: for fixed characters and symbols."
            )
        for char in body:
            kind = "u" if char.isupper() else "l" if char.islower() else "d"
            mask += "?" + kind
            crunch += {"u": ",", "l": "@", "d": "%"}[kind]
            length += 1
            count *= len(CLASSES[kind])
    elif spec.startswith("mask:"):
        body, index = spec[5:], 0
        while index < len(body):
            char = body[index]
            index += 1
            if char == "?":
                if index == len(body):
                    raise r.ResearchError(
                        "Incomplete mask token; use ?? for a literal question mark."
                    )
                kind = body[index]
                index += 1
                if kind == "?":
                    count *= 1
                elif kind == "1" and custom:
                    count *= len(custom)
                elif kind in CLASSES:
                    count *= len(CLASSES[kind])
                else:
                    raise r.ResearchError(
                        "Use ?u, ?l, ?d, ?s, ?a, ?1 with a custom set, or ?? in masks."
                    )
                mask += "?" + kind
            else:
                mask += char
            length += 1
    else:
        raise r.ResearchError(
            "Use a {character-type example} or mask: with explicit fixed characters and tokens."
        )
    if mask.startswith("-"):
        raise r.ResearchError(
            "A mask must not start with an option marker; use ?1 with a custom '-' character for a leading hyphen."
        )
    if not 8 <= length <= 63:
        raise r.ResearchError(
            "Personal passphrase formats must describe exactly 8-63 characters."
        )
    return {
        "mask": mask,
        "characters": length,
        "candidates": count,
        "custom": custom.replace("?", "??"),
        "crunch": crunch,
    }


def tool_version(tool):
    executable = shutil.which(tool)
    if not executable:
        return {"available": False, "version": None}
    flag = {
        "hashcat": "--version",
        "tshark": "--version",
        "aircrack-ng": "--help",
        "crunch": "-h",
    }[tool]
    text, code = bytearray(), None
    try:
        with subprocess.Popen(
            [executable, flag],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={**os.environ, "LC_ALL": "C"},
        ) as process:
            try:
                deadline = time.monotonic() + 8
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while len(text) < 8192:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            break
                        chunk = os.read(process.stdout.fileno(), 8192 - len(text))
                        if not chunk:
                            code = process.wait(timeout=max(0.001, remaining))
                            break
                        text.extend(chunk)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except (OSError, subprocess.TimeoutExpired):
        return {"available": True, "version": None}
    text = text.decode("utf-8", "replace")
    patterns = {
        "hashcat": r"\bv?(\d+\.\d+(?:\.\d+)?)\b",
        "tshark": r"(?:Wireshark|TShark)\)?\s+(\d+\.\d+(?:\.\d+)?)",
        "aircrack-ng": r"Aircrack-ng\s+(\d+\.\d+(?:\.\d+)?)",
        "crunch": r"(?:crunch\s+version|crunch)\s+(\d+\.\d+(?:\.\d+)?)",
    }
    match = re.search(patterns[tool], text, re.IGNORECASE)
    return {
        "available": True,
        "version": match[1]
        if match and (code in {0, 1} or len(text) == 8192)
        else None,
    }


def engine_capabilities():
    executable = shutil.which("hashcat")
    if not executable:
        return False
    output = bytearray()
    try:
        with subprocess.Popen(
            [executable, "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as process:
            try:
                deadline = time.monotonic() + 8
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while len(output) < 131072:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            return False
                        chunk = os.read(process.stdout.fileno(), 8192)
                        if not chunk:
                            break
                        output.extend(chunk)
                required = (
                    b"--status-json",
                    b"--restore-file-path",
                    b"--runtime",
                    b"--workload-profile",
                    b"--restore-timer",
                    b"22000",
                )
                return all(flag in output for flag in required)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except OSError:
        return False


def hash_input(path):
    # Modern managed jobs deliberately accept only mode 22000 text, not captures.
    lines = r.bounded_lines(r.small_input(path))
    valid = 0
    for raw in lines:
        if not raw.strip() or raw.startswith(b"#"):
            continue
        try:
            parts = raw.decode("ascii").split("*")
        except UnicodeError:
            raise r.ResearchError(
                "Expected an ASCII mode-22000 hash export, not a capture."
            ) from None
        if len(parts) != 9 or parts[:1] != ["WPA"] or parts[1] not in {"01", "02"}:
            raise r.ResearchError(
                "Managed recovery needs a structurally valid WPA*01/WPA*02 mode-22000 export."
            )
        _, kind, digest, ap, client, ssid, nonce, eapol, pair = parts
        hex_field = lambda value, n: (
            len(value) == n and bool(re.fullmatch(r"[0-9a-fA-F]+", value))
        )
        addresses = all(
            hex_field(value, 12)
            and r.unicast(":".join(value[i : i + 2] for i in range(0, 12, 2)))
            for value in (ap, client)
        )
        if (
            not hex_field(digest, 32)
            or int(digest, 16) == 0
            or not addresses
            or ap.lower() == client.lower()
            or len(ssid) > 64
            or len(ssid) % 2
            or not re.fullmatch(r"[0-9a-fA-F]*", ssid)
        ):
            raise r.ResearchError(
                "Hash export contains invalid digest, address or SSID field syntax."
            )
        if kind == "01" and any((nonce, eapol, pair)):
            raise r.ResearchError("PMKID records must not contain EAPOL-only fields.")
        if kind == "02" and (
            not hex_field(nonce, 64)
            or not hex_field(pair, 2)
            or not 198 <= len(eapol) <= 512
            or len(eapol) % 2
            or not re.fullmatch(r"[0-9a-fA-F]+", eapol)
        ):
            raise r.ResearchError(
                "EAPOL record nonce, message-pair or packet syntax is invalid."
            )
        valid += 1
    if not valid:
        raise r.ResearchError("No supported recovery records were found.")
    return valid


def writable_directory(path):
    directory = Path(path).resolve()
    if not directory.is_dir():
        raise r.ResearchError("Select an existing output directory.")
    try:
        with tempfile.TemporaryFile(dir=directory):
            pass
        free = shutil.disk_usage(directory).free
    except OSError:
        raise r.ResearchError("Output directory is not writable.") from None
    if free < MIN_FREE:
        raise r.ResearchError(
            "Output directory has less than 64 MiB free; no job was started."
        )
    return free


def preflight(path, output, wordlist=None, spec=None, custom="", capture=False):
    free = writable_directory(output)
    if capture:
        data = r.analyze("handshake-validate", path)
        return {
            "status": "candidate_only"
            if data["status"] == "candidate"
            else "inconclusive",
            "evidence": data,
            "free_bytes": free,
            "limitations": [
                "Capture must be converted through the existing workflow before a managed mode-22000 job."
            ],
        }
    records = hash_input(path)
    details = format_spec(spec, custom) if spec is not None else None
    if (wordlist is None) == (spec is None):
        raise r.ResearchError("Choose exactly one local wordlist or password format.")
    if wordlist is not None:
        stats = r.wordlist_analysis(wordlist)["metrics"]
        if not stats["passphrase_length_entries"]:
            raise r.ResearchError("Wordlist has no 8-63-byte passphrase candidates.")
    tools = {
        name: tool_version(name)
        for name in ("hashcat", "aircrack-ng", "crunch", "tshark")
    }
    ready = (
        tools["hashcat"]["version"] is not None
        and int(tools["hashcat"]["version"].split(".")[0]) >= 6
    )
    capabilities = engine_capabilities() if ready else False
    ready = ready and capabilities
    required_bytes = (
        MIN_FREE
        + Path(path).stat().st_size
        + (Path(wordlist).stat().st_size if wordlist is not None else 0)
        + records * 64
    )
    if free < required_bytes:
        raise r.ResearchError(
            "Insufficient free space for private snapshots, potential results and the 64 MiB safety reserve."
        )
    return {
        "status": "ready_for_explicit_start" if ready else "blocked",
        "records": records,
        "managed_flags_available": capabilities,
        "estimated_required_free_bytes": required_bytes,
        "free_bytes": free,
        "tools": tools,
        "format": details,
        "limitations": [
            "Structural checks do not verify MICs, credentials, recoverability, GPU drivers or backend availability. Managed jobs require Hashcat 6+ with status/restore/runtime flags and mode 22000; no recovery was run."
        ],
    }


def private_json(path, value):
    r.publish_private(path, json.dumps(value, indent=2) + "\n")


def private_directory(path):
    path = Path(path).resolve()
    mode = path.stat()
    if (
        not stat.S_ISDIR(mode.st_mode)
        or mode.st_uid != os.getuid()
        or stat.S_IMODE(mode.st_mode) & 0o077
    ):
        raise r.ResearchError(
            "Job/case directory must be owned by this user with mode 0700."
        )
    return path


def create_profile(
    path, name, source, wordlist=None, spec=None, custom="", workload=2, runtime=3600
):
    if (
        not NAME.fullmatch(name)
        or workload not in {1, 2, 3}
        or not 1 <= runtime <= 86400
    ):
        raise r.ResearchError(
            "Use a short alphanumeric job name, workload 1-3 and runtime 1-86400 seconds."
        )
    source = str(Path(source).resolve())
    wordlist = str(Path(wordlist).resolve()) if wordlist is not None else None
    check = preflight(source, Path(path).parent, wordlist, spec, custom)
    if check["status"] == "blocked":
        raise r.ResearchError(
            "Managed jobs require Hashcat 6+ with mode 22000 and status/restore/runtime flags. Preflight did not start recovery."
        )
    settings = {
        "format": "airgeddon-job-v1",
        "name": name,
        "directory": str(Path(path).resolve()),
        "input": source,
        "wordlist": wordlist,
        "spec": spec,
        "custom": custom,
        "workload": workload,
        "runtime": runtime,
        "input_digest": r.evidence_digest(source)["sha256"],
        "wordlist_digest": r.evidence_digest(wordlist)["sha256"] if wordlist else None,
    }
    directory = Path(path)
    directory.mkdir(mode=0o700)
    try:
        for key, filename in (("input", "input.22000"), ("wordlist", "wordlist.txt")):
            if settings[key] is None:
                continue
            content = r.small_input(settings[key])
            if hashlib.sha256(content).hexdigest() != settings[key + "_digest"]:
                raise r.ResearchError(
                    "Input changed while saving the private job snapshot."
                )
            with open(directory / filename, "xb") as stream:
                os.chmod(directory / filename, 0o600)
                stream.write(content)
        private_json(directory / "profile.json", settings)
        private_json(
            directory / "state.json",
            {
                "status": "created",
                "elapsed_seconds": 0,
                "profile_digest": hashlib.sha256(
                    (directory / "profile.json").read_bytes()
                ).hexdigest(),
            },
        )
    except BaseException:
        # Only the exclusively created new directory belongs to this operation.
        shutil.rmtree(directory)
        raise
    return {
        "status": "profile_created",
        "name": name,
        "preflight": check,
        "limitations": [
            "Profile contains private paths and pattern settings. No recovery has started."
        ],
    }


def load_profile(directory):
    directory = private_directory(directory)
    profile = r.json_input(directory / "profile.json", 65536)
    expected = {
        "format",
        "name",
        "directory",
        "input",
        "wordlist",
        "spec",
        "custom",
        "workload",
        "runtime",
        "input_digest",
        "wordlist_digest",
    }
    if (
        not isinstance(profile, dict)
        or set(profile) != expected
        or profile["format"] != "airgeddon-job-v1"
        or not isinstance(profile["name"], str)
        or not NAME.fullmatch(profile["name"])
        or type(profile["workload"]) is not int
        or profile["workload"] not in {1, 2, 3}
        or type(profile["runtime"]) is not int
        or not 1 <= profile["runtime"] <= 86400
        or not isinstance(profile["custom"], str)
    ):
        raise r.ResearchError("Unsupported job profile schema.")
    if profile.get("directory") != str(directory):
        raise r.ResearchError(
            "Managed job directory moved; create a new profile rather than relocating checkpoints."
        )
    for key in ("input", "wordlist"):
        value = profile[key]
        if key == "wordlist" and value is None:
            continue
        if not isinstance(value, str) or not Path(value).is_absolute() or "\0" in value:
            raise r.ResearchError("Profile inputs must be absolute regular-file paths.")
        if not isinstance(profile[key + "_digest"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", profile[key + "_digest"]
        ):
            raise r.ResearchError("Profile fingerprint is invalid.")
    if (
        (profile["wordlist"] is None) == (profile["spec"] is None)
        or profile["spec"] is not None
        and not isinstance(profile["spec"], str)
    ):
        raise r.ResearchError("Profile must select one wordlist or format.")
    if profile["spec"] is not None:
        format_spec(profile["spec"], profile["custom"])
    return directory, profile


def safe_progress(data):
    output = {}
    if not isinstance(data, dict):
        return output
    progress = data.get("progress")
    if (
        isinstance(progress, list)
        and len(progress) == 2
        and all(type(n) is int and 0 <= n < 2**128 for n in progress)
    ):
        output["progress"] = progress
    devices = data.get("devices", [])
    if isinstance(devices, list):
        speeds = [d.get("speed") for d in devices[:256] if isinstance(d, dict)]
        speeds = [n for n in speeds if type(n) in {int, float} and 0 <= n < 1e30]
        if speeds:
            output["candidates_per_second"] = sum(speeds)
    eta = data.get("estimated_stop")
    if type(eta) is int and 0 < eta < 2**40:
        output["tool_eta_seconds"] = max(0, eta - int(time.time()))
    return output


def public_state(state):
    if not isinstance(state, dict) or state.get("status") not in {
        "created",
        "running",
        "cracked",
        "exhausted",
        "interrupted",
        "engine_error",
    }:
        raise r.ResearchError("Unsupported job state.")
    output = {"status": state["status"]}
    for key in ("elapsed_seconds", "tool_eta_seconds"):
        value = state.get(key)
        if type(value) is int and 0 <= value < 2**64:
            output[key] = value
    for key in ("resumed", "checkpoint_available"):
        if type(state.get(key)) is bool:
            output[key] = state[key]
    output.update(safe_progress({"progress": state.get("progress")}))
    speed = state.get("candidates_per_second")
    if type(speed) in {int, float} and 0 <= speed < 1e30:
        output["candidates_per_second"] = speed
    return output


def replace_state(directory, state):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, prefix=".state-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(state, stream)
        os.replace(temporary, directory / "state.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def job_lock(directory):
    fd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise r.ResearchError("This job is already running or locked.") from None
        yield
    finally:
        os.close(fd)


def run_job(path, resume=False, confirmed=False):
    if not confirmed:
        raise r.ResearchError(
            "Explicit --yes confirmation is required; use only authorized offline evidence."
        )
    directory, profile = load_profile(path)
    with job_lock(directory):
        state = r.json_input(directory / "state.json", 65536)
        if not isinstance(state, dict) or not isinstance(state.get("status"), str):
            raise r.ResearchError("Invalid job state.")
        if not resume and state["status"] != "created":
            raise r.ResearchError(
                "Job already started. Use explicit resume with a valid checkpoint or create a new profile."
            )
        profile_digest = hashlib.sha256(
            r.small_input(directory / "profile.json", 65536)
        ).hexdigest()
        if state.get("profile_digest") != profile_digest:
            raise r.ResearchError(
                "Profile changed since creation; create a new job rather than modifying a saved session."
            )
        for filename in (
            "session.restore",
            "results.txt",
            "engine.potfile",
            "state.json",
        ):
            if (directory / filename).is_symlink():
                raise r.ResearchError("Managed job artifacts must not be symlinks.")
        if not resume and any(
            (directory / filename).exists()
            for filename in ("session.restore", "results.txt", "engine.potfile")
        ):
            raise r.ResearchError(
                "Fresh job contains stale engine artifacts; create a new profile rather than reusing results."
            )
        if resume:
            for filename, key in (
                ("engine.potfile", "potfile_digest"),
                ("results.txt", "results_digest"),
            ):
                artifact = directory / filename
                actual = (
                    r.evidence_digest(artifact)["sha256"]
                    if artifact.is_file()
                    else None
                )
                if state.get(key) != actual:
                    raise r.ResearchError(
                        "Saved engine results/potfile changed; resume refused."
                    )
        restore = directory / "session.restore"
        if resume and (
            not restore.is_file()
            or restore.is_symlink()
            or state["status"] in {"cracked", "exhausted"}
        ):
            raise r.ResearchError("No resumable checkpoint is available for this job.")
        if (
            resume
            and state.get("checkpoint_digest") != r.evidence_digest(restore)["sha256"]
        ):
            raise r.ResearchError(
                "Checkpoint does not match the saved job state; resume refused."
            )
        for key, filename in (("input", "input.22000"), ("wordlist", "wordlist.txt")):
            if profile[key] is not None:
                snapshot = directory / filename
                if (
                    snapshot.is_symlink()
                    or r.evidence_digest(snapshot)["sha256"] != profile[key + "_digest"]
                ):
                    raise r.ResearchError(
                        "A private input snapshot changed; resume/start refused."
                    )
        check = preflight(
            directory / "input.22000",
            directory,
            directory / "wordlist.txt" if profile["wordlist"] is not None else None,
            profile["spec"],
            profile["custom"],
        )
        if check["status"] == "blocked":
            raise r.ResearchError(
                "Hashcat 6+ with mode 22000 and status/restore/runtime flags is required."
            )
        executable = shutil.which("hashcat")
        args = [
            executable,
            "--session",
            "airgeddon",
            "--restore-file-path",
            str(restore),
        ]
        if resume:
            args += ["--restore"]
        else:
            args += [
                "-m",
                "22000",
                "--potfile-path",
                str(directory / "engine.potfile"),
                "--logfile-disable",
                "--outfile",
                str(directory / "results.txt"),
                "--outfile-format",
                "2",
                "--restore-timer",
                "10",
            ]
            if profile["wordlist"]:
                args += [
                    "-a",
                    "0",
                    str(directory / "input.22000"),
                    str(directory / "wordlist.txt"),
                ]
            else:
                compiled = format_spec(profile["spec"], profile["custom"])
                if (directory / compiled["mask"]).exists() or (
                    compiled["custom"] and (directory / compiled["custom"]).exists()
                ):
                    raise r.ResearchError(
                        "Mask/custom set would be interpreted as an existing filename rather than characters; change the format."
                    )
                args += ["-a", "3"]
                if compiled["custom"]:
                    args += ["-1", compiled["custom"]]
                args += [str(directory / "input.22000"), compiled["mask"]]
        args += [
            "-w",
            str(profile["workload"]),
            "--runtime",
            str(profile["runtime"]),
            "--status",
            "--status-json",
            "--status-timer",
            "5",
        ]
        state = {
            "status": "running",
            "elapsed_seconds": 0,
            "resumed": resume,
            "profile_digest": profile_digest,
        }
        replace_state(directory, state)
        start = time.monotonic()
        # All artifacts created by Hashcat inherit private permissions.
        previous_umask = os.umask(0o077)
        previous_term = signal.getsignal(signal.SIGTERM)

        def interrupt_job(_signum, _frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, interrupt_job)
        try:
            with subprocess.Popen(
                args,
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            ) as process:
                pending, total = bytearray(), 0
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        while selector.get_map():
                            if time.monotonic() - start > profile["runtime"] + 10:
                                raise TimeoutError
                            if not selector.select(0.5):
                                continue
                            chunk = os.read(process.stdout.fileno(), 8192)
                            if not chunk:
                                selector.unregister(process.stdout)
                                break
                            total += len(chunk)
                            pending.extend(chunk)
                            if total > 8 * 1024 * 1024 or len(pending) > 65536:
                                raise r.ResearchError(
                                    "Job diagnostic output exceeded its budget; inspect the local engine installation."
                                )
                            while b"\n" in pending:
                                line, _, pending = pending.partition(b"\n")
                                try:
                                    observed = safe_progress(json.loads(line))
                                except (ValueError, UnicodeError, RecursionError):
                                    continue
                                if observed:
                                    state.update(observed)
                                    state["elapsed_seconds"] = int(
                                        time.monotonic() - start
                                    )
                                    replace_state(directory, state)
                                    print(
                                        json.dumps(
                                            {"job_progress": public_state(state)}
                                        ),
                                        flush=True,
                                    )
                    process.wait(timeout=5)
                    state["status"] = {
                        0: "cracked",
                        1: "exhausted",
                        2: "interrupted",
                        3: "interrupted",
                        4: "interrupted",
                    }.get(process.returncode, "engine_error")
                except (KeyboardInterrupt, TimeoutError, subprocess.TimeoutExpired):
                    state["status"] = "interrupted"
                finally:
                    if process.poll() is None:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGINT)
                        try:
                            process.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            with contextlib.suppress(ProcessLookupError):
                                os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                    if state["status"] == "cracked" and (
                        not (directory / "results.txt").is_file()
                        or (directory / "results.txt").stat().st_size == 0
                    ):
                        state["status"] = "engine_error"
                    state["elapsed_seconds"] = int(time.monotonic() - start)
                    state["checkpoint_available"] = (
                        restore.is_file() and not restore.is_symlink()
                    )
                    state["checkpoint_digest"] = (
                        r.evidence_digest(restore)["sha256"]
                        if state["checkpoint_available"]
                        else None
                    )
                    for filename, key in (
                        ("engine.potfile", "potfile_digest"),
                        ("results.txt", "results_digest"),
                    ):
                        artifact = directory / filename
                        state[key] = (
                            r.evidence_digest(artifact)["sha256"]
                            if artifact.is_file()
                            else None
                        )
                    replace_state(directory, state)
        except BaseException:
            state["status"] = "engine_error"
            replace_state(directory, state)
            raise
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            os.umask(previous_umask)
        return public_state(state)


def case_create(path, manifest):
    entries = r.manifest_entries(r.json_input(manifest, 65536))
    base = Path(manifest).resolve().parent
    canonical, sources = {}, set()
    for mode, value, baseline in entries:
        item = {"file": str((base / value).resolve())}
        sources.add(item["file"])
        if baseline is not None:
            item["baseline"] = str((base / baseline).resolve())
            sources.add(item["baseline"])
        canonical[mode] = item
    if sum(Path(source).stat().st_size for source in sources) > r.MAX_EVIDENCE:
        raise r.ResearchError(
            "Case inputs exceed the combined 512 MiB fingerprint budget."
        )
    fingerprints = {source: r.evidence_digest(source) for source in sorted(sources)}
    with tempfile.TemporaryDirectory(prefix="airgeddon-case-") as staging:
        stable_manifest = Path(staging) / "manifest.json"
        private_json(stable_manifest, canonical)
        report = r.audit_report(stable_manifest)
    for source, fingerprint in fingerprints.items():
        if r.evidence_digest(source)["sha256"] != fingerprint["sha256"]:
            raise r.ResearchError(
                "Case input changed during analysis; no case was created."
            )
    directory = Path(path)
    directory.mkdir(mode=0o700)
    try:
        private_json(directory / "settings.json", canonical)
        private_json(directory / "evidence.json", fingerprints)
        private_json(
            directory / "versions.json",
            {
                name: tool_version(name)
                for name in ("tshark", "hashcat", "aircrack-ng", "crunch")
            },
        )
        r.publish_private(directory / "report.md", report)
        private_json(
            directory / "case.json",
            {
                "format": "airgeddon-case-v1",
                "report_sha256": hashlib.sha256(report.encode()).hexdigest(),
                "source_files": len(sources),
            },
        )
    except BaseException:
        shutil.rmtree(directory)
        raise
    return {
        "status": "case_created",
        "source_files": len(sources),
        "limitations": [
            "Sources are fingerprinted, not copied. Private settings contain paths. Not a signed chain of custody."
        ],
    }


def case_export(path, output):
    directory = private_directory(path)
    meta = r.json_input(directory / "case.json", 65536)
    report = r.small_input(directory / "report.md", 1024 * 1024)
    if (
        not isinstance(meta, dict)
        or meta.get("format") != "airgeddon-case-v1"
        or meta.get("report_sha256") != hashlib.sha256(report).hexdigest()
    ):
        raise r.ResearchError(
            "Generated case report no longer matches its saved fingerprint; export refused."
        )
    r.publish_private(output, report.decode("utf-8"))
    return {
        "status": "report_exported",
        "limitations": [
            "Only the generated identifier-omitting report was exported, not paths, source fingerprints, profiles or results. Review before sharing."
        ],
    }


def main(argv=None):
    parser = r.PrivateParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fmt = sub.add_parser("format-builder")
    fmt.add_argument("spec")
    fmt.add_argument("--charset1", default="")
    fmt.add_argument("--shell", action="store_true")
    for command in ("recovery-preflight", "job-create"):
        child = sub.add_parser(command)
        child.add_argument("file")
        child.add_argument("output")
        child.add_argument("--wordlist")
        child.add_argument("--format", dest="spec")
        child.add_argument("--charset1", default="")
        if command == "job-create":
            child.add_argument("--name", required=True)
            child.add_argument("--workload", type=int, choices=(1, 2, 3), default=2)
            child.add_argument("--runtime", type=int, default=3600)
        else:
            child.add_argument("--capture", action="store_true")
    for command in ("job-run", "job-resume", "job-status"):
        child = sub.add_parser(command)
        child.add_argument("directory")
        if command != "job-status":
            child.add_argument("--yes", action="store_true")
    for command in ("case-create", "case-export"):
        child = sub.add_parser(command)
        child.add_argument("directory")
        child.add_argument("file")
    args = parser.parse_args(argv)
    try:
        if args.command == "format-builder":
            data = format_spec(args.spec, args.charset1)
            if args.shell:
                print(
                    "\n".join(
                        str(data[key])
                        for key in ("mask", "characters", "candidates", "custom")
                    )
                )
                return 0
        elif args.command == "recovery-preflight":
            data = preflight(
                args.file,
                args.output,
                args.wordlist,
                args.spec,
                args.charset1,
                args.capture,
            )
        elif args.command == "job-create":
            data = create_profile(
                args.output,
                args.name,
                args.file,
                args.wordlist,
                args.spec,
                args.charset1,
                args.workload,
                args.runtime,
            )
        elif args.command == "job-status":
            directory, _ = load_profile(args.directory)
            data = r.json_input(directory / "state.json", 65536)
            data = public_state(data)
        elif args.command in {"job-run", "job-resume"}:
            data = run_job(args.directory, args.command == "job-resume", args.yes)
        elif args.command == "case-create":
            data = case_create(args.directory, args.file)
        else:
            data = case_export(args.directory, args.file)
        print(json.dumps(data, indent=2))
        return (
            2
            if data.get("status") in {"blocked", "engine_error", "inconclusive"}
            else 130
            if data.get("status") == "interrupted"
            else 0
        )
    except r.ResearchError as error:
        print("Operation unavailable: " + str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError, TypeError):
        print(
            "Operation unavailable: invalid local data, permissions or input/output failure.",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print("Operation cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    if sys.version_info < (3, 9):  # noqa: UP036 -- give older installations a clear error.
        raise SystemExit("Offline operations require Python 3.9 or newer.")
    raise SystemExit(main())
