# AIRGEDDON ADVANCED EXTENSION

Use only evidence/configurations you own or are authorized to assess. This
extension processes actual local inputs and can create private evidence records
and reports. It does not fabricate captures, discoveries, recovered credentials
or successful attacks. Existing training and dragon-preview entries remain
explicit simulations; existing recovery menus remain separate, explicit actions.

## Requirements and entry points

- Python **3.9+**, standard library only. No pip dependencies for runtime.
- A recent **tshark** for capture analysis (install through your distribution).
  Missing/unsupported fields, parser failures and timeouts are errors, not clean
  security verdicts. No automatic download or installation occurs.
- Linux/POSIX regular-file descriptors and hard links for private output
  publication. Native Windows is not supported. Docker includes Python/tshark.
- No root, X11 or radio is needed for the local CLI/menus.

```bash
bash airgeddon.sh --lab advanced       # five research sections
bash airgeddon.sh --lab laboratory    # diagnostics plus research/report tools
bash airgeddon.sh --lab research-tools # direct evidence/audit/report utilities
bash airgeddon.sh --lab help
```

In the full application, main menu **15** opens the extension and **14** opens
the laboratory. Main menu **16** and extension entry **6** provide direct access
to evidence records, wordlist/password audits and report generation. The five
original research sections remain entries 1–5. The laboratory preserves entries
1–12 and adds extension (13),
wordlist analysis (14), password audit (15), and report generation (16).
Menus use native airgeddon star titles, dash separators and numbering; results
pause before returning. Terminal font selection remains under your terminal's
control. Core headings have a German/Spanish/French extension pack; missing translations fall back to English. Normal airgeddon language
selection/pause and invalid-selection prompts are reused in the full application.
Invalid top-level/category selections pause before redrawing, so the explanation
remains visible.

## Analysis commands and inputs

Prefix every command below with `bash airgeddon.sh --lab`. Analysis output is
JSON by default; append `--text` for wrapped terminal text. Whitespace and shell
metacharacters in filenames are treated literally; quote paths as usual.

| Menu section / label | Command | Input and actual checks |
| --- | --- | --- |
| WPA Security / WPA/WPA2 Analysis | `wpa-analysis FILE` | Self-contained hostapd configuration: RSN/WPA mode, AKMs, ciphers, WPS, PMF and inline credential heuristics. |
| WPA Security / WPA3-SAE Analysis | `sae-analysis FILE` | Hostapd SAE/transition configuration, PMF, H2E setting and inline credential heuristics. Enterprise WPA3 is not treated as SAE. |
| WPA Security / PMKID Forensics | `pmkid-forensics FILE` | PMKID text syntax, field sanity and normalized duplicate detection. |
| WPA Security / EAPOL Analysis | `eapol-analysis FILE` | Actual capture: EAPOL message counts and conservative M1–M4 structural candidates. |
| Authentication / WPS Assessment | `wps-assessment FILE` | Hostapd WPS enablement/setup-lock configuration. No PIN attempts or live rate-limit test. |
| Authentication / Enterprise EAP Analysis | `enterprise-eap FILE` | Capture EAP request/response/success/failure counts, TLS/TTLS/PEAP/MD5/LEAP methods. No identity extraction. |
| Authentication / Authentication Diagnostics | `auth-diagnostics FILE` | Capture frame types, retries, auth/disconnect/probe counts, nonzero status and reason-code evidence. |
| Wireless Protocol / 802.11 Frame Analysis | `frame-analysis FILE` | Capture management/control/data counts, protected flags and retry flags. |
| Wireless Protocol / PMF Analysis | `pmf-analysis FILE` | Capture PMF advertisements, inconsistencies and protected/unprotected disconnect counts. |
| Wireless Protocol / Wi-Fi 6/7 Analysis | `wifi-generation FILE` | Capture HE/EHT capability/operation and multi-link extension-element counts. |
| Wireless Threat / Rogue AP Detection | `rogue-ap FILE [--baseline JSON]` | Capture beacon/probe-response APs compared against explicitly approved BSSIDs. Without a baseline: `baseline_required`. |
| Wireless Threat / Evil Twin Detection | `evil-twin FILE` | Capture same-SSID AP groups and differing advertised security profiles. Indicators, not a confirmed attack. |
| Wireless Threat / Client Threat Analysis | `client-threat FILE` | Capture retries, probes and unprotected disconnect evidence. Aggregate indicators; no client tracking or payload extraction. |
| Capture Forensics / Handshake Validation | `handshake-validate FILE` | Capture same-peer M1–M4 order/directions, matching replay counters, +1 replay transition, and at most 10 seconds between messages. |
| Capture Forensics / PMKID File Analysis | `pmkid-analyze FILE` | Same real text-record checks as PMKID Forensics. |
| Capture Forensics / Evidence Management | `evidence`, `evidence-verify` | SHA-256 fingerprint, saved records and verification; see below. |

`wpa2-audit` and `wpa3-audit` are aliases for `wpa-analysis` and `sae-analysis`.
These are configuration audits, **not** on-air WPA/SAE attack modules.

### Configuration format

Supply one effective UTF-8 hostapd `key=value` configuration, with explicit `wpa`.
Blank lines and full-line comments are accepted. Includes, multiple `bss`
sections, duplicate assessed keys and unsupported enumerated setting values
are rejected rather than guessed. Unknown keys are not assessed; they are not
executed. Inline credential values retain their exact whitespace and UTF-8 byte
lengths; only LF/CRLF line terminators are removed. External secret files,
runtime overrides, driver behavior, firmware,
certificates and enterprise policy are not resolved or certified.

Examples of checks are whether `wpa=2` and modern RSN ciphers are explicit,
whether SAE is configured, whether PMF is required for a pure WPA3 baseline,
and whether WPS is enabled. A clean supported checklist is **not** a complete
hostapd validation or proof of secure operation. Password heuristics are limited,
not breach lookups, entropy measurements or cracking-time estimates.

### Capture format and limits

Capture commands pass real evidence to tshark using `-n` (no name resolution),
field-only output and an already validated regular-file descriptor. No payloads,
SSIDs, MAC addresses, passwords or EAP identities are printed. Input evidence is
not rewritten. The tshark process is killed on deadline or output-budget failure.

- At most **20,000 input packets**, not 20,000 matching packets.
- **15 seconds** per capture analysis, **4 MiB** of parser output, and
  **64 KiB** of private diagnostics. Both pipes are drained concurrently to avoid
  deadlock; exceeding either budget terminates tshark.
- Older tshark versions missing required fields return a specific upgrade error.
  Recognized unsupported-format, truncated-file and permission diagnostics have
  distinct static messages. Unknown failures use a generic error; raw tshark
  diagnostics and paths are never printed or copied into reports.
- Empty matching results are not proof of absence; encrypted, truncated, wired,
  filtered or incomplete captures can omit relevant evidence.
- Handshake candidates are **structural only**: no MIC/nonces/cryptographic
  authenticity, credential correctness or recoverability verification. Repeated
  same-peer/stage/replay rows no longer erase matched prefixes (for example, a
  repeated M1 after M2). `repeated_stage_rows` counts these repeats, not confirmed
  radio retransmissions. Same-peer order, replay and per-gap timing checks still
  apply; one structural candidate is counted per AP/client/replay key.
- PMF flags/disconnect counts do not establish a PMF bypass. HE/EHT elements do
  not certify generation, bands, interoperability or actual throughput.
- Same-name APs are normal in managed networks; spoofing, baseline incompleteness
  and legitimate configuration changes prevent definitive threat verdicts.

Approved-AP baseline JSON accepts exactly this shape, with 1–4,096 nonzero
unicast BSSIDs (example locally administered address, replace with your own):

```json
{"approved_bssids": ["02:00:00:00:00:01"]}
```

```bash
bash airgeddon.sh --lab rogue-ap '/private/authorized.pcapng' \
  --baseline '/private/approved.json' --text
```

### PMKID text format

Accepts hashcat 22000 PMKID lines (`WPA*01*PMKID*AP*CLIENT*ESSID_HEX***`) and
legacy four-field lines (`PMKID*AP*CLIENT*ESSID_HEX`). AP/client are 12 hex digits;
PMKID is 32 nonzero hex digits; ESSID is at most 32 bytes encoded as hex. Address
unicast/distinctness checks and case-normalized duplicate counts are performed.
`WPA*02` EAPOL lines are counted as **not analyzed**, never validated as PMKIDs.
Blank/full-line `#` comments are skipped. Binary captures are not text exports.
Syntactic validity is not cryptographic authenticity or recoverability.

## Evidence Management: real saved records

```bash
bash airgeddon.sh --lab evidence '/private/evidence.cap' --text
bash airgeddon.sh --lab evidence '/private/evidence.cap' \
  --record '/private/NEW-evidence.json'
bash airgeddon.sh --lab evidence-verify '/private/evidence.cap' \
  '/private/NEW-evidence.json' --text
```

Hashing reads the actual bytes, up to **512 MiB**, and checks file size/mtime
stability across the read. The JSON record contains `format` (value
`airgeddon-evidence-v1`), `algorithm` (`SHA-256`), `sha256`, `bytes` and
`recorded_utc`. Empty regular evidence files may be fingerprinted. Paths and
source identifiers are omitted. Explicitly requested fingerprints themselves
can identify evidence: keep records private.

Records/reports are created with mode **0600**, through a temporary file and
no-clobber hard-link publication in the destination directory. Existing files,
including symlinks, are never overwritten. The directory must already exist and
support hard links. Source evidence is not changed. Back up records separately;
this is not a full evidence repository or legal chain-of-custody system.
The timestamp uses the local clock, not a trusted timestamp authority. A matching
digest proves only a match against the supplied record, not provenance.

## Additional working laboratory tools

```bash
bash airgeddon.sh --lab wordlist-analyze '/private/list.txt' --text
bash airgeddon.sh --lab password-audit --text  # hidden interactive prompt
```

Wordlist analysis counts duplicates, empty entries, invalid UTF-8, edge whitespace
and 8–63-byte candidates without printing candidate contents. Duplicate checking
uses temporary salted digests. LF/CRLF lines are supported. No candidate mutations,
downloads or recovery job are run. Password auditing accepts at most 1,024 UTF-8
bytes; obvious examples, sequences, repetition and short values are flagged, not
certified strong. For deliberate automation, `--stdin` reads the first line:
provide it from a secure source, not a plaintext command saved in shell history.
Password arguments are not accepted. Python cannot guarantee memory erasure.

Text/list inputs: **32 MiB**, at most **100,000 entries**, each at most **8,192
bytes**. Configurations: **1 MiB**. JSON documents: **1 MiB**, duplicate keys
rejected. Devices, directories and FIFOs are rejected without reading them.

## Audit Report Generator: recompute, do not invent

Create a JSON manifest mapping supported analysis command names from the table
(or `wordlist-analyze`) to authorized local input paths. Each value may be a
path string or an object with `file`. Only `rogue-ap` also accepts `baseline`.
Both input and baseline paths resolve relative to the manifest directory, not
the current working directory. Absolute paths remain supported. Example:

```json
{
  "sae-analysis": "hostapd.conf",
  "handshake-validate": "authorized.pcapng",
  "pmkid-analyze": "authorized.22000",
  "rogue-ap": {"file": "authorized.pcapng", "baseline": "approved.json"}
}
```

```bash
bash airgeddon.sh --lab audit-report '/private/manifest.json' \
  '/private/NEW-report.md'
```

The generator actually runs each requested analysis and writes Markdown. Missing
inputs/tools or other analysis failures appear as **`not_assessed`** sections,
not passes. A report can therefore be created successfully while some sections
were unavailable; inspect every section. Omitting the output path prints to
stdout. Manifests are at most **64 KiB**; supported modes occur at most once.
Each capture section has its own 15-second budget. Missing or invalid baseline
files produce `not_assessed`; an omitted baseline produces `baseline_required`.
Malformed manifest options are rejected before any analyses run. A report summary
counts requested, unavailable and baseline-required sections; report creation
is never a declaration that every assessment passed.
Reports omit source paths, peer identifiers and credentials. They are not
security certificates; review before sharing and keep outside the repository.

## Status and exit-code contract

- **0**: analysis completed or report/record created. This does **not** mean
  secure: inspect `status`, `metrics`, `findings`, and `limitations`.
- **1**: evidence verification completed and found a **mismatch**.
- **2**: invalid inputs, missing dependencies, failed/unsupported capture parsing,
  budget failure or output-creation failure. No successful analysis is inferred.
- **130**: cancellation/EOF while acquiring an interactive password.

Statuses distinguish `candidate`, `inconclusive`, `baseline_required`, `review`,
`issues_found`, `no_flagged_issues`, `observed`, and evidence match/mismatch.
`not_flagged_by_local_heuristic` is intentionally not called “strong”.

## Validation

`bash tests/run.sh` runs the existing shell regression suites, extension menu/CLI
checks, and Python unit tests with synthetic files and mocked dissector output.
A real executable fixture tests subprocess argument handling, inherited regular
file descriptors, parser failure and output-budget termination. No test starts
wireless transmissions, cracking, package installation or firewall changes.
`tests/test_research_integration.py` additionally generates actual PCAP and
PCAPNG files and sends them through the installed tshark and public CLI. It
checks all capture routes, structural M1–M4 exchanges including repeated stages, incomplete evidence,
malformed input, AP/PMF/EAP counts, privacy and unchanged source bytes. Frames
are entirely synthetic and contain no real credentials or cryptographically
valid handshake. No radio or network access is used.

The integration suite explicitly skips when tshark is absent locally. To require
it (and fail rather than skip if missing), run:

```bash
AIRGEDDON_REQUIRE_TSHARK_TESTS=1 python3 tests/test_research_integration.py
```

CI installs distribution tshark on Ubuntu 22.04 and 24.04 and requires these
integration tests. Generated capture files live only in temporary directories;
no binary evidence files are committed. These checks do not substitute for
validation against real acquired evidence and the specific tshark
version/hardware in an authorized lab.

## Managed operations and case folders

Tools-menu entries 5–8 add preflight, richer fixed/custom formats, private named
Hashcat jobs with checkpoint resume and filtered progress, and private case
bundles with report-only export. Start/resume is always explicit; opening menus,
creating profiles and creating cases never starts recovery. See
[OPERATIONS.md](OPERATIONS.md) for the full interface, budgets, local translation
pack and installed-engine validation scope. The legacy recovery workflows remain
available; only new managed jobs require the modern Hashcat status/restore flags.
