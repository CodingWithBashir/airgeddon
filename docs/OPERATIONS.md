# Offline operations: preflight, formats, jobs and cases

Use only files/networks you own or are explicitly authorized to assess. Nothing
starts by opening a menu, previewing a format, checking preflight, creating a
profile, or creating/exporting a case. These features never transmit packets.

Open **main menu 16** or:

```bash
bash airgeddon.sh --lab research-tools
```

Tools menu entries **5–8** are preflight, format builder, managed jobs, and private
case folders. Existing research, evidence and report entries remain available.
Python 3.9+ and Linux/POSIX are required. Managed recovery additionally requires
recognized **Hashcat 6+**, mode 22000, and the status/restore/runtime flags checked
in its help output. Missing tools are reported, not installed automatically.

## 1. Preflight

```bash
bash airgeddon.sh --lab recovery-preflight '/private/authorized.22000' '/private' \
  --format 'mask:HOME?d?d?d?d'
bash airgeddon.sh --lab recovery-preflight '/private/authorized.22000' '/private' \
  --wordlist '/private/words.txt'
```

Checks include:

- Readable regular input, mode-22000 WPA*01/WPA*02 structure, digest/address/SSID
  field syntax and EAPOL packet/nonce/message-pair lengths.
- Exactly one wordlist or format. Wordlists need 8–63-byte candidates.
- Existing writable output directory and a conservative free-space estimate:
  input/wordlist snapshot sizes, potential results, plus a **64 MiB** reserve.
- Bounded info-only tool-version probes (Hashcat, Aircrack-ng, Crunch, tshark) and
  managed Hashcat help/flag compatibility checks. No benchmark or recovery.

A `blocked` result exits 2. `ready_for_explicit_start` is **not** cryptographic
validation, proof of driver/GPU functionality, or a recovery-success guarantee.
Engine parsing/runtime errors remain possible and are not reported as recovered
passwords. Text/list input budgets remain 32 MiB and 100,000 lines; input line
limits from the existing research tools apply.

Capture-only preflight is also available:

```bash
bash airgeddon.sh --lab recovery-preflight '/private/authorized.pcapng' '/private' --capture
```

It requires tshark and returns structural candidate/inconclusive evidence. A
capture still needs conversion through the existing workflow before a managed
mode-22000 job. The legacy recovery menus retain their existing conversions and
validation; mandatory new preflight applies to **managed jobs**, not every legacy
backend. Native Aircrack and legacy Hashcat workflows remain available.

## 2. Format builder

Legacy brace examples keep their meaning:

```bash
bash airgeddon.sh --lab format-builder '{OC43DE32}'
```

Each uppercase/lowercase/digit position is unknown within that character class.
For known characters, symbols and a custom set, use the explicit `mask:` syntax:

```bash
bash airgeddon.sh --lab format-builder 'mask:HOME?d?d?d?d'
bash airgeddon.sh --lab format-builder 'mask:HOME000?1' --charset1 'AB?'
```

| Token | Meaning |
| --- | --- |
| `?u` / `?l` / `?d` | Uppercase ASCII / lowercase ASCII / decimal digit |
| `?s` | Printable ASCII symbols, including space |
| `?a` | All 95 printable ASCII characters |
| `?1` | Unique literal characters from the supplied custom set |
| `??` | A literal question mark |
| Other characters after `mask:` | Fixed literal characters |

`mask:HOME?d?d?d?d` keeps `HOME` fixed and has 10,000 candidates. Candidate counts
use arbitrary-precision integers; no speed/ETA is invented. Formats describe
exactly **8–63 printable ASCII positions**. Custom sets have at most 95 characters;
question marks in them are safely escaped before passing them to Hashcat.
Leading option markers are refused (use a single-character `?1` set for a leading
hyphen); patterns matching existing files are refused rather than read as mask
files. There is no shell evaluation, automatic increment, candidate download or generated
large wordlist file. Quote patterns in the shell, and do not put actual complete
passwords or sensitive known fragments in shell history.

The existing optional prompt before personal offline recovery now accepts both
`{example}` and `mask:` formats. `?1` asks for custom characters. Blank keeps the
old workflow. Explicit masks require Python and a **Hashcat** selection; Aircrack
keeps the existing brace-template/Crunch path. Unsupported formats cancel rather
than falling back to unrestricted recovery.

## 3. Named private jobs and resume

### Create a profile — does not start recovery

```bash
bash airgeddon.sh --lab job-create '/private/authorized.22000' '/private/NEW-job' \
  --name home-audit --format 'mask:HOME000?1' --charset1 AB \
  --workload 2 --runtime 3600
```

Use `--wordlist '/private/words.txt'` instead of `--format` for dictionary mode.
Names accept 1–48 ASCII letters/digits/underscore/hyphen, starting alphanumeric.
Profiles are immutable for resume: create a new profile to change settings.

The new directory is **0700**, with **0600** profile/state and private snapshots
of the validated hash export and optional wordlist. Snapshots are fingerprinted;
original files can later be removed without losing the saved job inputs. Changed
snapshots or profiles are refused. Existing directories are never overwritten.
Run jobs/cases as the same owning user; files created through the sudo application
are root-owned. Choose permanent private storage outside application temporary
directories and Git. Recommended ignored checkout directories are `.airgeddon-jobs/` and
`.airgeddon-cases/`; storing outside the checkout is preferable.

### Explicit start, progress, interruption and resume

```bash
bash airgeddon.sh --lab job-run '/private/NEW-job' --yes
bash airgeddon.sh --lab job-status '/private/NEW-job'
bash airgeddon.sh --lab job-resume '/private/NEW-job' --yes
```

`--yes` is required to start/resume from the CLI; the menu asks for confirmation.
A per-job nonblocking lock prevents concurrent starts. Commands use argument
arrays, not `eval`. No service, background daemon or automatic retry is created.

- Hashcat JSON status is filtered to elapsed seconds, progress counters,
  candidates/second and **tool-reported** ETA. Paths, targets, device names,
  candidates and raw diagnostic text are not printed or persisted in progress.
  Status is a saved snapshot, updated when the engine emits status (requested
  every five seconds); absent ETA/speed stays absent.
- Plaintext recovered results, if any, are written to private `results.txt`, not
  printed by this wrapper and never included in case report exports. A private
  `engine.potfile` preserves partial recoveries across resume; no global potfile
  is used. Both results and potfile fingerprints are verified before resume.
- Workload **1–3** (default 2) changes Hashcat scheduling. It is **not a hard CPU
  percentage or thermal cap**. No overclocking, warning suppression or forced
  driver flags are added.
- Runtime is **1–86,400 seconds per attempt**, default 3,600. It is passed to the
  engine and independently bounded by the wrapper. Ctrl+C/SIGTERM or expiry
  interrupts only this managed process group; it gets SIGINT and up to eight
  seconds to exit, then SIGKILL if necessary. Enforcement includes up to ten
  seconds of wrapper grace plus shutdown time, not an exact wall-clock deadline.
- Restore updates are requested every ten seconds. Resume requires an actual
  saved checkpoint matching its recorded fingerprint and the unchanged profile
  and snapshots. Do not move the job directory. A killed/unresponsive engine,
  power loss or incompatible driver/version can prevent a usable checkpoint;
  missing/modified checkpoints are **not** simulated or repaired. If needed,
  create a new validated job.
- Non-JSON console text is discarded. A 64 KiB pending-line and 8 MiB total-output
  budget stops runaway diagnostics; long/noisy jobs can hit this before runtime.

CLI exit 0 means the engine completed (`cracked` or `exhausted`), **not** that a
password was necessarily recovered. Engine error/preflight failure exits 2;
handled interruption exits 130. A successful preflight does not override engine
errors. The wrapper does not implement GPU/driver compatibility certification.

## 4. Private case folders and report export

```bash
bash airgeddon.sh --lab case-create '/private/NEW-case' '/private/manifest.json'
bash airgeddon.sh --lab case-export '/private/NEW-case' '/private/NEW-shared-report.md'
```

The manifest uses the existing research report schema, including rogue-AP
baselines. The new **0700** case directory contains **0600** files:

- `settings.json`: canonical absolute analysis/baseline paths (private).
- `evidence.json`: SHA-256 fingerprints, byte sizes and local timestamps (private).
- `versions.json`: bounded tool-version observations, without raw banners.
- `report.md`: generated identifier-omitting analysis report.
- `case.json`: case schema, source count and generated report fingerprint.

A stable canonical manifest is used to recompute analyses. Source fingerprints
are checked before/after analysis; total input size is at most **512 MiB**.
Sources are **not copied** into cases (unlike managed-job snapshots). Cases can
contain `not_assessed` sections if a tool is absent: case creation is not a pass
verdict. This is reproducibility metadata, not a full acquisition suite, trusted
timestamp, signature or legal chain of custody.

Export verifies the generated report fingerprint and publishes **only that
report**, refusing changed reports and existing output paths. Profiles, private
source paths, fingerprints, source evidence and job results are not exported.
The record is not signed: an owner who modifies both report and fingerprint can
invalidate its guarantees. Review every report before sharing.

## 5. Terminal integration and translation scope

Options/notices wrap on word boundaries and titles shorten for narrow terminals
(minimum supported extension width: 24 columns). Numbering stays aligned; native
application colors, selection/error/pause prompts remain in use. Noninteractive
output omits ANSI styling. EOF returns/cancels; cancellation never starts a job.

A first **German, Spanish and French** pack translates research section headings,
core operations labels and selected job/case prompts. Set the application's
language normally, or for local menus use:

```bash
AIRGEDDON_EXTENSION_LANGUAGE=GERMAN bash airgeddon.sh --lab research-tools
```

Missing strings and other languages fall back to English. **Full translation of
all extension prompts and every airgeddon language is not yet complete.** CLI
JSON keys and analysis findings remain stable English. Wide CJK/combining text
may need terminal-specific display-width handling beyond the current wrapping.

## 6. Validation and installed-tool coverage

`bash tests/run.sh` includes unit tests for profiles, snapshots, confirmation,
locks, fingerprints, resume, safe progress, formats and case exports. Recovery
execution tests use an executable **fake engine**, never real passwords.

Additional installed-tool tests are explicit about availability:

```bash
AIRGEDDON_REQUIRE_TSHARK_TESTS=1 python3 tests/test_research_integration.py
AIRGEDDON_REQUIRE_ENGINE_TESTS=1 python3 tests/test_tool_integration.py
```

The engine suite checks versions/help flags, **two** synthetic Hashcat `--stdout`
candidates and **ten** synthetic Crunch candidates, without hash recovery or a
benchmark. Aircrack-ng is only queried for help/version. CI installs the tools on
Ubuntu 22.04/24.04 and requires both integration suites. Locally, absent tools
cause explicit skips unless the corresponding require flag is set. Passing
mock/unit tests is not real GPU, checkpoint-file or driver validation.
