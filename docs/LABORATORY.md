# BashirMonZ assessment laboratory

This fork is developed and maintained by **BashirMonZ**, building on airgeddon by
v1s1t0r and its contributors. Original attribution and the GPL license remain intact.

Use wireless capture and offline recovery only on networks and files you own or
are explicitly authorized to assess. Captures, wordlists and recovered passwords
can be sensitive; store them privately and do not commit them to Git.

## What changed

- All eight configurable timeout contexts accept **1–40,000 seconds**, including
  WPS, handshake/PMKID capture, identity capture, certificate analysis and WPA3
  analysis. Blank input retains the existing default. Defaults have not increased.
- The normal handshake capture flow checks whether saving the capture succeeded
  before offering to open the existing offline recovery menu. The prompt defaults
  to **No**. It does not silently start cracking or choose a dictionary.
- Main menu **14** opens a laboratory with tool readiness, capture metadata,
  wordlist statistics and a link to the existing offline recovery menus.
- A local command-line laboratory runs without root, X11, a wireless adapter,
  network access or starting the interactive application.
- Container builds retain distribution-maintained Hashcat instead of replacing it
  with an unpinned Hashcat 2.0 binary, and include optional inspection utilities.
- Hardware-free tests cover timeout validation, capture-save handling, recovery
  consent, diagnostics, file safety and error handling.

## Timeout is a budget, not a rate limit

40,000 seconds is 11 hours, 6 minutes, 40 seconds. Increasing this maximum permits a
longer operation; it does **not** make traffic capture or password recovery faster.
Existing interrupt and early-success handling remain in place. Very short capture
budgets may expire before a useful exchange occurs. Use a realistic budget rather
than automatically choosing the maximum.

## Existing diagnostic utilities

Run these from the checkout, or use an absolute path to `airgeddon.sh`:

```bash
bash airgeddon.sh --lab help
bash airgeddon.sh --lab tools
bash airgeddon.sh --lab capture '/path/to/authorized capture.cap'
bash airgeddon.sh --lab wordlist '/path/to/my dictionary.txt'
```

`tools` inventories more than 50 tools grouped by capability. It only checks
whether commands are present; it never installs software or runs the listed tools.
A command being available does not establish compatible drivers, versions, GPU
support or hardware. Optional dependencies remain optional.

`capture` requires `capinfos` (commonly provided by Wireshark packages), `readlink`
and GNU `timeout`. It reads metadata, **not** passwords. Metadata alone does not
prove that a capture contains a usable handshake. The existing recovery workflow
still performs its own target selection and validation.

`wordlist` requires `awk` and GNU `timeout`. It reports entry counts, empty entries,
8–63-byte candidate counts and 64-character hexadecimal candidate counts without
printing candidate text. CRLF line endings are accounted for; length is measured
in bytes, not Unicode characters. This is a basic inventory, not a complete
validation of every password format or recovery tool's parsing rules.

Both file inspections have a 15-second execution budget and report failure if the
budget expires. Inputs must be readable, nonempty regular files. Neither utility
rewrites the input. There is no automatic package download, GPU benchmark,
wordlist download, credential upload or password-recovery process.

## Offline recovery workflow

After a successful save in the normal handshake capture flow, explicitly accept
the recovery-menu prompt, or choose main menu **6** / laboratory **4** later. Select
the authorized capture and a dictionary in the existing menu. Already-selected
capture paths can be reused using the existing confirmation prompt.

Before a personal offline recovery job starts, an optional **password format**
prompt accepts a position-by-position example in braces, such as `{OC43DE32}`.
Uppercase letters stand for A–Z, lowercase letters for a–z, and digits for 0–9;
the example maps to `?u?u?d?d?u?u?d?d`. Braces are delimiters, not part of the
password. Brace examples accept **8–63 ASCII alphanumeric positions**. For fixed
characters, symbols and a custom character set, Hashcat selections also accept
`mask:HOME?d?d?d?d` and the explicit format builder described in
[OPERATIONS.md](OPERATIONS.md). Raw 64-digit PSKs remain outside this interface.
This is a character-type template, **not** the exact password to try.

- **Press Enter to skip** and keep the selected dictionary/rules/bruteforce flow.
- A supplied format replaces that job's dictionary/rules/length/charset settings
  with a fixed-length search. The program shows the derived pattern and search
  space and requires explicit confirmation before starting it. Declining or EOF
  cancels the job; it never falls back to an unrestricted search.
- Hashcat uses a fixed mask (no `--increment`); Aircrack streams candidates from
  Crunch, which must be installed for this optional path. No giant dictionary
  file is generated. Enterprise and automatic credential-verification paths are
  unchanged. Formats are not reused or saved for the next job.
- A format narrows candidate structure, not necessarily to a practical number.
  `{OC43DE32}` still represents **4,569,760,000 candidates**. If your assumption
  is wrong, the password will not be among them. There is no speed or success
  guarantee. Only use captures/hashes you own or are authorized to assess.

A handshake is not the Wi-Fi password. Offline recovery only succeeds if the
selected method can find the actual password; strong random passwords may remain
infeasible to recover. No 10× improvement or guaranteed recovery is claimed.

## Windows support — coming soon

This is a visible roadmap notice, not a Windows implementation or support claim.
Native Windows remains unsupported. No background service or installer is added.
Hardware passthrough, wireless drivers, privilege handling and platform-specific
process management require separate design and testing before support can ship.

## Development and tests

```bash
bash tests/run.sh
shellcheck scripts/*.sh tests/*.sh
```

Tests use temporary fixtures and mocks, never real wireless operations, cracking,
package installation or host firewall changes. CI runs these checks on pull requests.
`airgeddon.sh` can now be sourced to expose its functions without calling `main` or
installing signal traps; sourcing still initializes its global variables.

These focused scripts replace the requested artificial line-count expansion:
adding 30,000 lines of padding would not add performance, functionality or tests.
This is a functional first increment, not a claim to have tripled the application
or multiplied the recovery engine's performance.

The interactive runtime path is unchanged: install the usual Linux prerequisites,
configure `.airgeddonrc` (or `/etc/airgeddonrc`, which takes precedence), then run
`sudo bash airgeddon.sh`. Only do this in an authorized, isolated assessment
setup. The read-only `--lab` commands do not need sudo.

## Automatic CPU-only recovery profile

When you select an existing Hashcat recovery option, supported Hashcat versions
(3 or newer) now perform a bounded, eight-second `hashcat -I` backend probe.
Successful CPU-only detection selects CPU devices (`-D 1`) and the throughput-oriented
workload profile (`-w 3`). The backend runtime manages its own parallelism; this
change does not invent thread counts or force global OpenMP settings. The CPU
profile also removes the legacy `--force` flag so runtime warnings stay effective.

This profile may improve throughput but can make the desktop less responsive and
increase power use or heat. It does not overclock, change CPU governors, disable
thermal safeguards, enable optimized kernels that shorten password-length support,
or promise a particular speedup. GPU/mixed-device backends, failed probes and
unrecognized output retain their existing settings. Merely owning a display GPU
is not treated as proof of a usable compute backend. Reported device types are
handled conservatively, including skipped/unsupported accelerators.

Probe results, including failures, are cached for the process and refreshed when
the detected executable path or reported Hashcat version changes. Ordinary program
startup and the `tools` inventory do not perform this probe. Restart airgeddon after
changing drivers to refresh detection for an unchanged executable/version.

Choose a profile with an environment variable (not an `.airgeddonrc` setting):

```bash
sudo env AIRGEDDON_CPU_PROFILE=auto bash airgeddon.sh      # default: CPU-only -w 3
sudo env AIRGEDDON_CPU_PROFILE=balanced bash airgeddon.sh  # CPU-only -w 2
sudo env AIRGEDDON_CPU_PROFILE=off bash airgeddon.sh       # keep previous settings
bash airgeddon.sh --lab performance                       # report only; no benchmark
```

The report shows available logical CPUs and the compute backend, and is also
available as laboratory option **5**. It does not claim to detect which device a
separately launched recovery process is currently using. Missing Hashcat, missing
GNU timeout or driver errors report an unknown backend rather than guessing.
Aircrack-ng, John, capture behavior and unrelated system processes are unchanged.

## Dragon status console

The existing portal startup now displays a static ASCII dragon with
**Initialization of portals**, followed by messages for workspace preparation,
access-point setup, addressing/DHCP/routing, the control workflow, DNS, portal
pages/web service startup, shutdown and restoration. The display does not add,
remove or reorder operational commands.

These are **stage announcements**, not independently verified readiness checks.
The console tells you to inspect the existing control window and service logs for
readiness or failures; it never substitutes a fabricated success bar for actual
health checks. No additional network probes, portal capability or attack behavior
are introduced.

Preview the display without root or starting any service:

```bash
bash airgeddon.sh --lab dragon
```

It is also available as laboratory option **6**. Preview output is explicitly
marked as a preview. The static art has no animation loop, sleeps or extra CPU
load in the background. Redirected output is plain text, and `NO_COLOR` and the
existing `AIRGEDDON_BASIC_COLORS=false` setting disable colored stage labels.
Disable the theme entirely with an environment variable:

```bash
sudo env AIRGEDDON_DRAGON_UI=off bash airgeddon.sh
```

`AIRGEDDON_DRAGON_UI` is an environment setting, not an `.airgeddonrc` setting.
The theme is optional: if its module is missing, the existing portal flow remains
available without it. Hardware-free tests check the status output and verify
that the mocked operational sequence is identical with the theme on or off.

## Health, hardware, training and recovery preflight

The laboratory menu now includes options **7–12**, also available without root:

```bash
bash airgeddon.sh --lab health
bash airgeddon.sh --lab hardware
bash airgeddon.sh --lab quality '/path/to/authorized capture.cap'
bash airgeddon.sh --lab preflight '/path/to/authorized capture.cap' '/path/to/my dictionary.txt'
bash airgeddon.sh --lab train
bash airgeddon.sh --lab report
bash airgeddon.sh --lab report './private-assessment.md'
```

### Local health snapshot

`health` takes bounded, local `ps` and `ss` snapshots. It reports whether selected
AP/DHCP/DNS/web processes and default-port listeners are observed, without dumping
process arguments or endpoint addresses. Missing tools or failed queries are
reported as **UNKNOWN**, not as evidence of health. Nothing is scanned or started.
Run it in another terminal while an authorized lab workflow is running if needed.

These are system-wide observations, not verified instance ownership or protocol
health. A running process or open port does not prove correct configuration,
application responses, successful DHCP allocation or working DNS. Custom ports
are not included. Existing control windows and logs remain necessary.

### Hardware summary

`hardware` runs a bounded, read-only `iw list` query and reports aggregate advertised
AP, managed and monitor-mode capabilities. It does not scan nearby networks,
change an adapter's mode, show device identifiers or prove injection/concurrency
support. Aggregation does not mean every mode is supported by every adapter.
Use the existing dependency/version checks and CPU/backend report as appropriate.

### Capture evidence and preflight

`quality` runs a bounded offline tshark analysis requesting only EAPOL frame
numbers, then prints the count and limitations. It prints no addresses, SSIDs or
packet payloads. Positive evidence is **not a complete-handshake verdict**:
retransmissions, missing messages, wrong targets and other validation issues may
remain. Zero EAPOL packets does not exclude a PMKID-only capture.

`preflight` combines that analysis with the existing private wordlist statistics.
It returns failure when either inspection fails, and never launches a recovery
job, chooses a target, generates candidates or estimates success probability.
Dependencies: tshark, GNU timeout, readlink and awk. Each file inspection retains
its existing 15-second budget plus up to two seconds for forced termination.

### Offline training

`train` is a fixed, clearly labeled simulation: it shows a mocked portal startup
failure and cleanup discussion with the dragon display. It needs no services,
wireless adapter, real capture or real credentials. It does not call wireless,
packet-analysis or password-recovery tools. It is a teaching/demo mode, not a
network isolation boundary for the ordinary interactive workflows.

### Credential-safe diagnostic reports

`report` generates an allowlisted summary of tool availability, local service
observations, limitations and defensive recommendations. It **does not ingest
or claim to redact arbitrary logs**. Raw logs, process arguments, hostnames,
file paths, SSIDs, addresses, passwords and wordlist contents are excluded by
construction. Review even this summary before sharing: service/tool presence can
still reveal information about a host.

With an output path, the report is staged privately in the destination directory
and atomically published without overwriting existing files. The resulting file
has mode **0600**. Existing regular files, symlinks, directories, FIFOs and devices
are refused. Filesystems that cannot hard-link files fail safely. With no path,
stdout is used; any shell redirection you add is your responsibility.

The report is a diagnostic assessment aid, not evidence that a vulnerability was
found. It includes WPA3/WPS/passphrase/firmware recommendations but does not invent
an audit result or collect recovered credentials.

## Emergency cleanup and firewall snapshot protection

Interactive startup now installs TERM/EXIT handlers. Recovery is armed only after
normal startup variables are initialized. Sourcing the script and read-only lab
commands do not install or arm these traps. Normal explicit exits mark their
existing cleanup complete so the EXIT handler does not repeat it.

On termination or an unexpected shell exit, best-effort recovery:

- acts only once, ignoring repeated TERM while recovery is in progress;
- only signals tracked direct child processes after checking their parent PID;
- requests routing/firewall restoration when a trusted snapshot exists;
- requests monitor-mode and spoofed-MAC restoration and, for the last registered
  session only, NetworkManager restart;
- limits newly introduced recursive temporary cleanup to an owned, non-symlink
  `/tmp/ag<number>/` instance directory;
- keeps the original unexpected exit status; TERM exits with status 143.

Firewall cleanup now validates a nonempty, owned, non-symlink snapshot using the
selected backend's check/test mode **before global cleanup**. If validation fails,
only instance rules are targeted, and the snapshot is retained. Restoration
failure also retains the snapshot rather than deleting the only recovery copy.
Backends lacking the required validation mode fail conservatively.

This is not a guarantee of complete restoration. Existing firewall and multi-instance
operations are not transactional or fully locked. Validation can fail against a
changed live ruleset; restoration can fail after cleanup. Tmux-owned processes
that are not children of the shell are not blindly terminated. Driver failures,
service-manager hangs, externally changed state, SIGKILL, power loss and kernel
failure may still require manual recovery. Inspect warnings and retained snapshots
locally before applying any manual restoration. Keep assessments isolated and do
not rely on this tool to preserve unrelated live production networking.

Tests cover the new functionality with synthetic command output and mocked state
restoration; no real packet capture, cracking job or firewall change is performed.

## Advanced Extension

Main menu **15** opens the five requested research sections; laboratory **13**
opens the same extension. Main menu **16** and extension **6** open the shared
evidence, wordlist/password audit and report tools. Menus use the native airgeddon title/color helpers,
ASCII separators and aligned option numbering, with a pause after results.
No terminal font override or graphical dashboard is introduced. Section labels
are currently English; the existing application selection/pause prompts retain
its selected language. Redirected extension output omits ANSI color codes.

Open the local menus without starting the main application or requiring root:

```bash
bash airgeddon.sh --lab advanced
bash airgeddon.sh --lab laboratory
bash airgeddon.sh --lab research-tools
```

These are working local analyzers, not fixed demonstration results. Evidence
records and reports are actually written when requested. Source files remain
unchanged: modifying a capture would invalidate the evidence being analyzed.
Nothing starts an unspecified on-air test, service, recovery job or config edit.
See [ADVANCED_EXTENSION.md](ADVANCED_EXTENSION.md) for every input format, CLI
command, output status, evidence/report workflow and analysis limitation.

### Research reliability improvements

- Repeated same-peer/stage/replay EAPOL rows preserve already matched handshake
  stages; strict peer/replay/timing checks and cryptographic limitations remain.
- Bounded tshark diagnostics distinguish recognized version/field, capture-format,
  truncation and permission failures without exposing raw tool diagnostics.
- Report manifests support `{"rogue-ap":{"file":"authorized.pcapng","baseline":"approved.json"}}`,
  while existing path-only manifests remain valid. Summaries explicitly count
  unavailable and baseline-required sections.

These are functional changes, not an artificial source-line multiplier or a
claim of 5× throughput, recovery success, or complete wireless-security coverage.

## Managed operations

Main menu **16** / `--lab research-tools` now includes preflight (5), an explicit
format builder (6), named private Hashcat jobs with progress/runtime/workload and
verified checkpoint resume (7), and case folders/redacted report export (8).
Creating a profile does not start recovery: run/resume requires confirmation.
See [OPERATIONS.md](OPERATIONS.md) for commands, input snapshots, supported tool
versions, workload-vs-CPU-cap distinctions, translation coverage and limitations.

The new translation pack covers core German/Spanish/French headings and selected
operations prompts, with English fallback for untranslated strings/languages.
Installed-engine tests are optional locally and required in CI; they do not
establish real GPU/checkpoint compatibility when skipped or mocked.
