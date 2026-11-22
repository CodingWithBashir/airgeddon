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
- A read-only command-line laboratory runs without root, X11, a wireless adapter,
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

## Read-only utilities

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
