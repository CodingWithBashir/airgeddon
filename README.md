# airgeddon — BashirMonZ fork

Fork developed and maintained by **BashirMonZ**. Original airgeddon by v1s1t0r
and its contributors; upstream credits and GPL license are preserved.

**Windows support — coming soon.** Native Windows is not currently supported.

See the [assessment laboratory guide](docs/LABORATORY.md) for the 1–40,000-second
timeout range, read-only tool/capture/wordlist diagnostics, and the opt-in handoff
to the existing offline recovery menu. Longer timeouts are not a speed increase;
a captured handshake does not guarantee recovery. Use only on authorized networks.

```bash
bash airgeddon.sh --lab help   # no sudo, GUI or wireless adapter needed
bash airgeddon.sh --lab tools
bash airgeddon.sh --lab dragon      # preview only; starts no services
bash airgeddon.sh --lab performance  # CPU/backend report; no benchmark
bash tests/run.sh             # hardware-free regression checks
```


Hashcat recovery now automatically uses a throughput-oriented profile when a
bounded device probe confirms a CPU-only backend. GPU/unknown backends retain
existing settings. For a more responsive desktop use `AIRGEDDON_CPU_PROFILE=balanced`,
or `off` to disable tuning. See the laboratory guide for trade-offs; no fixed
speedup is guaranteed.

[![Version-shield]](https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/CHANGELOG.md) [![Bash4.2-shield]](http://tldp.org/LDP/abs/html/bashver4.html#AEN21220) [![License-shield]](https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/LICENSE) [![Docker-shield]](https://github.com/v1s1t0r1sh3r3/airgeddon/actions/workflows/master.yml) [![Discord-shield]](https://discord.gg/sQ9dgt9)

[![Paypal-shield]](https://www.paypal.com/paypalme/airgeddon) [![Cryptocurrencies-shield]](https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contributing-&-Code-of-Conduct)


> This is a multi-use bash script for Linux systems to audit wireless networks.

![Banner]

---

All the needed info about how to "install | use | enjoy" `airgeddon` is present at [GitHub's Wiki].

- *I. Content & Features*
  - [Home]
  - [Features]
  - [Screenshots]
  - [Wallpapers]


- *II. Requirements*
  - [Requirements]
  - [Compatibility]
	 - [Cards and Chipsets]
	 - [Wayland]
	 - [Consistent Network Device Naming]
	 - [Kali Nethunter]
  - [Essential Tools]
  - [Optional Tools]
	 - [BeEF Tips]
	 - [Hashcat Tips]
	 - [Bettercap Tips]
  - [Update Tools]
  - [Internal Tools]
  - [Known incompatibilities]


- *III. Getting started*
  - [Installation & Usage]
  - [Options]
  - [Docker]
	 - [Linux]
	 - [Mac OSX]
	 - [Windows]
  - [Other Sources]
  - [FAQ & Troubleshooting]


- *IV. Learning*
  - [CWP Certification]


- *V. Project & Development*
  - [Official Website]
  - [Plugins system]
	 - [Plugins development]
	 - [Plugins Hall of Fame]
  - [Supported Languages]
  - [Contributing & Code of Conduct]
  - [Security Policy]
  - [Merchandising Online Shop]
  - [Changelog]
  - [Disclaimer & License]
  - [Contact]


- *VI. Acknowledgments & References*
  - [Hat Tip To]
  - [Inspiration]

---

[Banner]: https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/imgs/banners/airgeddon_banner.png "We will conquer the earth!!"
[GitHub's Wiki]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki

[Home]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki
[Features]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Features
[Screenshots]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Screenshots
[Wallpapers]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Wallpapers
[Requirements]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Requirements
[Compatibility]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Compatibility
[Cards and Chipsets]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Cards%20and%20Chipsets
[Wayland]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Wayland
[Consistent Network Device Naming]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Consistent%20Network%20Device%20Naming
[Kali Nethunter]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Kali%20Nethunter
[Essential Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Essential%20Tools
[Optional Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Optional%20Tools
[BeEF Tips]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/BeEF%20Tips
[Hashcat Tips]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Hashcat%20Tips
[Bettercap Tips]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Bettercap%20Tips
[Update Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Update%20Tools
[Internal Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Internal%20Tools
[Known incompatibilities]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Known%20incompatibilities
[Installation & Usage]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Installation%20&%20Usage
[Options]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Options
[Docker]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker
[Linux]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker%20Linux
[Mac OSX]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker%20Mac%20OSX
[Windows]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker%20Windows
[Other Sources]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Other%20Sources
[FAQ & Troubleshooting]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/FAQ%20&%20Troubleshooting
[CWP Certification]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/CWP%20Certification
[Plugins system]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20System
[Plugins development]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20Development
[Plugins Hall of Fame]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20Hall%20of%20Fame
[Supported Languages]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Supported%20Languages
[Contributing & Code of Conduct]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contributing-&-Code-of-Conduct
[Security Policy]: https://github.com/v1s1t0r1sh3r3/airgeddon/security/policy
[Merchandising Online Shop]: https://airgeddon.creator-spring.com/
[Changelog]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Changelog
[Disclaimer & License]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Disclaimer%20&%20License
[Contact]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contact
[Hat Tip To]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Hat%20Tip%20To
[Inspiration]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Inspiration
[Official Website]: https://airgeddon.pro/

[Version-shield]: https://img.shields.io/badge/version-12.10-blue.svg?style=flat-square&colorA=273133&colorB=0093ee "Latest version"
[Bash4.2-shield]: https://img.shields.io/badge/bash-4.2%2B-blue.svg?style=flat-square&colorA=273133&colorB=00db00 "Bash 4.2 or later"
[License-shield]: https://img.shields.io/badge/license-GPL%20v3%2B-blue.svg?style=flat-square&colorA=273133&colorB=bd0000 "GPL v3+"
[Docker-shield]: https://github.com/v1s1t0r1sh3r3/airgeddon/actions/workflows/master.yml/badge.svg?branch=master "Docker CI master"
[Discord-shield]: https://img.shields.io/discord/629812069964840991.svg?style=flat-square&colorA=273133&colorB=CBA317&logo=discord&label=Discord%20chat
[Paypal-shield]: https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square&colorA=273133&colorB=b008bb "Paypal"
[Cryptocurrencies-shield]: https://img.shields.io/badge/donate-cryptocurrencies-blue.svg?style=flat-square&colorA=273133&colorB=f7931a "Cryptocurrencies"
