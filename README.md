Below are ready-to-copy GitHub docs focused solely on Solution B (the pure-Python “mini nmap”). Paste each block into a file with the indicated name.

README.md
```markdown
# mini-nmap (Pure-Python Network Scanner)

A practical, pure-Python network scanner inspired by Nmap. It implements common features for day-to-day host discovery and port scanning without requiring the Nmap binary.

Legal note: Only scan systems you own or have explicit permission to test.

## Features

- Host discovery: ICMP ping (if Scapy) or TCP ping fallback
- Scans:
  - TCP connect (-sT)
  - TCP SYN (-sS, requires Scapy + root)
  - UDP best-effort (-sU)
- Version detection (-sV): lightweight banner grabbing
- Heuristic OS guess (-O): TTL/window hints (requires Scapy)
- Traceroute (--traceroute): Scapy-based
- Timing templates (-T0..-T5), parallelism control (--min-rate)
- Output: normal text (-oN) and JSON (-oJ)

Not a full Nmap replacement. See “Limitations” below.

## Requirements

- Linux (tested) and Python 3.10+
- Optional for raw features:
  - Scapy: `pip install scapy`
  - Root privileges (sudo) for SYN scan, ICMP discovery, and traceroute

## Installation

```bash
git clone <your-repo-url>.git
cd <your-repo-dir>

# Optional: create a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# For raw packet features (recommended)
pip install scapy
```

No external binaries are required.

## Quick Start

Basic TCP connect scan of common ports (22, 80, 443 by default):
```bash
python mini_nmap.py 192.168.1.10
```

SYN + version + OS guess over a subnet:
```bash
sudo python mini_nmap.py -sS -sV -O -p 1-1000 -T4 192.168.1.0/24
```

Ping sweep only (no port scan):
```bash
sudo python mini_nmap.py -sn 10.0.0.0/24
```

UDP best-effort + traceroute:
```bash
sudo python mini_nmap.py -sU -p 53,123,161 --traceroute -T3 example.com
```

JSON output to a file:
```bash
python mini_nmap.py -sT -p 22,80,443 -oJ scan.json scanme.nmap.org
```

## Usage

Show help:
```bash
python mini_nmap.py -h
```

Targets:
- IPs, hostnames, CIDR, or simple range `192.168.1.10-20`
- Examples: `10.0.0.5`, `scanme.nmap.org`, `192.168.1.0/24`

Ports:
- `-p "22,80,443"` or `-p "1-1024"`

Scan types:
- `-sT` TCP connect scan
- `-sS` TCP SYN scan (Scapy + root)
- `-sU` UDP best-effort scan

Discovery and extras:
- `-sn` Ping scan only (host discovery; no ports)
- `-Pn` Treat all hosts as up (skip discovery)
- `-sV` Version detection (banner grab)
- `-O` OS guess (heuristic; Scapy)
- `--traceroute` Traceroute (Scapy)

Timing and output:
- `-T 0..5` Timing template (default 3)
- `--min-rate N` Override parallelism (connections in flight)
- `-oN file` Normal text output file
- `-oJ file` JSON output file

## Example Output (text)

```
Starting mini-nmap at 2025-01-01 12:00:00
Nmap scan report for 192.168.1.10
Host is up (3ms latency).
PORT     STATE         SERVICE        VERSION/BANNER
22/tcp   open          ssh            SSH-2.0-OpenSSH_9.0
80/tcp   open          http           HTTP/1.1 200 OK
443/tcp  closed        https
OS guess: Linux/Unix/macOS (likely)
```

## Limitations

- Not feature-parity with Nmap:
  - Missing many scan types (FIN/XMAS/ACK), IPv6, NSE scripts, proxies/decoys, fragmentation, spoofing, etc.
- UDP results often appear as “open|filtered” without ICMP feedback.
- OS detection is heuristic and not authoritative.
- Raw features require Scapy and root privileges.
- When scanning both TCP and UDP on the same port number, results are summarized per port number and may not distinguish protocol in combined views.

## Troubleshooting

- Raw features not working: run with `sudo` and install Scapy (`pip install scapy`).
- No hosts appear up: firewalls may block ping—try `-Pn`.
- DNS resolution issues: use direct IPs or check `/etc/resolv.conf`.
- Slow or timeouts: increase speed with `-T4`/`-T5` and/or `--min-rate`; beware of false “filtered” on high-latency links.

## Performance Tips

- Use `-T4` for faster but still pragmatic scanning.
- Restrict port ranges with `-p` for quicker results.
- Prefer SYN scan (`-sS`) for speed and lower connection overhead (requires root + Scapy).

## Roadmap

- Additional scan types (FIN/XMAS/ACK)
- Basic IPv6 support
- Pluggable probe library (NSE-like light scripts)
- Service fingerprint database
- More output formats (e.g., XML)

## Security and Ethics

- Only scan with authorization.
- Follow local laws and acceptable-use policies.
- Respect rate limits and avoid disrupting production systems.

## License

MIT (recommended). Add a LICENSE file to this repository.
```

CONTRIBUTING.md
```markdown
# Contributing to mini-nmap (Pure-Python)

Thanks for your interest in contributing! This repository contains a single tool of focus: `mini_nmap.py`, a pure-Python network scanner.

We welcome fixes, features, docs, and tests—especially improvements to reliability, output, and safety.

## Code of Conduct

Be respectful and constructive. Assume good faith. Keep reviews and discussions focused on the code and the problem.

## Development Setup

```bash
git clone <your-repo-url>.git
cd <your-repo-dir>

python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install scapy  # for raw packet features used by -sS/-O/--traceroute
```

Recommended tooling:
- Formatting: `black` and `isort`
- Linting: `ruff` or `flake8`
- Testing: `pytest` (for unit/integration tests)

```bash
pip install black isort ruff pytest
```

Format/lint:
```bash
black .
isort .
ruff check .
```

## Running Locally

Help/usage:
```bash
python mini_nmap.py -h
```

Examples:
```bash
python mini_nmap.py -sT -p 22,80,443 127.0.0.1
sudo python mini_nmap.py -sS -p 1-100 127.0.0.1
sudo python mini_nmap.py -sn 192.168.1.0/24
```

Note: SYN scan, ICMP discovery, and traceroute require Scapy and root privileges.

## Contribution Guidelines

- Open an issue for larger features to discuss design before implementation.
- Keep CLI flags backward compatible; document any changes in the README.
- Add in-code comments for non-obvious networking logic or heuristics.
- Prefer conservative defaults; do not enable aggressive scanning by default.
- Update README examples and flags when adding features.
- Write tests where feasible (e.g., unit tests for parsers and helpers; mark slow/integration tests).

## Commit Messages

Use clear, descriptive messages:
- feat: add UDP payload probe for NTP
- fix: handle ConnectionRefusedError in TCP connect scan
- docs: expand README troubleshooting
- chore: format with black

## Security

- Validate inputs (target parsing, port ranges).
- Avoid enabling spoofing/decoys or unsafe behaviors by default.
- Do not commit secrets or private data. See SECURITY.md for reporting vulnerabilities.

## Licensing

By contributing, you agree that your contributions will be licensed under the project’s chosen license (see LICENSE).
```

SECURITY.md
```markdown
# Security Policy

We take security seriously. If you discover a vulnerability or a behavior that could be abused in `mini_nmap.py`, please report it responsibly.

Please include:
- A description of the issue and potential impact
- Steps to reproduce (PoC, logs, environment)
- Affected versions/commit hashes

We aim to acknowledge valid reports within 5 business days.

## Scope

- `mini_nmap.py` (host discovery, TCP/UDP scanning, banner grabbing, traceroute, OS guess)

Out of scope:
- Vulnerabilities in third-party libraries (e.g., Scapy). Report to their projects.

## Responsible Disclosure

Please give us reasonable time to investigate and release a fix before public disclosure.

## Safe Defaults

- Raw packet features require explicit root privileges.
- Defaults avoid overly aggressive timing.
- Documentation reminds users to scan only with authorization.
```
