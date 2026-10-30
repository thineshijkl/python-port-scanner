# Python Port Scanner

A fast, multithreaded TCP connect port scanner written in pure Python (standard library only). It detects open ports, identifies common services, grabs service banners, and exports results to JSON or CSV.

> **Legal notice:** This tool is for educational use and authorized security testing only. Scan only systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your country.

## Features

- TCP connect scanning using full three-way handshakes
- Multithreaded scanning (configurable thread count)
- Flexible port selection: single ports, lists, ranges, or a built-in list of common ports
- Service name lookup for open ports
- Optional banner grabbing (including the `Server` header on HTTP ports)
- JSON and CSV export for reports
- Input validation and clear error messages
- Unit tests using Python's built-in `unittest`
- No third-party dependencies

## How it works

For each port, the scanner attempts a normal TCP connection:

| Port state | What happens | Result |
|------------|--------------|--------|
| Open | The server answers SYN with SYN-ACK and the handshake completes | Reported as open |
| Closed | The server answers with RST (reset) | Skipped, and fast |
| Filtered | A firewall silently drops packets, so there is no reply | Skipped after the timeout |

Scans run in parallel using a thread pool, which turns a scan that would take hours sequentially into seconds.

## Requirements

- Python 3.8 or newer
- No external packages

## Installation

```bash
git clone https://github.com/thineshijkl/python-port-scanner.git
cd python-port-scanner
```

## Usage

```bash
# Scan the default range (1-1024)
python scanner.py 127.0.0.1

# Scan specific ports
python scanner.py 127.0.0.1 -p 22,80,443

# Scan a range with banner grabbing
python scanner.py 127.0.0.1 -p 1-10000 -b

# Scan common ports only and save results as JSON
python scanner.py scanme.nmap.org --common -o scan_results/scanme.json

# Save as CSV instead
python scanner.py 127.0.0.1 -p 1-1024 -o scan_results/local.csv
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Hostname or IPv4 address | required |
| `-p`, `--ports` | Ports to scan, e.g. `80`, `22,80,443`, `1-1024` | `1-1024` |
| `-c`, `--common` | Scan a list of common ports only | off |
| `-t`, `--threads` | Number of worker threads (1 to 500) | `100` |
| `--timeout` | Seconds to wait per port | `1.0` |
| `-b`, `--banner` | Try to grab service banners | off |
| `-o`, `--output` | Save results to `.json` or `.csv` | none |

## Example output