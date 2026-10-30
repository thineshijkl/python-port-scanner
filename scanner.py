#!/usr/bin/env python3
"""
Python Port Scanner

A multithreaded TCP connect scanner with service detection, banner grabbing
and JSON/CSV export.

LEGAL NOTICE: For educational use only. Scan only systems you own or have
explicit written permission to test. Unauthorized scanning may be illegal.
"""

import argparse
import csv
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# The most commonly used service ports, used by the --common option.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443,
]

# Ports where we send a simple HTTP request to provoke a response.
HTTP_PORTS = {80, 8000, 8080, 8888}


def parse_ports(spec):
    """Turn a string like '22,80,100-200' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid range '{part}': start is greater than end")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("No ports specified")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def get_service_name(port):
    """Look up the standard service name for a TCP port, if there is one."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock, host, port):
    """Try to read a short banner from an already connected socket."""
    try:
        if port in HTTP_PORTS:
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.sendall(request.encode())
        data = sock.recv(1024).decode(errors="ignore")
    except OSError:
        return ""

    lines = [line.strip() for line in data.splitlines() if line.strip()]
    if not lines:
        return ""

    if port in HTTP_PORTS:
        for line in lines:
            if line.lower().startswith("server:"):
                return line[:100]
    return lines[0][:100]


def scan_port(ip, port, timeout, grab):
    """Scan one TCP port. Return a result dict if open, otherwise None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # connect_ex returns 0 when the TCP handshake succeeds.
        if sock.connect_ex((ip, port)) != 0:
            return None
        banner = grab_banner(sock, ip, port) if grab else ""
        return {
            "port": port,
            "state": "open",
            "service": get_service_name(port),
            "banner": banner,
        }
    except OSError:
        return None
    finally:
        sock.close()


def print_result(result):
    """Print one open port as soon as it is found."""
    line = f"[+] {result['port']}/tcp open  {result['service']}"
    if result["banner"]:
        line += f"  | {result['banner']}"
    print(line)


def run_scan(ip, ports, threads, timeout, grab):
    """Scan all ports using a pool of worker threads."""
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, p, timeout, grab) for p in ports]
        try:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    print_result(result)
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Cancelling remaining ports...")
            for future in futures:
                future.cancel()
    return sorted(results, key=lambda r: r["port"])


def save_results(path, meta, results):
    """Save results as CSV (if path ends in .csv) or JSON."""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)

    if path.lower().endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**meta, "open_ports": results}, f, indent=2)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner. Scan only systems you are authorized to test."
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="ports to scan, e.g. 80 or 22,80,443 or 1-1024 (default: 1-1024)",
    )
    parser.add_argument(
        "-c", "--common", action="store_true",
        help="scan only a list of common ports (overrides --ports)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="number of worker threads (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="seconds to wait per port (default: 1.0)",
    )
    parser.add_argument(
        "-b", "--banner", action="store_true",
        help="try to grab service banners from open ports",
    )
    parser.add_argument(
        "-o", "--output",
        help="save results to a file (.json or .csv)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.threads < 1 or args.threads > 500:
        parser.error("--threads must be between 1 and 500")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        ports = COMMON_PORTS if args.common else parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: could not resolve host '{args.target}'")
        sys.exit(1)

    print("Only scan systems you own or have permission to test.")
    print(f"Target : {args.target} ({ip})")
    print(f"Ports  : {len(ports)} port(s), {args.threads} threads, {args.timeout}s timeout")
    print(f"Started: {datetime.now().isoformat(timespec='seconds')}")
    print("-" * 50)

    start = time.perf_counter()
    results = run_scan(ip, ports, args.threads, args.timeout, args.banner)
    duration = time.perf_counter() - start

    print("-" * 50)
    print(f"Scan complete: {len(results)} open port(s) found in {duration:.2f}s")

    if args.output:
        meta = {
            "target": args.target,
            "ip": ip,
            "scanned_ports": len(ports),
            "started": datetime.now().isoformat(timespec="seconds"),
            "duration_seconds": round(duration, 2),
        }
        save_results(args.output, meta, results)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()