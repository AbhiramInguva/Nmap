
"""
mini_nmap.py — A pure-Python network scanner inspired by nmap.

This is NOT a full replacement for nmap. It implements a practical subset:
  - Host discovery (ICMP if scapy is available; else TCP ping)
  - TCP connect scan (-sT)
  - TCP SYN scan (-sS) if scapy installed and root
  - UDP scan (-sU) best-effort for common UDP behaviors
  - Version detection (-sV) by banner grabbing and simple probes
  - Simple OS guess (-O) using TTL/window heuristics (requires scapy)
  - Traceroute (--traceroute) via scapy
  - Timing templates (-T0..-T5), JSON/text output (-oJ/-oN)

Install scapy for raw features:
  pip install scapy
Run with privileges for raw packet features (sudo).

Usage examples:
  python mini_nmap.py -sT -p 22,80,443 192.168.1.10
  sudo python mini_nmap.py -sS -sV -O -p 1-1000 -T4 192.168.1.0/24
  sudo python mini_nmap.py -sn 10.0.0.0/24
  sudo python mini_nmap.py -sU -p 53,123,161 --traceroute -T3 example.com

Limitations:
  - Not all nmap scan types/features implemented.
  - UDP results often “open|filtered” without ICMP feedback.
  - OS guess is heuristic and not authoritative.
"""

import argparse
import asyncio
import concurrent.futures
import contextlib
import ipaddress
import json
import random
import socket
import struct
import sys
import time
from typing import List, Dict, Any, Optional, Tuple

# Optional scapy
try:
    from scapy.all import (
        IP, ICMP, TCP, UDP, sr1, sr, conf, L3RawSocket,
        traceroute as scapy_traceroute
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# -------------------- Timing profiles --------------------
TIMING_PROFILES = {
    0: {"conn_limit": 64,  "timeout": 5.0, "udp_timeout": 2.0, "retries": 2, "delay": 0.02},
    1: {"conn_limit": 128, "timeout": 3.0, "udp_timeout": 1.5, "retries": 2, "delay": 0.01},
    2: {"conn_limit": 256, "timeout": 2.0, "udp_timeout": 1.2, "retries": 1, "delay": 0.005},
    3: {"conn_limit": 512, "timeout": 1.5, "udp_timeout": 1.0, "retries": 1, "delay": 0.002},
    4: {"conn_limit": 1024,"timeout": 1.0, "udp_timeout": 0.8, "retries": 0, "delay": 0.0},
    5: {"conn_limit": 2048,"timeout": 0.7, "udp_timeout": 0.5, "retries": 0, "delay": 0.0},
}

# -------------------- Port to service hints --------------------
SERVICE_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "domain", 67: "dhcp", 68: "dhcp",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2379: "etcd", 2380: "etcd-peer",
    27017: "mongodb", 3000: "http-alt", 3306: "mysql",
    3389: "ms-wbt-server", 4433: "https-alt", 4444: "metasploit",
    5000: "http-alt", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 6379: "redis", 6443: "kube-apiserver",
    8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 9000: "http-alt", 9200: "elasticsearch",
    11211: "memcached",
}

# -------------------- Helpers --------------------
def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a)
            end = int(b)
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

def expand_targets(targets: List[str]) -> List[str]:
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        # Range form like 192.168.1.10-20
        if "-" in t and "/" not in t:
            try:
                base, rng = t.rsplit(".", 1)
                start, end = rng.split("-", 1)
                start, end = int(start), int(end)
                for last in range(start, end + 1):
                    out.append(f"{base}.{last}")
                continue
            except Exception:
                pass
        # CIDR or single IP/hostname
        try:
            net = ipaddress.ip_network(t, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                out.extend(str(ip) for ip in net.hosts())
                continue
        except Exception:
            pass
        out.append(t)
    # Deduplicate, preserve order
    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

async def resolve_host(host: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        res = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if res:
            return res[0][4][0]
    except Exception:
        return None
    return None

def service_name(port: int) -> str:
    return SERVICE_HINTS.get(port) or ""

# -------------------- Host discovery --------------------
def icmp_ping_once(dst: str, timeout: float = 1.0) -> Optional[float]:
    if not SCAPY_AVAILABLE:
        return None
    ts = time.time()
    try:
        pkt = IP(dst=dst)/ICMP()
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is not None:
            return time.time() - ts
    except PermissionError:
        return None
    except Exception:
        return None
    return None

async def tcp_ping(host: str, ports=(80, 443), timeout: float = 0.5) -> Optional[float]:
    start = time.time()
    for p in ports:
        try:
            await asyncio.wait_for(asyncio.open_connection(host, p), timeout=timeout)
            return time.time() - start
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Connection refused also means host is up
            return time.time() - start
    return None

async def discover_hosts(target_ips: List[str], timing: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    results = {}
    sem = asyncio.Semaphore(timing["conn_limit"])

    async def probe(ip):
        async with sem:
            rtt = None
            # Prefer ICMP if available
            if SCAPY_AVAILABLE:
                rtt = await asyncio.to_thread(icmp_ping_once, ip, max(0.2, timing["timeout"]/2))
            if rtt is None:
                rtt = await tcp_ping(ip, timeout=max(0.2, timing["timeout"]/2))
            if rtt is not None:
                results[ip] = {"up": True, "rtt": rtt}
            else:
                results[ip] = {"up": False, "rtt": None}
            await asyncio.sleep(timing["delay"])

    await asyncio.gather(*(probe(ip) for ip in target_ips))
    return results

# -------------------- Scans --------------------
async def tcp_connect_scan(host: str, ports: List[int], timing: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    res: Dict[int, Dict[str, Any]] = {}
    sem = asyncio.Semaphore(timing["conn_limit"])

    async def check_port(p: int):
        state = "filtered"
        reason = "timeout"
        start = time.time()
        try:
            fut = asyncio.open_connection(host, p)
            reader, writer = await asyncio.wait_for(fut, timeout=timing["timeout"])
            state = "open"
            reason = "syn-ack"
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        except asyncio.TimeoutError:
            state = "filtered"
            reason = "no-response"
        except ConnectionRefusedError:
            state = "closed"
            reason = "conn-refused"
        except OSError as e:
            # Network unreachable, host unreachable, etc.
            state = "filtered"
            reason = f"oserror:{e.errno}"
        res[p] = {"state": state, "reason": reason, "proto": "tcp", "service": service_name(p), "banner": None, "ttl": None, "win": None, "product": None}
        await asyncio.sleep(timing["delay"])

    await asyncio.gather(*(
        (asyncio.create_task(check_port(p)) if await sem.acquire() or True else None)
        for p in ports
    ))
    return res

def syn_probe_once(dst: str, dport: int, timeout: float) -> Tuple[str, Optional[int], Optional[int]]:
    """
    Returns (state, ttl, window)
    """
    if not SCAPY_AVAILABLE:
        return ("unknown", None, None)
    try:
        pkt = IP(dst=dst)/TCP(dport=dport, flags="S")
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is None:
            return ("filtered", None, None)
        if ans.haslayer(TCP):
            tcp = ans.getlayer(TCP)
            ttl = ans.ttl if hasattr(ans, "ttl") else None
            win = tcp.window
            if tcp.flags & 0x12 == 0x12:  # SYN-ACK
                # send RST to be polite
                with contextlib.suppress(Exception):
                    sr(IP(dst=dst)/TCP(dport=dport, flags="R"), timeout=0.2, verbose=0)
                return ("open", ttl, win)
            if tcp.flags & 0x14 == 0x14:  # RST-ACK
                return ("closed", ttl, win)
        # ICMP unreachable or others considered filtered
        return ("filtered", None, None)
    except PermissionError:
        return ("unknown", None, None)
    except Exception:
        return ("unknown", None, None)

async def tcp_syn_scan(host: str, ports: List[int], timing: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    res: Dict[int, Dict[str, Any]] = {}
    if not SCAPY_AVAILABLE:
        # Fallback to connect scan
        return await tcp_connect_scan(host, ports, timing)

    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(timing["conn_limit"])

    async def syn_port(p: int):
        async with sem:
            state, ttl, win = await loop.run_in_executor(None, syn_probe_once, host, p, timing["timeout"])
            res[p] = {"state": state, "reason": "syn" if state != "unknown" else "no-raw", "proto": "tcp",
                      "service": service_name(p), "banner": None, "ttl": ttl, "win": win, "product": None}
            await asyncio.sleep(timing["delay"])

    await asyncio.gather(*(syn_port(p) for p in ports))
    return res

def udp_probe_once(host: str, port: int, timeout: float) -> Tuple[str, Optional[bytes]]:
    """
    Best-effort UDP probe:
      - For known ports, send small protocol-appropriate payload
      - If UDP response arrives -> open
      - If timeout -> open|filtered
    """
    payloads = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
        123: struct.pack("!BBBb11I", 0x23, 0, 0, 0, *([0]*11)),  # NTP minimal
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    }
    data = payloads.get(port, b"")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setblocking(False)
            s.settimeout(timeout)
            s.sendto(data, (host, port))
            # Try to receive a UDP reply
            try:
                resp, _ = s.recvfrom(2048)
                return ("open", resp)
            except socket.timeout:
                return ("open|filtered", None)
            except Exception:
                return ("open|filtered", None)
    except PermissionError:
        return ("open|filtered", None)
    except Exception:
        return ("open|filtered", None)

async def udp_scan(host: str, ports: List[int], timing: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    res: Dict[int, Dict[str, Any]] = {}
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(min(256, timing["conn_limit"]))  # keep UDP sane

    async def do_port(p: int):
        async with sem:
            state, resp = await loop.run_in_executor(None, udp_probe_once, host, p, timing["udp_timeout"])
            res[p] = {"state": state, "reason": "udp-probe", "proto": "udp",
                      "service": service_name(p), "banner": None, "ttl": None, "win": None, "product": None}
            await asyncio.sleep(timing["delay"])

    await asyncio.gather(*(do_port(p) for p in ports))
    return res

# -------------------- Version detection --------------------
async def banner_grab(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None

    # Protocol-specific quick probes
    probe = None
    if port in (80, 8080, 8000, 8081, 8888):
        probe = b"HEAD / HTTP/1.0\r\nHost: %b\r\nUser-Agent: mini-nmap\r\n\r\n" % host.encode()
    elif port == 443:
        # Avoid full TLS; just attempt to read if any banner is sent (unlikely)
        probe = None
    elif port == 22:
        # SSH sends banner first
        probe = None
    elif port in (21, 25, 110, 143, 587, 993, 995):
        # These often greet
        probe = None
    elif port == 6379:
        probe = b"INFO\r\n"
    elif port == 27017:
        # Legacy Mongo handshake would be more complex; skip
        probe = None

    banner = b""
    try:
        if probe:
            writer.write(probe)
            await writer.drain()
        with contextlib.suppress(Exception):
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    try:
        return banner.decode("utf-8", errors="replace").strip() if banner else None
    except Exception:
        return None

async def version_detect(host: str, port_states: Dict[int, Dict[str, Any]], timing: Dict[str, Any]):
    tasks = []
    for p, info in port_states.items():
        if info["proto"] == "tcp" and info["state"] == "open":
            tasks.append((p, asyncio.create_task(banner_grab(host, p, timing["timeout"]))))
    for p, t in tasks:
        banner = await t
        if banner:
            port_states[p]["banner"] = banner
            # Very naive product inference
            b = banner.lower()
            if "openssh" in b:
                port_states[p]["product"] = "OpenSSH"
            elif "nginx" in b:
                port_states[p]["product"] = "nginx"
            elif "apache" in b or "httpd" in b:
                port_states[p]["product"] = "Apache httpd"
            elif "redis" in b:
                port_states[p]["product"] = "Redis"
            elif "postgresql" in b:
                port_states[p]["product"] = "PostgreSQL"
            elif "mysql" in b:
                port_states[p]["product"] = "MySQL"

# -------------------- OS Guess (heuristic) --------------------
def os_guess_from_ttl_win(ttls: List[int], wins: List[int]) -> Optional[str]:
    if not ttls:
        return None
    ttl = max(set(ttls), key=ttls.count)
    # Map TTL to OS family guess
    if ttl >= 200:
        base = "Cisco/Network device"
    elif ttl >= 120:
        base = "Windows"
    elif ttl >= 60:
        base = "Linux/Unix/macOS"
    else:
        base = "Unknown"
    if wins:
        w = max(set(wins), key=wins.count)
        # Add hints
        if base.startswith("Windows") and w in (8192, 65535, 64240, 65535):
            base += " (likely)"
        elif "Linux" in base and w in (29200, 5840, 14600, 29200, 64240, 65535):
            base += " (likely)"
    return base

# -------------------- Traceroute --------------------
def do_traceroute(host: str, maxttl: int = 30, dport: int = 33434, timeout: float = 2.0) -> List[Tuple[int, str, Optional[float]]]:
    hops = []
    if not SCAPY_AVAILABLE:
        return hops
    try:
        res, _ = scapy_traceroute(host, maxttl=maxttl, dport=dport, timeout=timeout, verbose=0)
        for snd, rcv in res:
            ttl = snd.ttl
            ip = rcv.src
            rtt = (rcv.time - snd.sent_time) if hasattr(snd, "sent_time") and hasattr(rcv, "time") else None
            hops.append((ttl, ip, rtt))
        hops.sort(key=lambda x: x[0])
    except Exception:
        pass
    return hops

# -------------------- Reporting --------------------
def print_text_report(scan: Dict[str, Any], out):
    out.write(f"Starting mini-nmap at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    for host, hres in scan["hosts"].items():
        status = "up" if hres["up"] else "down"
        rtt_ms = f"{int(hres['rtt']*1000)}ms" if hres["rtt"] else "n/a"
        out.write(f"Nmap scan report for {host}\n")
        out.write(f"Host is {status} ({rtt_ms} latency).\n")
        ports = hres.get("ports", {})
        if ports:
            out.write("PORT     STATE         SERVICE        VERSION/BANNER\n")
            for p in sorted(ports.keys()):
                info = ports[p]
                portstr = f"{p}/{info['proto']}"
                state = info["state"]
                svc = (info["service"] or "").ljust(14)
                banner = info.get("banner") or ""
                out.write(f"{portstr:<8} {state:<13} {svc:<14} {banner[:80]}\n")
        if hres.get("os_guess"):
            out.write(f"OS guess: {hres['os_guess']}\n")
        if hres.get("trace"):
            out.write("Traceroute:\n")
            for ttl, ip, rtt in hres["trace"]:
                r = f"{int(rtt*1000)}ms" if rtt else "n/a"
                out.write(f"  {ttl:>2}  {ip:<15}  {r}\n")
        out.write("\n")

def write_outputs(scan: Dict[str, Any], oN: Optional[str], oJ: Optional[str]):
    if oN:
        with open(oN, "w", encoding="utf-8") as f:
            print_text_report(scan, f)
    if oJ:
        with open(oJ, "w", encoding="utf-8") as f:
            json.dump(scan, f, indent=2)

# -------------------- Main scanning flow --------------------
async def scan_host(host: str, args, timing) -> Dict[str, Any]:
    host_result: Dict[str, Any] = {"up": True, "rtt": None, "ports": {}, "os_guess": None, "trace": None}

    # Port selection
    ports = parse_ports(args.ports) if args.ports else [22, 80, 443]
    random.shuffle(ports)  # avoid easy IDS signatures

    # Choose TCP scan mode
    tcp_scan = None
    if args.sS:
        tcp_scan = tcp_syn_scan
    elif args.sT or (not args.sS and not args.sU):
        tcp_scan = tcp_connect_scan

    # TCP scan
    tcp_states = {}
    if tcp_scan:
        tcp_ports = [p for p in ports if p >= 1 and p <= 65535]
        tcp_states = await tcp_scan(host, tcp_ports, timing)

    # UDP scan
    udp_states = {}
    if args.sU:
        udp_ports = [p for p in ports if p >= 1 and p <= 65535]
        udp_states = await udp_scan(host, udp_ports, timing)

    # Merge results
    merged: Dict[int, Dict[str, Any]] = {}
    for p, info in {**tcp_states, **udp_states}.items():
        merged[p] = info

    # Version detection
    if args.sV and tcp_scan:
        await version_detect(host, merged, timing)

    # OS guess using TTL/window stats from SYN results
    if args.O and SCAPY_AVAILABLE and merged:
        ttls = [v["ttl"] for v in merged.values() if v["ttl"]]
        wins = [v["win"] for v in merged.values() if v["win"]]
        host_result["os_guess"] = os_guess_from_ttl_win(ttls, wins)

    # Traceroute
    if args.traceroute:
        host_result["trace"] = do_traceroute(host)

    host_result["ports"] = merged
    return host_result

async def main_async(args):
    # Timing
    tprof = max(0, min(5, args.T))
    timing = TIMING_PROFILES[tprof]
    if args.min_rate:
        timing["conn_limit"] = max(timing["conn_limit"], args.min_rate)

    # Expand and resolve targets
    targets = expand_targets(args.targets)
    resolved = []
    for t in targets:
        if all(c.isdigit() or c == "." for c in t):
            resolved.append(t)
            continue
        ip = await resolve_host(t)
        if ip:
            resolved.append(ip)
        else:
            print(f"Warning: could not resolve {t}", file=sys.stderr)

    if not resolved:
        print("No valid targets.", file=sys.stderr)
        return

    # Host discovery
    hosts_info = {}
    if args.Pn:
        for ip in resolved:
            hosts_info[ip] = {"up": True, "rtt": None}
    else:
        hosts_info = await discover_hosts(resolved, timing)

    scan: Dict[str, Any] = {"started": time.time(), "args": vars(args), "hosts": {}}

    if args.sn:
        # Ping scan only
        for ip, info in hosts_info.items():
            scan["hosts"][ip] = {"up": info["up"], "rtt": info["rtt"], "ports": {}}
        print_text_report(scan, sys.stdout)
        write_outputs(scan, args.oN, args.oJ)
        return

    # Full scan on alive hosts
    alive = [ip for ip, info in hosts_info.items() if info["up"]]
    if not alive:
        print("No hosts are up (or blocked by discovery). Use -Pn to skip discovery.", file=sys.stderr)
        return

    sem = asyncio.Semaphore(8)  # limit concurrent hosts

    async def scan_one(ip):
        async with sem:
            hres = await scan_host(ip, args, timing)
            # carry discovery rtt
            hres["rtt"] = hosts_info[ip].get("rtt")
            scan["hosts"][ip] = hres

    await asyncio.gather(*(scan_one(ip) for ip in alive))

    # Output
    print_text_report(scan, sys.stdout)
    write_outputs(scan, args.oN, args.oJ)

def parse_args():
    p = argparse.ArgumentParser(description="mini-nmap: a Python network scanner inspired by nmap")
    p.add_argument("targets", nargs="+", help="Targets: IPs, hostnames, CIDR, or range like 192.168.1.10-20")
    p.add_argument("-p", "--ports", help="Port spec, e.g., 22,80,443 or 1-1024")
    # Scan types
    p.add_argument("-sT", action="store_true", help="TCP connect scan")
    p.add_argument("-sS", action="store_true", help="TCP SYN scan (requires scapy + root)")
    p.add_argument("-sU", action="store_true", help="UDP scan")
    # Discovery
    p.add_argument("-sn", action="store_true", help="Ping scan (host discovery only)")
    p.add_argument("-Pn", action="store_true", help="Treat all hosts as online (skip discovery)")
    # Extras
    p.add_argument("-sV", action="store_true", help="Version detection (banner grab)")
    p.add_argument("-O", action="store_true", help="OS guess (heuristic; scapy only)")
    p.add_argument("--traceroute", action="store_true", help="Run traceroute (scapy)")
    # Timing/output
    p.add_argument("-T", type=int, default=3, help="Timing template 0-5 (default 3)")
    p.add_argument("--min-rate", type=int, default=0, help="Minimum parallel connections")
    p.add_argument("-oN", help="Normal text output filename")
    p.add_argument("-oJ", help="JSON output filename")
    return p.parse_args()

def main():
    # Warn about scapy missing if needed
    args = parse_args()
    if (args.sS or args.O or args.traceroute) and not SCAPY_AVAILABLE:
        print("Note: scapy not available. Install with: pip install scapy", file=sys.stderr)
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)

if __name__ == "__main__":
    main()
