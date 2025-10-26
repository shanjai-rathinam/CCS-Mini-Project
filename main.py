#!/usr/bin/env python3
"""
DNS Spoofing Detection Tool
Mini Project – CCS-Mini-Project
Author: [YOUR FULL NAME]
Roll No: [YOUR ROLL NUMBER]
"""

import sys
import os
import datetime
import argparse
from collections import defaultdict
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR

# ---------- CONFIGURATION ----------
TRUSTED_DNS_SERVERS = [
    '8.8.8.8', '8.8.4.4',           # Google
    '1.1.1.1', '1.0.0.1',           # Cloudflare
    '208.67.222.222', '208.67.220.220'  # OpenDNS
]

LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'dns_log.txt')
os.makedirs(LOG_DIR, exist_ok=True)

# Cache: query_id → list of timestamps (last 60 s)
query_cache = defaultdict(list)

# ---------- HELPERS ----------
def log_message(msg: str):
    ts = datetime.datetime.now().isoformat()
    line = f"[{ts}] {msg}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(line)
    print(line.rstrip())

def handle_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == 53):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # ----- QUERY -----
    if pkt.haslayer(DNSQR):
        dns = pkt[DNS]
        qid = dns.id
        domain = dns.qd.qname.decode().rstrip('.')
        log_message(f"QUERY: {domain} (ID: {qid}) from {src_ip} to {dst_ip}")
        query_cache[qid].append(datetime.datetime.now().timestamp())
        return

    # ----- RESPONSE -----
    if pkt.haslayer(DNSRR):
        dns = pkt[DNS]
        qid = dns.id
        domain = dns.qd.qname.decode().rstrip('.') if dns.qd else "?"
        answer_ip = dns.an.rdata if dns.an else "?"
        if isinstance(answer_ip, bytes):
            answer_ip = '.'.join(str(b) for b in answer_ip)

        log_message(f"RESPONSE: {domain} -> {answer_ip} (ID: {qid}) from {src_ip} to {dst_ip}")

        # 1. Untrusted server
        if src_ip not in TRUSTED_DNS_SERVERS:
            alert = f"POTENTIAL SPOOFING: Response from untrusted server {src_ip} for {domain}"
            log_message(alert)

        # 2. Cache-poisoning (multiple answers in short window)
        now = datetime.datetime.now().timestamp()
        recent = [t for t in query_cache[qid] if now - t < 10]
        if len(recent) > 1:
            alert = f"POTENTIAL CACHE POISONING: {len(recent)} responses for ID {qid} ({domain})"
            log_message(alert)

        # Clean old cache entries
        query_cache[qid] = [t for t in query_cache[qid] if now - t < 60]

# ---------- MAIN ----------
def main(interface: str = None, duration: int = None):
    if interface is None:
        interface = 'eth0'   # change if needed (wlan0, en0, …)

    log_message("=== DNS Spoofing Detector STARTED ===")
    log_message(f"Interface: {interface}")
    log_message(f"Duration : {duration or 'indefinite'} seconds")
    log_message(f"Trusted   : {', '.join(TRUSTED_DNS_SERVERS)}")

    try:
        sniff(
            iface=interface,
            filter="udp port 53",
            prn=handle_packet,
            timeout=duration,
            store=False
        )
    except KeyboardInterrupt:
        log_message("=== STOPPED by user ===")
    except Exception as e:
        log_message(f"ERROR: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Spoofing Detector")
    parser.add_argument("interface", nargs="?", help="Network interface (e.g. eth0)")
    parser.add_argument("duration", nargs="?", type=int, help="Seconds to run")
    args = parser.parse_args()
    main(args.interface, args.duration)
