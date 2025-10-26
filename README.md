# DNS Spoofing Detection using Packet Monitoring Tool

**Mini Project for College Assignment**  
**Author:** [Your Name]  
**Date:** October 2025  
**GitHub:** `https://github.com/your-username/dns-spoofing-detector`

---

## Overview

This project implements a **real-time DNS Spoofing Detection Tool** using **packet monitoring** with **Scapy** in Python. It sniffs DNS traffic on a specified network interface, logs queries and responses, and detects potential **DNS spoofing (cache poisoning)** attacks by identifying:

- Responses from **untrusted DNS servers**
- **Multiple responses** for the same query (indicative of poisoning attempts)

Perfect for educational purposes and network security awareness.

---

## Features

| Feature | Description |
|-------|-------------|
| **Live Packet Sniffing** | Captures DNS packets (UDP port 53) in real time |
| **Query-Response Logging** | Logs domain, IP, query ID, and timestamps |
| **Spoofing Detection** | Flags responses from non-public DNS servers |
| **Cache Poisoning Detection** | Alerts on duplicate responses for same query ID |
| **CLI Interface** | Easy to use with interface and duration options |
| **File Logging** | All activity saved to `logs/dns_log.txt` |

---

## How It Works

1. **Sniffing**: Uses Scapy to capture packets with filter `udp port 53`.
2. **Query Parsing**: Extracts domain name and transaction ID.
3. **Response Analysis**:
   - Checks if source IP is in **trusted list** (Google, Cloudflare, OpenDNS).
   - Matches response to recent queries using **DNS transaction ID**.
   - Flags **multiple responses** within 10 seconds → possible poisoning.
4. **Alerting**: Prints and logs **🚨 alerts** for suspicious activity.

---

## Prerequisites

- **OS**: Linux / macOS (Windows with Npcap)
- **Python**: 3.8 or higher
- **Root/Administrator**: Required for packet sniffing
- **Network Interface**: Know your interface name (`eth0`, `wlan0`, `en0`, etc.)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/dns-spoofing-detector.git
cd dns-spoofing-detector

# Install dependencies
pip install -r requirements.txt

# Create logs directory
mkdir logs
```

### `requirements.txt`
```txt
scapy==2.5.0
```

---

## Usage

> **Must run with `sudo`**

### 1. Monitor for 30 seconds on interface `eth0`
```bash
sudo python3 main.py eth0 30
```

### 2. Monitor indefinitely (stop with Ctrl+C)
```bash
sudo python3 main.py wlan0
```

### 3. Default (eth0, indefinite)
```bash
sudo python3 main.py
```

---

## Sample Output

```
[2025-10-26T10:15:30] === DNS Spoofing Detector Started ===
[2025-10-26T10:15:31] QUERY: google.com (ID: 4921) from 192.168.1.100 to 8.8.8.8
[2025-10-26T10:15:32] RESPONSE: google.com -> 142.250.190.78 (ID: 4921) from 8.8.8.8 to 192.168.1.100
[2025-10-26T10:15:35] 🚨 POTENTIAL SPOOFING: Response from untrusted server 192.168.1.50 for evil.com
[2025-10-26T10:15:36] 🚨 POTENTIAL CACHE POISONING: 2 responses for query ID 1234 (bank.com)
```

All logs saved to: `logs/dns_log.txt`

---

## Detection Logic

| Detection Type | Trigger |
|---------------|--------|
| **Untrusted Server** | Source IP not in trusted list |
| **Cache Poisoning** | >1 response for same query ID within 10 seconds |

### Trusted DNS Servers (Configurable)
```python
TRUSTED_DNS_SERVERS = [
    '8.8.8.8', '8.8.4.4',       # Google
    '1.1.1.1', '1.0.0.1',       # Cloudflare
    '208.67.222.222', '208.67.220.220'  # OpenDNS
]
```

---

## Project Structure

```
dns-spoofing-detector/
├── main.py              # Core detection script
├── requirements.txt     # Dependencies
├── README.md            # This file
├── logs/                # Auto-created
│   └── dns_log.txt      # Generated log
└── demo_output.txt      # Sample output
```

---

## Testing the Tool

1. **Normal DNS Query**:
   ```bash
   nslookup google.com
   ```
   → Should log query and trusted response.

2. **Simulate Spoofing (Local Test)**:
   - Run a rogue DNS server on your machine (e.g., using `dnsmasq` or `python -m http.server` with fake responses).
   - Query a domain → Tool should flag **untrusted server**.

3. **Cache Poisoning Simulation**:
   - Use `scapy` to send two fake responses for same query ID.

---

## Limitations

- Only detects **basic spoofing** (not DNSSEC-aware).
- Focuses on **IPv4 + A records**.
- No support for **DoH/DoT** (encrypted DNS).
- False positives possible on local/corporate networks.

---

## Future Enhancements

- Add **DNSSEC validation** using `dnspython`
- Support **DoH (DNS over HTTPS)** parsing
- Web dashboard with **Flask + live graphs**
- Machine learning for **anomaly detection**
- Export logs to **CSV/JSON**

---

## Code Highlights (`main.py`)

```python
# Key detection in handle_dns_packet()
if src_ip not in TRUSTED_DNS_SERVERS:
    alert_msg = f"🚨 POTENTIAL SPOOFING: Response from untrusted server {src_ip}"
    log_message(alert_msg)

# Cache poisoning detection
if recent_count > 1:
    log_message(f"🚨 POTENTIAL CACHE POISONING: {recent_count} responses for ID {query_id}")
```

---

## References

- Scapy Documentation: [https://scapy.readthedocs.io](https://scapy.readthedocs.io)
- DNS Spoofing: OWASP, RFC 5452
- Packet Analysis: *Practical Packet Analysis* by Chris Sanders

---

## License

```
MIT License - Free to use, modify, and distribute.
```

---

**Submitted for College Mini Project – Network Security**  
*“Detecting DNS attacks at the packet level using open-source tools.”*

---

**Ready to push to GitHub!**  
Just replace `[Your Name]` and `[your-username]`, commit, and deploy.  
Need a **PPT**, **demo video**, or **report**? Ask me!
