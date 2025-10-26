# DNS Spoofing Detection using Packet Monitoring Tool

## Overview
This mini project implements a network packet monitoring tool to detect DNS spoofing attacks. DNS spoofing (or DNS cache poisoning) occurs when an attacker redirects DNS queries to malicious servers, potentially leading to phishing or data theft. The tool:

- **Captures** DNS packets (queries and responses) on a specified network interface.
- **Logs** all DNS activity to a file for analysis.
- **Detects anomalies**:
  - Responses from untrusted DNS servers (not in a predefined list of public resolvers).
  - Multiple responses for the same query within a short time (indicative of poisoning attempts).

Built with Python and Scapy for low-level packet handling. Suitable for educational purposes and basic network security monitoring.

## Features
- Real-time packet sniffing with UDP port 53 filter (standard DNS).
- Configurable trusted DNS servers.
- Query-response matching using DNS transaction IDs.
- Alert logging for suspicious activity.
- Command-line interface for easy use.

## Prerequisites
- **OS**: Linux/macOS (Windows requires Npcap for Scapy).
- **Python**: 3.8+.
- **Admin Privileges**: Run with `sudo` for raw socket access.
- **Network Interface**: Know your interface (e.g., `ifconfig` or `ip link` to list).

## Installation
1. Clone or create the repo:
