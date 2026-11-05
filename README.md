# 🛡️ Automated Linux System Hardening & NIST SP 800-53 Compliance Engine

[![Bash](https://img.shields.io/badge/Script-Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)]()
[![Python](https://img.shields.io/badge/Parser-Python_3-3776AB?style=flat&logo=python&logoColor=white)]()
[![Compliance](https://img.shields.io/badge/Compliance-NIST_SP_800--53-blue?style=flat)]()
[![Platform](https://img.shields.io/badge/OS-Ubuntu%20%7C%20Kali%20%7C%20Debian-orange?style=flat&logo=linux)]()

A hybrid DevSecOps automation utility designed to bridge the gap between a vulnerable, out-of-the-box Linux installation and an enterprise-secured server. In a single execution, this engine audits system configurations, dynamically remediates vulnerabilities, deploys an anti-brute-force firewall, and generates a formal, timestamped compliance report mapped to the **NIST SP 800-53 Rev. 5** framework.

---

## 📖 Overview

Default Linux distributions prioritize usability over strict security, often leaving systems exposed to automated botnet scanning, SSH credential stuffing, and local privilege escalation. This tool was built for:
*   **DevSecOps Pipeline Integration:** Hardening "Golden Images" from boot.
*   **Regulatory Audits:** Generating cryptographic, timestamped proof of compliance (e.g., PCI-DSS, ISO 27001).
*   **Active Incident Response:** Rapidly containing active network attacks and throttling unauthorized access attempts without taking the server offline.

---

## ✨ Key Features

*   **Idempotent Execution & Safety:** Automatically creates timestamped backups in `/var/backups` before applying any modifications. Safe to run continuously.
*   **Kernel Lockdown (`sysctl`):** Enables TCP SYN cookies, disables IPv4 forwarding, blocks ICMP redirects, and enforces memory ASLR.
*   **Identity & Access Control:** Retroactively enforces 90-day password expiration, 12-character PAM complexity, and disables rogue `UID 0` (root) accounts.
*   **Aggressive File Auditing:** Detects and automatically remediates dangerous world-writable (`0777`) files in `/home` and `/tmp`.
*   **Stateful Boundary Protection:** Configures UFW in a default-deny posture, blocks legacy protocols (FTP, Telnet, SMB), and throttles SSH connections to stop brute-forcing.
*   **Dual-Format Reporting:** Outputs a highly structured, human-readable Text Report and a machine-readable JSON artifact for SIEM integration.

---

## 🏗️ Architecture

The tool is divided into two decoupled components:
1.  **`harden_engine.sh` (The Actuator):** A low-level Bash script that interacts with the kernel, file system, and system daemons. It remediates the vulnerabilities and streams the audited state into a raw CSV pipeline.
2.  **`nist_reporter.py` (The Analyzer):** A Python script operating strictly on the Standard Library (no `pip` installs required). It parses the raw execution stream, queries live network sockets, and generates the final compliance metrics and artifacts.

---

## 🚀 Installation & Usage

### 1. Prerequisites
Ensure the target system has the necessary base utilities installed. This project relies entirely on native Linux tools to avoid third-party agent overhead.
```bash
sudo apt update
sudo apt install -y python3 libpam-pwquality openssh-server ufw iproute2 procps gawk grep sed coreutils
