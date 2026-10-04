# Threat Hunting Hypothesis & Execution Matrix

## Overview
This document outlines threat hunting investigations targeting unflagged adversary activity across Windows endpoints, focusing on dual-use tools, anti-forensic techniques, and alternative protocol exfiltration.

---

## Hunt 1: Unauthorized Dual-Use Tool Execution

* **Hypothesis:** Adversaries execute unauthorized port scanners, sniffing tools, or penetration testing utilities from writable user paths (`%AppData%`, `%Temp%`, `Downloads`) to discover network assets without triggering standard antivirus alarms.
* **Technique Mapping:** MITRE ATT&CK T1046 (Network Service Discovery), T1040 (Network Sniffing).
* **Data Sources:** Windows Prefetch (`.pf`), Process Creation Events (Event ID 4688 / Sysmon Event ID 1).
* **Investigation Workflow:**
  1. Extract and parse Prefetch artifacts using `PECmd`.
  2. Query for anomalous binary names matching patterns: `NMAP`, `BETTERCAP`, `WIRESHARK`, `DUMPCAP`, `IPSCAN`.
  3. Validate `RunCount` and cross-reference timestamps with local operational change logs.
* **Hunt Finding:** Verified execution of `BETTERCAP.EXE` (7 runs), `NMAP.EXE` (3 runs), and `WIRESHARK.EXE` (1 run) during late April 2021.

---

## Hunt 2: Secure File Erasure (Anti-Forensics)

* **Hypothesis:** Attackers utilize command-line secure deletion utilities (e.g., Sysinternals SDelete) to overwrite staging files, scripts, and logs prior to disconnecting, hindering post-incident analysis.
* **Technique Mapping:** MITRE ATT&CK T1070.004 (Indicator Removal: File Deletion).
* **Data Sources:** Windows Prefetch (`.pf`), Command-line parameters, Registry MRU keys.
* **Investigation Workflow:**
  1. Filter Prefetch executions for `sdelete.exe` and `sdelete64.exe`.
  2. Correlate last run timestamps against system event drop-offs and system shutdown records.
  3. Verify whether target directories contain unallocated clusters with zeroed out/overwritten patterns.
* **Hunt Finding:** Confirmed execution of `SDELETE64.EXE` on `2021-04-29 20:45:12 UTC` and `SDELETE.EXE` on `2021-04-30 01:08:06 UTC`.

---

## Hunt 3: Lateral Transfer via Legacy / Plain-Text Protocols

* **Hypothesis:** Adversaries leverage installed FTP/SFTP clients to stage and exfiltrate internal reconnaissance output to local attacker-controlled infrastructure.
* **Technique Mapping:** MITRE ATT&CK T1048.003 (Exfiltration Over Alternative Protocol).
* **Data Sources:** Third-party application configs, network socket history, DNS cache.
* **Investigation Workflow:**
  1. Audit configuration files in `%AppData%` for installed transfer clients (e.g., `FileZilla\recentservers.xml`).
  2. Extract host, port, protocol, and username properties.
  3. Cross-reference destination IP addresses against enterprise asset management records.
* **Hunt Finding:** Identified outbound connection records in `recentservers.xml` targeting internal IP `192.168.1.20` over port `21` using user account `kali`.
