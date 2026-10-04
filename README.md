# Windows Endpoint Forensics & Threat Hunting Lab (Case: AfricanFalls)

## Executive Summary
A host-based Digital Forensics and Incident Response (DFIR) and Threat Hunting investigation was conducted on a logical forensic image (`.ad1`) acquired from a compromised Windows workstation. The investigation confirmed a multi-stage intrusion involving local network reconnaissance, credential sniffing, encrypted staging, external file transfer setup, and intentional anti-forensic wiping before acquisition.

---

## Threat Hunting Hypotheses
* **Hypothesis 1 (Execution of Non-Standard Binaries):** Adversaries often execute dual-use security tools and portable payloads from user-writable directories (`%Temp%`, `Downloads`, or `AppData`).
* **Hypothesis 2 (Anti-Forensic Activity):** Prior to containment or extraction, attackers leverage file wiping utilities to hinder forensic recovery and timelining.
* **Hypothesis 3 (Alternative Protocol Exfiltration):** Suspected exfiltration attempts utilizing plain-text or alternative network protocols (e.g., FTP) from installed third-party utilities.

---

## Technical Findings & Artifact Analysis

### 1. Evidence of Execution (PECmd / Windows Prefetch)
Parsing the extracted Windows Prefetch artifacts with **PECmd** confirmed the execution of unauthorized assessment and evasion tooling:

| Executable Name | Run Count | Last Run Timestamp (UTC) | Tactic / Threat Hunting Context |
| :--- | :---: | :--- | :--- |
| `BETTERCAP.EXE` | 7 | 2021-04-28 17:24:05 | **Credential Access**: Man-in-the-Middle and packet sniffing framework |
| `NMAP.EXE` | 3 | 2021-04-28 17:37:54 | **Discovery**: Active subnet discovery and port scanning |
| `WIRESHARK.EXE` / `DUMPCAP.EXE` | 1 / 8 | 2021-04-28 17:39:31 | **Collection**: Network packet capture and inspection |
| `IPSCAN.EXE` | 3 | 2021-04-29 16:28:12 | **Discovery**: Lightweight IP range sweeping |
| `TORBROWSER-INSTALL...EXE` | 1 | 2021-04-29 18:22:32 | **Defense Evasion / C2**: Anonymous communication channel setup |
| `QUICKCRYPTO.EXE` | 5 | 2021-04-30 00:28:40 | **Collection / Impact**: File encryption and steganographic data staging |
| `BURPSUITECOMMUNITY.EXE` | 1 | 2021-04-30 00:40:45 | **Discovery**: Web application testing and proxy interception |
| `SDELETE.EXE` / `SDELETE64.EXE` | 4 / 1 | 2021-04-30 01:08:06 | **Defense Evasion (Anti-Forensics)**: Secure file shredding to prevent recovery |

![Evidence of Execution]

---

### 2. Host Persistence & Registry Triage (Registry Explorer)
Analysis of the `SOFTWARE` registry hive (`Microsoft\Windows\CurrentVersion\Run`) demonstrated that active auto-start mechanisms were absent. However, an invalidated entry (`LastServiceStart`) marked with an **Is Deleted** flag was identified with a last modification timestamp of `2021-04-30 00:58:47 UTC`. This timeline correlates directly with the execution window of anti-forensic wiping tools on the host.

![Registry Analysis]

---

### 3. Exfiltration Infrastructure (FileZilla Configuration Triage)
Inspection of `recentservers.xml` extracted from the target host uncovered an active outbound connection profile:
* **Target Host:** `192.168.1.20`
* **Port:** `21` (FTP)
* **Authenticated Account:** `kali`
* **Logon Type:** Standard interactive authentication (`2`)

This confirms lateral or external data staging directed toward an adversary-controlled Linux workstation on the local network segment.

![FileZilla Evidence]

---

### 4. Forensic Timelining & Reconstruction (Autopsy)
Utilizing **Autopsy**, system activity was synthesized across browser history, downloaded payloads, and execution logs:
1. **Initial Tool Staging (2021-04-28):** Ingestion and installation of WinPcap/Npcap drivers followed by port scanners (`Nmap`) and MitM tooling (`Bettercap`).
2. **Reconnaissance & Evasion (2021-04-29):** Sweeps across the IP subnet, followed by Tor Browser installation.
3. **Encryption & Data Destruction (2021-04-30):** Deployment of `QuickCrypto`, subsequent FTP staging toward `192.168.1.20`, and execution of `SDelete` at `01:08:06 UTC` immediately prior to system shutdown and acquisition.

![Autopsy Timeline]

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Mapped Evidence |
| :--- | :--- | :--- | :--- |
| **Discovery** | T1046 | Network Service Discovery | `NMAP.EXE`, `IPSCAN.EXE` |
| **Credential Access** | T1040 | Network Sniffing | `BETTERCAP.EXE`, `WIRESHARK.EXE` |
| **Defense Evasion** | T1070.004 | File Deletion: Indicator Removal | `SDELETE.EXE`, `SDELETE64.EXE` |
| **Command & Control** | T1090.003 | Multi-hop Proxy: Tor | `TORBROWSER-INSTALL...EXE` |
| **Exfiltration** | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | `recentservers.xml` (`192.168.1.20:21`) |

---

## Indicators of Compromise (IoCs)
* **Adversary IP / Staging Server:** `192.168.1.20`
* **Outbound Service:** FTP (`TCP/21`)
* **Suspicious Binaries:** `bettercap.exe`, `sdelete.exe`, `sdelete64.exe`, `quickcrypto.exe`, `ipscan.exe`
* **Compromised Account Handle:** `kali`

---

## Containment & Remediation Recommendations
1. **Network Containment:** Isolate the endpoint from the broadcast domain and enforce perimeter firewall drops for all traffic to/from `192.168.1.20`.
2. **Credential Revocation:** Immediately invalidate all credentials stored or cached on the endpoint, including domain service credentials and FTP access keys.
3. **Host Reimaging:** Due to verified evidence wiping (`sdelete.exe`), the operating system state cannot be certified secure through conventional antivirus cleaning. Rebuild the system from a verified golden image.
