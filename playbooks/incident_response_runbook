# Incident Response Runbook: Endpoint Compromise & Anti-Forensics Activity

## 1. Identification & Initial Triage
* **Detection Triggers:** Process creation alerts for dual-use security tools (`bettercap.exe`, `nmap.exe`, `sdelete.exe`) or anomalous outbound network traffic via plain-text protocols (e.g., FTP).
* **Volatile Data Acquisition:** Prior to disconnecting the host, capture RAM and active network sockets via Live Response or remote triage tools.
* **Non-Volatile Preservation:** Create a targeted forensic logical triage image (`.ad1` via FTK Imager or triage packages via KAPE) capturing Prefetch, Registry hives (`SOFTWARE`, `SYSTEM`, `NTUSER.DAT`), and event logs (`Security.evtx`).

## 2. Containment
* **Network Isolation:** Apply immediate endpoint isolation via EDR or sever the physical/virtual network interface.
* **Perimeter Dropping:** Enforce firewall rules to block inbound and outbound traffic to identified internal/external staging hosts (`192.168.1.20:21`).

## 3. Evidence Collection & Deep Triage
* **Evidence of Execution:** Parse Prefetch files using `PECmd` to confirm whether target binaries executed, extract execution frequency (`RunCount`), and identify last run timestamps in UTC.
* **Persistence Inspection:** Analyze `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` keys using `Registry Explorer` to identify auto-start entries or deleted values (`LastServiceStart`).
* **Lateral Staging:** Review third-party application configurations (e.g., FileZilla `recentservers.xml`) for unauthorized remote IP addresses and session credentials.

## 4. Eradication & Remediation
* **Credential Rotation:** Invalidate all local, domain, and service account credentials that authenticated on the endpoint during the compromise window.
* **Host Sanitization:** Because anti-forensic utilities (`sdelete.exe`) were executed to overwrite evidence, clean wiping cannot be fully verified. Re-image the workstation completely from a known-good baseline image.

## 5. Post-Incident Review & Hardening
* Document all confirmed Indicators of Compromise (IoCs).
* Deploy process creation detection rules (Sigma/YARA) across the SOC monitoring pipeline to detect subsequent attempts.
