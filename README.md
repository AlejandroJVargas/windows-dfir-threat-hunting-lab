# Windows Endpoint Forensics & Threat Hunting Lab (Case: AfricanFalls)

## Executive Summary
Se llevó a cabo una investigación pericial de **Respuesta a Incidentes (DFIR)** y **Threat Hunting** sobre una imagen lógica (`.ad1`) de un endpoint Windows comprometido. El análisis confirmó actividades maliciosas multifásicas que abarcan reconocimiento de red, interceptación de tráfico local, configuración de canales de exfiltración y borrado seguro de evidencia pericial (*Anti-Forensics*).

---

## Technical Findings & Artifact Analysis

### 1. Evidence of Execution (PECmd & Prefetch)
El análisis forense de los artefactos de Windows Prefetch decodificados con **PECmd** demostró la ejecución comprobada de múltiples herramientas no autorizadas:

| Binary / Tool | Run Count | Last Run Timestamp (UTC) | Forensic Context |
| :--- | :---: | :--- | :--- |
| `BETTERCAP.EXE` | 7 | 2021-04-28 17:24:05 | Man-in-the-Middle y sniffing de red local |
| `NMAP.EXE` | 3 | 2021-04-28 17:37:54 | Escaneo activo de puertos y mapeo de subred |
| `WIRESHARK.EXE` / `DUMPCAP.EXE` | 1 / 8 | 2021-04-28 17:39:31 | Captura masiva de paquetes de red |
| `IPSCAN.EXE` | 3 | 2021-04-29 16:28:12 | Barrido de direcciones IP en el segmento |
| `TORBROWSER-INSTALL...EXE` | 1 | 2021-04-29 18:22:32 | Instalación de navegador anónimo (evasión perimetral) |
| `QUICKCRYPTO.EXE` | 5 | 2021-04-30 00:28:40 | Software de cifrado local y esteganografía |
| `BURPSUITECOMMUNITY.EXE` | 1 | 2021-04-30 00:40:45 | Interceptación de tráfico web local |
| `SDELETE.EXE` / `SDELETE64.EXE` | 4 / 1 | 2021-04-30 01:08:06 | Destrucción de evidencia pericial mediante sobrescritura |

![Evidence of Execution]

---

### 2. Persistence & Registry Analysis (Registry Explorer)
El análisis del hive `SOFTWARE` reveló modificaciones en las claves de arranque automático (`CurrentVersion\Run`), destacando una entrada eliminada (`LastServiceStart`) con timestamp pericial coincidente con la ventana del incidente (`2021-04-30 00:58:47 UTC`), indicativa de manipulación deliberada para ocultar rastros de persistencia.

![Registry Run Keys]

---

### 3. Exfiltration Infrastructure (FileZilla Artifacts)
La inspección pericial del archivo de configuración `recentservers.xml` de FileZilla expuso la infraestructura interna empleada para la transferencia de archivos:
* **Host Remoto:** `192.168.1.20`
* **Puerto:** `21` (FTP)
* **Usuario:** `kali`

![FileZilla Artifacts]

---

### 4. Forensic Timelining & Reconstruction (Autopsy)
Utilizando **Autopsy**, se reconstruyó la correlación temporal entre las descargas de utilidades ofensivas, la actividad de navegación y la secuencia final de destrucción de evidencia mediante `SDelete` previa a la toma de la imagen forense.

![Autopsy Timeline]

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Artifact Evidence |
| :--- | :--- | :--- | :--- |
| **Discovery** | T1046 | Network Service Discovery | `NMAP.EXE`, `IPSCAN.EXE` |
| **Credential Access** | T1040 | Network Sniffing | `BETTERCAP.EXE`, `WIRESHARK.EXE` |
| **Defense Evasion** | T1070.004 | File Deletion (Secure Overwrite) | `SDELETE.EXE`, `SDELETE64.EXE` |
| **Command & Control** | T1090.003 | Multi-hop Proxy (Tor) | `TORBROWSER-INSTALL...EXE` |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol (FTP) | `recentservers.xml` (`192.168.1.20:21`) |

---

## Indicators of Compromise (IoCs)
* **Host / Remote C2 IP:** `192.168.1.20`
* **Network Protocol:** FTP (`Port 21`)
* **Suspicious Binaries:** `sdelete.exe`, `sdelete64.exe`, `bettercap.exe`, `quickcrypto.exe`
* **Key User Account:** `kali`

---

## Containment & Remediation Actions
1. **Network Containment:** Aislar inmediatamente el host comprometido del segmento de red y bloquear el tráfico saliente/entrante hacia la IP `192.168.1.20`.
2. **Credential Invalidation:** Revocar y rotar todas las credenciales de servicio y cuentas de usuario que hayan iniciado sesión en el host.
3. **Eradication:** Reinstalar la estación de trabajo desde una imagen corporativa verificada debido al uso comprobado de utilidades de destrucción pericial (`SDelete`).
