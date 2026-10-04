@echo off
REM ============================================================================
REM Incident Response Triage Script: Artifact Extraction
REM Purpose: Automates the collection of critical Windows host artifacts 
REM          for DFIR analysis (Prefetch, Registry Hives, Event Logs, and Network Data).
REM ============================================================================

set OUTPUT_DIR=C:\ForensicsLab\Triage_Extracted
echo [*] Initializing Host Artifact Extraction...
echo [*] Target Directory: %OUTPUT_DIR%

REM Create output directories
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OUTPUT_DIR%\Prefetch" mkdir "%OUTPUT_DIR%\Prefetch"
if not exist "%OUTPUT_DIR%\Registry" mkdir "%OUTPUT_DIR%\Registry"
if not exist "%OUTPUT_DIR%\EventLogs" mkdir "%OUTPUT_DIR%\EventLogs"
if not exist "%OUTPUT_DIR%\Network" mkdir "%OUTPUT_DIR%\Network"

REM 1. Collect Volatile Network State
echo [+] Collecting active network connections and routing tables...
netstat -ano > "%OUTPUT_DIR%\Network\netstat_ano.txt"
ipconfig /all > "%OUTPUT_DIR%\Network\ipconfig_all.txt"
arp -a > "%OUTPUT_DIR%\Network\arp_cache.txt"

REM 2. Collect Evidence of Execution (Windows Prefetch)
echo [+] Preserving Windows Prefetch files (.pf)...
robocopy "%SystemRoot%\Prefetch" "%OUTPUT_DIR%\Prefetch" *.pf /R:1 /W:1 /NJH /NJS /NDL /NC /NS

REM 3. Collect System Registry Hives
echo [+] Extracting system hives using Windows built-in reg tool...
reg save HKLM\SYSTEM "%OUTPUT_DIR%\Registry\SYSTEM.hiv" /y >nul 2>&1
reg save HKLM\SOFTWARE "%OUTPUT_DIR%\Registry\SOFTWARE.hiv" /y >nul 2>&1

REM 4. Collect Security & System Event Logs
echo [+] Preserving Security and System Windows Event Logs (.evtx)...
copy /Y "%SystemRoot%\System32\winevt\Logs\Security.evtx" "%OUTPUT_DIR%\EventLogs\" >nul 2>&1
copy /Y "%SystemRoot%\System32\winevt\Logs\System.evtx" "%OUTPUT_DIR%\EventLogs\" >nul 2>&1

echo [*] Artifact extraction completed successfully.
echo [*] Review collected files under: %OUTPUT_DIR%
pause
