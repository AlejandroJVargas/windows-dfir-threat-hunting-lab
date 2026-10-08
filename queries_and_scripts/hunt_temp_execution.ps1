<#
.SYNOPSIS
    Threat Hunting script to parse and detect suspicious execution from PECmd CSV outputs.
#>
param (
    [string]$CsvPath = "C:\ForensicsLab\Prefetch_Parsed\*_PECmd_Output.csv"
)

$SuspiciousPatterns = "SDELETE|BETTERCAP|QUICKCRYPTO|TORBROWSER|BURP|NMAP|IPSCAN"

Import-Csv -Path (Resolve-Path $CsvPath) | 
    Where-Object { $_.ExecutableName -match $SuspiciousPatterns } | 
    Select-Object ExecutableName, RunCount, LastRun, SourceFilename | 
    Sort-Object LastRun -Descending | 
    Format-Table -AutoSize
