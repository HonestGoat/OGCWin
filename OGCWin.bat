@echo off
C:\Program Files\PowerShell\7\pwsh.exe -ExecutionPolicy Bypass -Command ^
"Start-Process pwsh.exe -Verb RunAs -ArgumentList '-NoExit -ExecutionPolicy Bypass -NoProfile -File \"C:\ProgramData\OGC Windows Utility\scripts\OGCMode.ps1\"' -WindowStyle Normal"
exit
