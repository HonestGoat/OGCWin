@echo off
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command ^
"Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoExit -ExecutionPolicy Bypass -NoProfile -File \"C:\ProgramData\OGC Windows Utility\launch.ps1\"' -WindowStyle Normal"
exit
