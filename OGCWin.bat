@echo off
title OGCWin Mode Selector
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command ^
"Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoExit -ExecutionPolicy Bypass -NoProfile -File \"C:\ProgramData\OGC Windows Utility\scripts\OGCMode.ps1\"' -WindowStyle Normal"
exit
