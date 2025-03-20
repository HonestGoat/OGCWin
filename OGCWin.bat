@echo off
title OGCWin Mode Selector
"%ProgramFiles%\PowerShell\7\pwsh.exe" -ExecutionPolicy Bypass -Command ^
"Start-Process -FilePath pwsh.exe -Verb RunAs -ArgumentList '-NoExit -ExecutionPolicy Bypass -NoProfile -File \"C:\ProgramData\OGC Windows Utility\scripts\OGCMode.ps1\"'"
exit
