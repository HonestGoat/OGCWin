@echo off
:: Set PowerShell script path
set "parentFolder=C:\ProgramData\OGC Windows Utility"
set "scriptsFolder=%parentFolder%\scripts"
set "OGClaunch=%scriptsFolder%\launch.ps1"

:: Check if PowerShell is running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~s0' -Verb RunAs"
    exit /b
)

:: Launch PowerShell with black background, custom title, and admin rights
powershell -NoExit -ExecutionPolicy Bypass -NoProfile -Command ^
"& { $host.UI.RawUI.WindowTitle = 'OGC Windows Utility Launcher'; $host.UI.RawUI.BackgroundColor = 'Black'; $host.UI.RawUI.ForegroundColor = 'White'; Clear-Host; Start-Process powershell.exe -ArgumentList '-NoExit -ExecutionPolicy Bypass -NoProfile -File \"%OGClaunch%\"' -Verb RunAs }"
exit
