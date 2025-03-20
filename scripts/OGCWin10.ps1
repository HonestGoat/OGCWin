# OGC New Windows Setup Wizard by Honest Goat
# Version: 0.1

# Start with administrator privileges, bypass execution policy and force black background
function Test-Admin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}
Test-Admin

Set-ExecutionPolicy Bypass -Scope Process -Force
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

# Define colour functions and progress bars
function Write-Color {
    param (
        [string]$Text,
        [string]$ForegroundColor = "White",
        [string]$BackgroundColor = "Black"
    )
    Write-Host $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
}

function Show-Progress {
    param (
        [string]$Message
    )
    for ($i = 1; $i -le 100; $i += 10) {
        Write-Progress -Activity $Message -Status "$i% Complete" -PercentComplete $i
        Start-Sleep -Milliseconds 300
    }
    Write-Host "`n[$Message Complete]" -ForegroundColor Green
}

# OGC Banner
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "        OGC Windows 11 Utility         " -ForegroundColor Yellow
Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Host "        Created by Honest Goat         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host ""
Write-Host ""
Write-Host ""
# Welcome & Instructions
Write-Host "Welcome to the OGC Windows Gaming Utility!" -ForegroundColor Cyan
Write-Host ""
Write-Host "This utility will help you optimize your Windows installation by:" -ForegroundColor Yellow
Write-Host "✔ Removing unnecessary bloatware and preinstalled apps" -ForegroundColor Green
Write-Host "✔ Disabling telemetry, tracking, and data collection" -ForegroundColor Green
Write-Host "✔ Customizing Windows settings for a better gaming experience" -ForegroundColor Green
Write-Host "✔ Improving privacy and performance" -ForegroundColor Green
Write-Host "✔ Allow you to remove or install common applications." -ForegroundColor Green
Write-Host ""
Write-Host "! For optimal performance and privacy, apply settings marked as [Recommended] !" -ForegroundColor Magenta
Write-Host ""
Write-Host "⚠ THIS UTILITY WILL MAKE CAHNGES TO YOUR SYSTEM, ⚠" -ForegroundColor Red
Write-Host "⚠  BUT NO CRITICAL FUNCTIONALITY WILL BE LOST.   ⚠" -ForegroundColor Red
Write-Host ""
Write-Host "⚠ Please read each prompt carefully before proceeding. ⚠" -ForegroundColor Magenta
Write-Host ""