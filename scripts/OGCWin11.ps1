# OGC New Windows Setup Wizard by Honest Goat
# Version: 0.1
# This wizard disables tracking and data collection, optimizes Windows for gaming, removes bloatware,
# disables invasive and annoying features like CoPilot and Recall, removes Edge integrations and annoyances
# and allows the user to install a host of common applications drivers.

# Set PowerShell Execution Policy to allow scripts (requires admin)
Set-ExecutionPolicy Bypass -Scope Process -Force

# Force Black Background and White Text
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host
# Define color functions for better visibility
function Write-Color {
    param (
        [string]$Text,
        [string]$ForegroundColor = "White",
        [string]$BackgroundColor = "Black"
    )
    Write-Host $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
}

# Function to show progress bar
function Show-Progress {
    param (
        [string]$Message
    )
    Write-Host "[$Message]" -ForegroundColor Blue
    Start-Sleep -Seconds 2
}

# Detect Banner Version
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption
if ($winVer -match "Windows 10 Home" -or $winVer -match "Windows 10 Pro") {
    # Windows 10 Banner
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "        OGC Windows 10 Utility         " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
} elseif ($winVer -match "Windows 11 Home" -or $winVer -match "Windows 11 Pro") {
    # Windows 11 Banner
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
} else {
    Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

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