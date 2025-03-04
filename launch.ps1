# OGC Banner
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "       OGC Windows Gaming Utility      " -ForegroundColor Yellow
Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Host "        Created by Honest Goat         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue

Start-Sleep -Seconds 1

Write-Host "Checking for dependencies..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Function to check if WinGet is installed
function Test-WinGet {
    try {
        winget --version
        return $true
    } catch {
        return $false
    }
}

# Function to install WinGet
function Install-WinGet {
    # Define URLs for dependencies and WinGet
    $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $wingetApiUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"

    # Download and install Microsoft.VCLibs.140.00.UWPDesktop
    Write-Host "Downloading Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
    $vclibsPath = "$env:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx"
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$vclibsPath`" `"$vclibsUrl`"" -NoNewWindow -Wait
    Add-AppxPackage -Path $vclibsPath

    # Get the download URL of the latest WinGet installer from GitHub
    Write-Host "Fetching latest WinGet release information..." -ForegroundColor Yellow
    $latestRelease = Invoke-RestMethod -Uri $wingetApiUrl
    $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
    $wingetUrl = $wingetAsset.browser_download_url

    # Download and install WinGet
    Write-Host "Downloading WinGet..." -ForegroundColor Yellow
    $wingetPath = "$env:TEMP\$($wingetAsset.name)"
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$wingetPath`" `"$wingetUrl`"" -NoNewWindow -Wait
    Add-AppxPackage -Path $wingetPath

    # Clean up downloaded files
    Remove-Item -Path $vclibsPath, $wingetPath
}

# Main script execution
if (-not (Test-WinGet)) {
    Write-Host "WinGet is not installed. Attempting to install..." -ForegroundColor Yellow
    Install-WinGet
    Start-Sleep -Seconds 5 # Wait for installation to complete
    if (-not (Test-WinGet)) {
        Write-Host "WinGet installation failed. Exiting Utility." -ForegroundColor Red
        Write-Host "Please follow the manual intallation instructions" -ForegroundColor Red
        Write-Host "pinned in the Tech Support channel in the OGC Discord." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit 1
    }
}

Write-Host "All dependencies detected." -ForegroundColor Green
Start-Sleep -Seconds 1

Write-Host "Starting OGC Windows Utility..." -ForegroundColor Cyan
Start-Sleep -Seconds 1

# Start OGC Windows Utility in a new PowerShell window with a black background
$psCommand = @'
$host.UI.RawUI.BackgroundColor = 'Black'
$host.UI.RawUI.ForegroundColor = 'White'
Clear-Host
irm https://raw.githubusercontent.com/HonestGoat/OGCWin/main/OGCWin.ps1 | iex
'@

Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -Command `"$psCommand`"" -Verb RunAs
exit
Write-Host "You may now close this window." -ForegroundColor Green
