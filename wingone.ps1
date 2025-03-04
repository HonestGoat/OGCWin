# Winget removal tool.
# Mainly for testing purposes.

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 3
    exit
}

Write-Host "Starting WinGet removal process..." -ForegroundColor Cyan

# Function to remove a package
function Remove-AppxPackageSafely {
    param (
        [string]$PackageName
    )
    $package = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
    if ($package) {
        Write-Host "Removing $PackageName..." -ForegroundColor Yellow
        Get-AppxPackage -Name $PackageName | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Write-Host "$PackageName removed successfully." -ForegroundColor Green
    } else {
        Write-Host "$PackageName is not installed." -ForegroundColor Cyan
    }
}

# Function to remove a provisioned package
function Remove-AppxProvisionedPackageSafely {
    param (
        [string]$PackageName
    )
    $provisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $PackageName }
    if ($provisionedPackage) {
        Write-Host "Removing provisioned package: $PackageName..." -ForegroundColor Yellow
        Remove-AppxProvisionedPackage -Online -PackageName $provisionedPackage.PackageName -ErrorAction SilentlyContinue
        Write-Host "$PackageName provisioned package removed." -ForegroundColor Green
    } else {
        Write-Host "Provisioned package $PackageName is not found." -ForegroundColor Cyan
    }
}

# Remove WinGet (Windows Package Manager)
Remove-AppxPackageSafely -PackageName "Microsoft.DesktopAppInstaller"
Remove-AppxProvisionedPackageSafely -PackageName "Microsoft.DesktopAppInstaller"

# Remove Dependencies
Remove-AppxPackageSafely -PackageName "Microsoft.VCLibs.140.00"
Remove-AppxProvisionedPackageSafely -PackageName "Microsoft.VCLibs.140.00"

Remove-AppxPackageSafely -PackageName "Microsoft.UI.Xaml.2.8"
Remove-AppxProvisionedPackageSafely -PackageName "Microsoft.UI.Xaml.2.8"

# Remove any leftover files related to WinGet
$WinGetFolders = @(
    "$env:LOCALAPPDATA\Microsoft\WinGet",
    "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller*",
    "$env:ProgramFiles\WindowsApps\Microsoft.VCLibs*",
    "$env:ProgramFiles\WindowsApps\Microsoft.UI.Xaml*"
)

Write-Host "Cleaning up WinGet-related files..." -ForegroundColor Yellow
foreach ($folder in $WinGetFolders) {
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Deleted: $folder" -ForegroundColor Green
    }
}

## Prevent Windows from reinstalling WinGet automatically
#Write-Host "Blocking WinGet from being reinstalled by Windows Update..." -ForegroundColor Magenta
#$wingetRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned"
#if (!(Test-Path $wingetRegPath)) {
#    New-Item -Path $wingetRegPath -Force | Out-Null
#}
#New-ItemProperty -Path $wingetRegPath -Name "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" -PropertyType String -Value "Deprovisioned" -Force | Out-Null
#Write-Host "WinGet is now blocked from being automatically reinstalled." -ForegroundColor Green

Write-Host "WinGet and its dependencies have been successfully removed!" -ForegroundColor Cyan