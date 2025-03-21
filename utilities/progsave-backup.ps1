# OGC New Windows Setup Wizard by Honest Goat
# Version: 0.2 - No Compression, Enhanced Exclusions, User Prompt

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
$host.UI.RawUI.WindowTitle = "OGC New Windows Wizard"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

# OGC Banner
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "    OGC Saves and Settings Utility     " -ForegroundColor Yellow
Write-Host "    Game Saves and Program Settings    " -ForegroundColor Yellow
Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Host "        Created by Honest Goat         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "This utility will backup saved games and other" -ForegroundColor Yellow
Write-Host "program data from your pc, including the stuff in appdata" -ForegroundColor Yellow


# Confirm User Wants to Continue
Write-Host "!!! MAKE SURE THIS SCRIPT IS IN THE FOLDER YOU WANT TO BACKUP TO !!!" -ForegroundColor Magenta
Write-Host "!!! IF ITS NOT, THEN YOU SHOULD CLOSE THIS, MOVE THE SCRIPT AND RUN IT AGIAN !!!" -ForegroundColor Magenta
$continueScript = Read-Host "Is this script located in the folder that you want to backup your data to (y/n)?"
Start-Sleep -Seconds 1
$continueScript = Read-Host "!!! DISCLAIMER !!! You assume all risk of data loss. Press (y/n) to agree and continue"

if ($continueScript -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Blue
    Start-Sleep -Seconds 2
    exit
}

# Prompt user for action
Write-Host ""
Write-Host "Would you like to (B)ackup or (R)estore?" -ForegroundColor Yellow
$actionChoice = Read-Host "Enter B for Backup or R for Restore"
if ($actionChoice -notin @("B", "b", "R", "r")) {
    Write-Host "Invalid selection. Exiting." -ForegroundColor Red
    exit
}
$Mode = if ($actionChoice -in @("B", "b")) { "Backup" } else { "Restore" }

# Confirm folder placement and risk
Write-Host ""
Write-Host "!!! MAKE SURE THIS SCRIPT IS IN THE FOLDER YOU WANT TO BACKUP TO !!!" -ForegroundColor Magenta
Write-Host "!!! IF NOT, THEN YOU SHOULD CLOSE THIS, MOVE THE SCRIPT AND RUN IT AGAIN !!!" -ForegroundColor Magenta
$confirmFolder = Read-Host "Is this script located in the folder that you want to backup your data to (y/n)?"
if ($confirmFolder -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Blue
    exit
}

$disclaimer = Read-Host "!!! DISCLAIMER !!! You assume all risk of data loss. Press (y/n) to agree and continue"
if ($disclaimer -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Blue
    exit
}

# Working paths
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$BackupRoot = Join-Path -Path $ScriptRoot -ChildPath "Backup_$Timestamp"
$LogFile = Join-Path -Path $ScriptRoot -ChildPath "progsave.log"

function Write-Log {
    param ([string]$Message)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$time - $Message"
}

function Export-OutlookRegistry {
    param ([string]$ExportPath)
    try {
        $officeKey = "HKCU:\Software\Microsoft\Office"
        $officeVersions = Get-ChildItem $officeKey | Where-Object { $_.Name -match "\d+\.\d+" }
        foreach ($ver in $officeVersions) {
            $regPath = "$($ver.PSPath)\Outlook\Profiles"
            if (Test-Path $regPath) {
                $regFile = Join-Path -Path $ExportPath -ChildPath "OutlookProfiles_$($ver.PSChildName).reg"
                reg export $regPath $regFile /y | Out-Null
            }
        }
        Write-Log "Exported Outlook registry profiles."
    } catch {
        Write-Log "Outlook registry export failed: $_"
    }
}

$PathsRelative = @(
    "AppData\Roaming",
    "AppData\Local",
    "Saved Games",
    "Documents\Outlook Files",
    "AppData\Local\Microsoft\Outlook"
)

$Exclusions = @(
    "*\AppData\Local\Temp*",
    "*\AppData\Local\Microsoft\Windows*",
    "*\AppData\Roaming\Microsoft\Windows*",
    "*\AppData\Roaming\Microsoft\Themes*",
    "*\AppData\Roaming\Microsoft\Windows\Recent*",
    "*\AppData\Local\Microsoft\Windows\Caches*",
    "*\AppData\Local\Microsoft\Windows\Explorer*",
    "*\AppData\Local\Intel*",
    "*\AppData\Local\AMD*",
    "*\AppData\Local\NVIDIA*",
    "*\AppData\Roaming\Intel*",
    "*\AppData\Roaming\AMD*",
    "*\AppData\Roaming\NVIDIA*",
    "*\AppData\Local\Microsoft\Edge*",
    "*\AppData\Roaming\Microsoft\Edge*",
    "*\AppData\Local\Packages*"
)

if ($Mode -eq "Backup") {
    Write-Host "Starting backup..." -ForegroundColor Cyan
    Write-Log "Backup initiated."

    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    Export-OutlookRegistry -ExportPath $BackupRoot

    $i = 0
    foreach ($relPath in $PathsRelative) {
        $source = Join-Path -Path $env:USERPROFILE -ChildPath $relPath
        if (Test-Path $source) {
            $destination = Join-Path -Path $BackupRoot -ChildPath $relPath
            New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
            Write-Progress -Activity "Backing Up" -Status $relPath -PercentComplete (($i++ / $PathsRelative.Count) * 100)

            try {
                robocopy $source $destination /E /XD $Exclusions /NFL /NDL /NJH /NJS /NC | Out-Null
                Write-Log "Backed up $relPath"
            } catch {
                Write-Log "Failed to backup ${relPath}: $($_.Exception.Message)"
            }
        }
    }

    Write-Host "Backup complete. Files are saved to $BackupRoot" -ForegroundColor Green
    Write-Log "Backup complete."
}

if ($Mode -eq "Restore") {
    Write-Host "Starting restore..." -ForegroundColor Cyan
    Write-Log "Restore initiated."

    $folders = Get-ChildItem -Path $ScriptRoot -Directory | Where-Object { $_.Name -like "Backup_*" } | Sort-Object LastWriteTime -Descending
    if ($folders.Count -eq 0) {
        Write-Host "No backup folders found." -ForegroundColor Red
        Write-Log "No backup found."
        exit
    }

    $latest = $folders[0].FullName
    Write-Host "Restoring from: $latest"

    $items = Get-ChildItem -Path $latest -Recurse
    foreach ($item in $items) {
        $relPath = $item.FullName.Substring($latest.Length).TrimStart('\')
        $targetPath = Join-Path -Path $env:USERPROFILE -ChildPath $relPath
        try {
            if ($item.PSIsContainer) {
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            } else {
                Copy-Item -Path $item.FullName -Destination $targetPath -Force
            }
            Write-Log "Restored ${relPath}"
        } catch {
            Write-Log "Restore failed for ${relPath}: $_"
        }
    }

    Write-Host "Restore complete." -ForegroundColor Green
    Write-Log "Restore complete."
}
