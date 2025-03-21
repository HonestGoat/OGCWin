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
$host.UI.RawUI.WindowTitle = "OGC New Windows Wizard"
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
$continueScript = Read-Host "Is this script located in the folder that you want to backup your data to (y/n)?" -ForegroundColor Cyan
Start-Sleep -Seconds 1
$continueScript = Read-Host "!!! DISCLAIMER !!! You assume all risk of data loss. Press (y/n) to agree and continue" -ForegroundColor Red

if ($continueScript -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}


param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Backup", "Restore")]
    [string]$Mode
)

# Determine working directory
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$BackupRoot = Join-Path -Path $ScriptRoot -ChildPath "Backup_$Timestamp"
$BackupArchive = "$BackupRoot.7z"
$LogFile = Join-Path -Path $ScriptRoot -ChildPath "progsave.log"

# Log helper
function Write-Log {
    param ([string]$Message)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$time - $Message"
}

# 7-Zip detection
function Get-7ZipPath {
    $possiblePaths = @(
        "C:\Program Files\7-Zip\7z.exe",
        "C:\Program Files (x86)\7-Zip\7z.exe"
    )
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) { return $path }
    }
    return $null
}

# Install 7-Zip if missing
function Install-7Zip {
    if (-Not (Get-7ZipPath)) {
        Write-Log "7-Zip not found. Attempting installation..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install --id 7zip.7zip -e --accept-source-agreements --accept-package-agreements
        } else {
            $Installer = "$env:TEMP\7zSetup.exe"
            Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z1900-x64.exe" -OutFile $Installer
            Start-Process -FilePath $Installer -ArgumentList "/S" -Wait
            Remove-Item $Installer -Force
        }
    }
}

# Export Outlook Registry Profiles
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

# Compress a directory
function Compress-Directory {
    param ($SourceDir, $DestinationArchive)
    $7z = Get-7ZipPath
    if ($7z) {
        & "$7z" a -mx=9 -mmt "$DestinationArchive" "$SourceDir\*" | Out-Null
        Write-Log "Created archive at $DestinationArchive"
    } else {
        Write-Log "7-Zip not found."
    }
}

# Decompress an archive
function Expand-ArchiveCustom {
    param ($ArchivePath, $DestinationDir)
    $7z = Get-7ZipPath
    if ($7z) {
        & "$7z" x "$ArchivePath" -o"$DestinationDir" -y | Out-Null
        Write-Log "Extracted archive to $DestinationDir"
    } else {
        Write-Log "7-Zip not found."
    }
}

# Paths to back up (all relative to USERPROFILE)
$PathsRelative = @(
    "AppData\Roaming",
    "AppData\Local",
    "Saved Games",
    "Documents\Outlook Files",
    "AppData\Local\Microsoft\Outlook"
)

$Exclusions = @(
    "AppData\Local\Temp",
    "AppData\Local\Microsoft\Windows\Explorer",
    "AppData\Local\Microsoft\Windows\Caches",
    "AppData\Roaming\Microsoft\Windows",
    "AppData\Roaming\Microsoft\Windows\Recent",
    "AppData\Roaming\Microsoft\Windows\Themes"
)

# Perform backup
if ($Mode -eq "Backup") {
    Write-Output "Starting backup..."
    Write-Log "Backup initiated."

    Install-7Zip
    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    Export-OutlookRegistry -ExportPath $BackupRoot

    $i = 0
    foreach ($relPath in $PathsRelative) {
        $source = Join-Path -Path $env:USERPROFILE -ChildPath $relPath
        if (Test-Path $source) {
            $relativeTarget = Join-Path -Path $BackupRoot -ChildPath $relPath
            New-Item -ItemType Directory -Path (Split-Path $relativeTarget) -Force | Out-Null
            Write-Progress -Activity "Backing Up" -Status $relPath -PercentComplete (($i++ / $PathsRelative.Count) * 100)
            try {
                robocopy $source $relativeTarget /E /NFL /NDL /NJH /NJS /NC /XD $Exclusions | Out-Null
                Write-Log "Backed up $relPath"
            } catch {
                Write-Log "Failed to backup ${relPath}: $($_.Exception.Message)"
            }
        }
    }

    Compress-Directory -SourceDir $BackupRoot -DestinationArchive $BackupArchive
    Write-Output "Backup completed: $BackupArchive"
    Write-Log "Backup completed."
}

# Perform restore
if ($Mode -eq "Restore") {
    Write-Output "Starting restore..."
    Write-Log "Restore initiated."

    $archives = Get-ChildItem -Path $ScriptRoot -Filter "Backup_*.7z" | Sort-Object LastWriteTime -Descending
    if ($archives.Count -eq 0) {
        Write-Output "No backup archive found."
        Write-Log "No backup found."
        exit
    }

    $latest = $archives[0].FullName
    $tempRestore = Join-Path -Path $ScriptRoot -ChildPath "Restore_$Timestamp"
    New-Item -ItemType Directory -Path $tempRestore -Force | Out-Null
    Expand-ArchiveCustom -ArchivePath $latest -DestinationDir $tempRestore

    $items = Get-ChildItem -Path $tempRestore -Recurse
    foreach ($item in $items) {
        $relPath = ${item}.FullName.Substring($tempRestore.Length).TrimStart('\')
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

    Write-Output "Restore complete."
    Write-Log "Restore complete."
}

