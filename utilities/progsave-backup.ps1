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

