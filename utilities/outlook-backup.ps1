# OGC Windows Utility - Outlook Backup and Restore Script
# This script allows the user to fully backup or restore Microsoft Outlook configuration, files, and settings.

$parentFolder = "C:\ProgramData\OGC Windows Utility"
$backupRoot = "$parentFolder\backups\OutlookBackup"
$logFile = "$backupRoot\Outlook_BackupRestore_Log.txt"

function Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $message"
    Write-Host $message
}

function Backup-Outlook {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$backupRoot\Backup_$timestamp"
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    Log "Starting Outlook backup..."
    Log "Backup folder: $backupPath"

    # Backup PST/OST Files
    try {
        $pstBackupFolder = "$backupPath\PST_OST_Files"
        New-Item -ItemType Directory -Path $pstBackupFolder -Force | Out-Null
        $pstFiles = Get-ChildItem "$env:USERPROFILE\AppData\Local\Microsoft\Outlook" -Include *.pst, *.ost -Recurse -ErrorAction Stop
        foreach ($file in $pstFiles) {
            Copy-Item -Path $file.FullName -Destination $pstBackupFolder -Force
        }
        Log "PST and OST files backed up."
    } catch {
        Log "No PST or OST files found or error during backup: $_"
    }

    # Backup Signatures
    try {
        $signatureSource = "$env:APPDATA\Microsoft\Signatures"
        if (Test-Path $signatureSource) {
            Copy-Item $signatureSource "$backupPath\Signatures" -Recurse -Force
            Log "Signatures backed up."
        }
    } catch {
        Log "Error backing up signatures: $_"
    }

    # Backup Templates
    try {
        $templateSource = "$env:APPDATA\Microsoft\Templates"
        if (Test-Path $templateSource) {
            Copy-Item $templateSource "$backupPath\Templates" -Recurse -Force
            Log "Templates backed up."
        }
    } catch {
        Log "Error backing up templates: $_"
    }

    # Backup Registry Keys
    try {
        $regBackupFolder = "$backupPath\Registry"
        New-Item -ItemType Directory -Path $regBackupFolder -Force | Out-Null
        $regKeys = @(
            "HKEY_CURRENT_USER\Software\Microsoft\Office",
            "HKEY_CURRENT_USER\Software\Microsoft\Outlook",
            "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem"
        )
        foreach ($key in $regKeys) {
            $keyExists = reg query "$key" 2>$null
            if ($keyExists) {
                $safeKey = ($key -replace "[\\:\s]", "_")
                $regFile = "$regBackupFolder\$safeKey.reg"
                reg export "$key" "$regFile" /y | Out-Null
            } else {
                Log "Exported registry key: $key"
            }    
        }
    } catch {
        Log "Error exporting registry keys: $_"
    }

    Log "Outlook backup completed successfully!"
}

function Restore-Outlook {
    Log "Preparing to restore Outlook backup..."

    $availableBackups = Get-ChildItem -Path $backupRoot -Directory | Sort-Object LastWriteTime -Descending
    if (!$availableBackups) {
        Log "No backups found. Please run a backup first."
        return
    }

    Write-Host "Available backups:"
    $count = 1
    foreach ($folder in $availableBackups) {
        Write-Host "$count. $($folder.Name)"
        $count++
    }

    $choice = Read-Host "Enter the number of the backup you want to restore"
    $index = [int]$choice - 1
    if ($index -lt 0 -or $index -ge $availableBackups.Count) {
        Log "Invalid choice. Exiting."
        return
    }

    $backupPath = $availableBackups[$index].FullName
    Log "Restoring from: $backupPath"

    try {
        Copy-Item "$backupPath\PST_OST_Files\*" "$env:USERPROFILE\AppData\Local\Microsoft\Outlook" -Recurse -Force
        Log "PST and OST files restored."
    } catch {
        Log "Error restoring PST/OST files: $_"
    }

    try {
        $rulesFile = "$backupPath\OutlookRules.rwz"
        if (Test-Path $rulesFile) {
            $outlook = New-Object -ComObject Outlook.Application
            $namespace = $outlook.GetNamespace("MAPI")
            $namespace.LoadRulesFromFile($rulesFile)
            Log "Outlook rules restored successfully."
        }
    } catch {
        Log "Error restoring Outlook rules: $_"
    }

    try {
        Copy-Item "$backupPath\Signatures\*" "$env:APPDATA\Microsoft\Signatures" -Recurse -Force
        Log "Signatures restored."
    } catch {
        Log "Error restoring signatures: $_"
    }

    try {
        Copy-Item "$backupPath\Templates\*" "$env:APPDATA\Microsoft\Templates" -Recurse -Force
        Log "Templates restored."
    } catch {
        Log "Error restoring templates: $_"
    }

    try {
        $regFiles = Get-ChildItem "$backupPath\Registry" -Filter *.reg
        foreach ($file in $regFiles) {
            reg import $file.FullName | Out-Null
            Log "Imported registry: $($file.Name)"
        }
    } catch {
        Log "Error importing registry files: $_"
    }

    Log "Outlook restore process complete!"
}

# OGC Banner
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "       OGC Outlook Backup Utility      " -ForegroundColor Yellow
Write-Host "         https://discord.gg/ogc        " -ForegroundColor Magenta
Write-Host "         Created by Honest Goat        " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "This utility will backup all Outlook data and settings." -ForegroundColor Yellow
Write-Host "Then you can restore it and Outlook will be how it was." -ForegroundColor Yellow

$action = Read-Host "Enter your choice (backup / restore)"

if ($action -eq "backup") {
    Backup-Outlook
} elseif ($action -eq "restore") {
    Restore-Outlook
} else {
    Write-Host "Invalid option selected. Please run the script again and choose 'backup' or 'restore'."
}
