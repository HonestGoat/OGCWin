# ==========================================
#    OGC Windows Utility - Email Backup
#              By Honest Goat
#               Version: 0.9
# ==========================================

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
$host.UI.RawUI.WindowTitle = "OGCWin Utility Launcher"
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

# ==========================================
#             DEFINITIONS
# ==========================================

# Paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$backupFolder = "$parentFolder\backups\EmailBackup"
$tempFolder = "$backupFolder\TempStaging"

# User Data Paths
$userProfile = $env:USERPROFILE
$appData = $env:APPDATA
$localAppData = $env:LOCALAPPDATA

# Registry Paths to Backup (Outlook Only)
$regKeysToBackup = @(
    "HKEY_CURRENT_USER\Software\Microsoft\Office",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles"
)

# Supported Clients Configuration
$SupportedClients = @{
    "Outlook" = @{
        ProcessNames = @("OUTLOOK", "lync", "UcMapi", "ms-teams")
        Folders = @{
            "Signatures"      = "$appData\Microsoft\Signatures"
            "Stationery"      = "$appData\Microsoft\Stationery"
            "Templates"       = "$appData\Microsoft\Templates"
            "Outlook_Roaming" = "$appData\Microsoft\Outlook"
            "Outlook_Local"   = "$localAppData\Microsoft\Outlook"
            "Documents_Files" = "$userProfile\Documents\Outlook Files"
        }
    }
    "Thunderbird" = @{
        ProcessNames = @("thunderbird")
        Folders = @{
            "Thunderbird_Roaming" = "$appData\Thunderbird"
            "Thunderbird_Local"   = "$localAppData\Thunderbird"
        }
    }
    "ProtonMail" = @{
        ProcessNames = @("Proton Mail", "ProtonMail")
        Folders = @{
            "Proton_Roaming" = "$appData\Proton Mail"
            "Proton_Local"   = "$localAppData\Proton Mail"
        }
    }
    "eMClient" = @{
        ProcessNames = @("MailClient")
        Folders = @{
            "eMClient_Roaming" = "$appData\eM Client"
        }
    }
}

# Folder structure
$folders = @($parentFolder, $backupFolder)

# ==========================================
#             FUNCTIONS
# ==========================================

function Write-Log {
    param (
        [Parameter(Mandatory=$true)] [string]$Message,
        [Parameter(Mandatory=$false)] [ValidateSet("SUCCESS","FAILURE","INFO","WARNING","ERROR")] [string]$Status = "INFO",
        [string]$Module = "General"
    )
    $logFolder = Join-Path $parentFolder "logs"
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    $logFile = Join-Path $logFolder "${scriptName}_log.txt"
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$Status] [$timestamp] [$Module] $Message"
    try { Add-Content -Path $logFile -Value $logEntry -Force -ErrorAction Stop }
    catch { Write-Host "CRITICAL: Can't write to $logFile" -ForegroundColor Red }
    if ($Status -eq "FAILURE") { Write-Host "Error ($Module): $Message" -ForegroundColor Red }
    elseif ($Status -eq "WARNING") { Write-Host "Warning ($Module): $Message" -ForegroundColor Yellow }
}

function Show-Progress {
    param ([string]$Message)
    for ($i = 1; $i -le 100; $i += 20) {
        Write-Progress -Activity "Processing..." -Status $Message -PercentComplete $i
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity "Processing..." -Completed
}

function Close-EmailProcesses {
    Write-Log "Checking for running email processes..." "INFO"
    
    # Gather all process names from config
    $allProcs = @()
    foreach ($client in $SupportedClients.Values) {
        $allProcs += $client.ProcessNames
    }

    foreach ($p in $allProcs) {
        if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
            Write-Log "Killing process: $p to release file locks." "WARNING"
            Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
    Write-Log "Email processes terminated." "SUCCESS"
}

function Backup-EmailClients {
    param ()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $archiveName = "EmailClients_FullBackup_$timestamp.zip"
    $finalZipPath = Join-Path $backupFolder $archiveName

    # 1. Clean Staging Area
    if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
    
    Write-Log "Starting Backup Process..." "INFO"
    
    # 2. Close Apps
    Close-EmailProcesses

    # 3. Backup Files to Staging
    foreach ($clientName in $SupportedClients.Keys) {
        $clientConfig = $SupportedClients[$clientName]
        $foldersToBackup = $clientConfig.Folders
        
        # Check if client data exists at all before creating folder
        $clientHasData = $false
        foreach ($path in $foldersToBackup.Values) { if (Test-Path $path) { $clientHasData = $true } }

        if ($clientHasData) {
            Write-Log "Backing up: $clientName" "INFO"
            $clientStaging = Join-Path $tempFolder $clientName
            New-Item -ItemType Directory -Path $clientStaging -Force | Out-Null

            foreach ($folderKey in $foldersToBackup.Keys) {
                $src = $foldersToBackup[$folderKey]
                $dest = Join-Path $clientStaging $folderKey
                
                if (Test-Path $src) {
                    Write-Log "  -> Copying: $folderKey" "INFO"
                    try {
                        New-Item -ItemType Directory -Path $dest -Force | Out-Null
                        Copy-Item -Path "$src\*" -Destination $dest -Recurse -Force -ErrorAction Stop
                    } catch {
                        Write-Log "  -> Failed to copy $src : $_" "ERROR"
                    }
                }
            }
        } else {
            Write-Log "Skipping $clientName (No data found)" "WARNING"
        }
    }

    # 4. Export Registry (Outlook Only)
    try {
        $regFolder = Join-Path "$tempFolder\Outlook" "Registry"
        if (-not (Test-Path $regFolder)) { New-Item -ItemType Directory -Path $regFolder -Force | Out-Null }
        
        foreach ($key in $regKeysToBackup) {
            $safeName = ($key -replace "[\\:]", "_") + ".reg"
            $exportPath = Join-Path $regFolder $safeName
            
            # Check if key exists first
            if (Test-Path "Registry::$key") {
                Write-Log "Exporting Registry Key: $key" "INFO"
                $proc = Start-Process -FilePath "reg.exe" -ArgumentList "export `"$key`" `"$exportPath`" /y" -PassThru -Wait -NoNewWindow
                
                if ($proc.ExitCode -eq 0 -and (Test-Path $exportPath)) {
                    Write-Log "Registry export successful." "SUCCESS"
                } else {
                    Write-Log "Registry export failed for $key (Exit Code: $($proc.ExitCode))" "ERROR"
                }
            }
        }
    } catch {
        Write-Log "Registry Backup Error: $_" "ERROR"
    }

    # 5. Compress to Archive
    try {
        # Verify if staging is empty
        if ((Get-ChildItem $tempFolder).Count -eq 0) {
            Write-Log "No data was backed up. Aborting archive creation." "ERROR"
            return
        }

        Write-Log "Compressing backup to single archive... This may take time." "INFO"
        Show-Progress "Compressing Data"
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolder, $finalZipPath)
        
        if (Test-Path $finalZipPath) {
            $size = Get-Item $finalZipPath
            $sizeMB = "{0:N2}" -f ($size.Length / 1MB)
            Write-Log "Backup Archive Created Successfully: $archiveName ($sizeMB MB)" "SUCCESS"
        } else {
            throw "Archive file was not created."
        }

    } catch {
        Write-Log "Compression Failed: $_" "ERROR"
        Write-Log "Attempting to save uncompressed data instead..." "WARNING"
        $emergencyPath = Join-Path $backupFolder "Uncompressed_$timestamp"
        Copy-Item -Path $tempFolder -Destination $emergencyPath -Recurse
        return
    }

    # 6. Cleanup
    Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Backup Operation Complete." "SUCCESS"
}

function Restore-EmailClients {
    param ()
    
    # 1. Find Backups
    $zips = Get-ChildItem -Path $backupFolder -Filter "*.zip" | Sort-Object LastWriteTime -Descending
    
    if ($zips.Count -eq 0) {
        Write-Log "No backup archives found in $backupFolder" "ERROR"
        return
    }

    Write-Color "`nAvailable Backups:" -ForegroundColor Cyan
    $i = 1
    foreach ($z in $zips) {
        $size = "{0:N2} MB" -f ($z.Length / 1MB)
        Write-Host "$i. $($z.Name) [$size] - $( $z.LastWriteTime )"
        $i++
    }
    Write-Host ""

    $selection = Read-Host "Select backup number to restore (or Q to cancel)"
    if ($selection -match "^[qQ]$") { return }

    try {
        $index = [int]$selection - 1
        $targetZip = $zips[$index]
    } catch {
        Write-Log "Invalid selection." "ERROR"
        return
    }

    $confirm = Read-Host "WARNING: This will overwrite CURRENT EMAIL DATA. Type 'RESTORE' to confirm"
    if ($confirm -ne "RESTORE") { return }

    # 2. Close Apps
    Close-EmailProcesses
    
    # 3. Extract to Staging
    if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Log "Extracting archive..." "INFO"
    
    try {
        Expand-Archive -Path $targetZip.FullName -DestinationPath $tempFolder -Force -ErrorAction Stop
    } catch {
        Write-Log "Extraction Failed: $_" "ERROR"
        return
    }

    # 4. Restore Loop
    foreach ($clientName in $SupportedClients.Keys) {
        $clientStaging = Join-Path $tempFolder $clientName
        
        if (Test-Path $clientStaging) {
            Write-Log "Restoring data for: $clientName" "INFO"
            $foldersToRestore = $SupportedClients[$clientName].Folders
            
            foreach ($folderKey in $foldersToRestore.Keys) {
                $sourceDir = Join-Path $clientStaging $folderKey
                $targetDir = $foldersToRestore[$folderKey]
                
                if (Test-Path $sourceDir) {
                    Write-Log "  -> Restoring: $folderKey" "INFO"
                    if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
                    try {
                        Copy-Item -Path "$sourceDir\*" -Destination $targetDir -Recurse -Force -ErrorAction Stop
                    } catch {
                        Write-Log "  -> Error restoring $targetDir : $_" "ERROR"
                    }
                }
            }
        }
    }

    # 5. Restore Registry (Outlook Only)
    $regSource = Join-Path "$tempFolder\Outlook" "Registry"
    if (Test-Path $regSource) {
        Write-Log "Restoring Outlook Registry Settings..." "INFO"
        $regFiles = Get-ChildItem $regSource -Filter "*.reg"
        foreach ($reg in $regFiles) {
            Write-Log "Importing: $($reg.Name)" "INFO"
            Start-Process -FilePath "reg.exe" -ArgumentList "import `"$($reg.FullName)`"" -Wait -NoNewWindow
        }
    }

    # 6. Cleanup
    Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Restore Complete. Please restart your computer." "SUCCESS"
}

function Show-Disclaimer {
    Clear-Host
    Write-Color "===================================================" -ForegroundColor Red
    Write-Color "           !!! IMPORTANT DISCLAIMER !!!            " -ForegroundColor Red
    Write-Color "===================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "You are about to run an Email Backup/Restore operation." -ForegroundColor Yellow
    Write-Host "Supported Clients: Outlook, Thunderbird, Proton Mail, eM Client." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "NOTE ON WEBMAIL (Gmail, Yahoo, etc):" -ForegroundColor Magenta
    Write-Host "This tool CANNOT backup cloud webmail unless you have synced" -ForegroundColor Magenta
    Write-Host "it to a local client (like Outlook or Thunderbird) first." -ForegroundColor Magenta
    Write-Host ""
    Write-Host "By proceeding, you acknowledge and agree that:" -ForegroundColor Cyan
    Write-Host "1. You assume ALL RISK of potential data loss or corruption." -ForegroundColor Gray
    Write-Host "2. You are responsible for verifying the integrity of the backup." -ForegroundColor Gray
    Write-Host "3. The author (Honest Goat) is not liable for lost emails or files." -ForegroundColor Gray
    Write-Host ""
    Write-Color "===================================================" -ForegroundColor Red
    Write-Host ""
    
    $agreement = Read-Host "Type 'I AGREE' to proceed"
    if ($agreement -ne "I AGREE") {
        Write-Host "User did not agree. Exiting." -ForegroundColor Red
        Start-Sleep -Seconds 2
        exit
    }
    Clear-Host
}

# ==========================================
#        SETUP & VALIDATION
# ==========================================

# Ensure folders exist
foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) { 
        New-Item -Path $folder -ItemType Directory -Force | Out-Null 
    }
}

if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

# ==========================================
#           MAIN PROGRAM
# ==========================================

Show-Disclaimer

while ($true) {
    Clear-Host
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "       OGC Email Backup Utility        " -ForegroundColor Yellow
    Write-Host "         https://discord.gg/ogc        " -ForegroundColor Magenta
    Write-Host "         Created by Honest Goat        " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host ""
    Write-Host "Current User: $env:USERNAME" -ForegroundColor DarkGray
    Write-Host "Backup Location: $backupFolder" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "1. BACKUP Email Clients (Outlook, Thunderbird, Proton, eM Client)" -ForegroundColor Green
    Write-Host "2. RESTORE Email Clients from Archive" -ForegroundColor Yellow
    Write-Host "3. Open Backup Folder" -ForegroundColor Cyan
    Write-Host "Q. Quit" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "Select Option"

    switch ($choice) {
        "1" { Backup-EmailClients; Read-Host "Press Enter to continue..." }
        "2" { Restore-EmailClients; Read-Host "Press Enter to continue..." }
        "3" { Invoke-Item $backupFolder }
        "Q" { exit }
        "q" { exit }
        default { Write-Host "Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}