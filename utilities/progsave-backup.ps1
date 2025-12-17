# ==========================================
#    OGC Save Game & Program Data Utility
#              By Honest Goat
#               Version: 0.3
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
$backupFolder = "$parentFolder\backups\ProgSaveBackup"
$tempFolder = "$backupFolder\TempStaging"

# User Data Paths
# DO I NEED TO ADD APPDATA\ROAMING
$userProfile = $env:USERPROFILE
$documents = [Environment]::GetFolderPath("MyDocuments")
$appData = $env:APPDATA
$localAppData = $env:LOCALAPPDATA
$localLow = Join-Path $userProfile "AppData\LocalLow"
$savedGames = Join-Path $userProfile "Saved Games"

# Exclusion Lists (Critical to avoid backing up OS garbage)
# We want game saves and config files, NOT Windows system files.
$exclusions = @(
    "Microsoft", "Windows", "Temp", "Packages", "DiagTrack", "Diagnosis", 
    "Event Viewer", "CrashDumps", "NVIDIA", "AMD", "Intel", "Google", "Mozilla", 
    "Opera Software", "BraveSoftware", "Adobe", "OneDrive", "Skype", "Teams"
)

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

function Close-GameProcesses {
    Write-Log "Checking for running game processes..." "INFO"
    $processes = @("steam", "EpicGamesLauncher", "GalaxyClient", "Battle.net", "Origin", "Uplay", "UbisoftConnect")
    
    foreach ($p in $processes) {
        if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
            Write-Log "Killing process: $p to release file locks." "WARNING"
            Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }
    }
    Write-Log "Game launcher processes terminated." "SUCCESS"
}

function Copy-Filtered {
    param (
        [string]$Source,
        [string]$Destination,
        [string]$TypeDescription
    )
    
    if (-not (Test-Path $Source)) { return }
    
    Write-Log "Scanning $TypeDescription..." "INFO"
    
    # Get all subfolders in the source directory
    $subFolders = Get-ChildItem -Path $Source -Directory -ErrorAction SilentlyContinue
    
    foreach ($folder in $subFolders) {
        # Check if folder name is in exclusion list (Exact match or Partial match depending on strictness)
        $isExcluded = $false
        foreach ($ex in $exclusions) {
            if ($folder.Name -like "*$ex*") { $isExcluded = $true; break }
        }

        if (-not $isExcluded) {
            $destSub = Join-Path $Destination $folder.Name
            Write-Log "  -> Backing up: $($folder.Name)" "INFO"
            try {
                if (-not (Test-Path $destSub)) { New-Item -ItemType Directory -Path $destSub -Force | Out-Null }
                Copy-Item -Path "$($folder.FullName)\*" -Destination $destSub -Recurse -Force -ErrorAction Continue
            } catch {
                Write-Log "  -> Failed to copy $($folder.Name): $_" "ERROR"
            }
        }
    }
}

function Backup-GameSaves {
    param ()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmm"
    $archiveName = "GameSaves_Backup_$timestamp.zip"
    $finalZipPath = Join-Path $backupFolder $archiveName

    # 1. Clean Staging
    if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    Write-Log "Starting Game Save Backup..." "INFO"
    Close-GameProcesses

    # 2. Backup "Saved Games" Folder (Entirely)
    if (Test-Path $savedGames) {
        Write-Log "Backing up User Saved Games folder..." "INFO"
        $dest = Join-Path $tempFolder "User_SavedGames"
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item -Path "$savedGames\*" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 3. Backup Documents (My Games & Others)
    # We don't want all Documents (Word files etc), just game folders.
    # Common convention: "My Games" folder, or specific Publisher folders.
    if (Test-Path $documents) {
        Write-Log "Scanning Documents for Game Saves..." "INFO"
        $docStaging = Join-Path $tempFolder "Documents"
        New-Item -ItemType Directory -Path $docStaging -Force | Out-Null
        
        # Always grab "My Games"
        $myGames = Join-Path $documents "My Games"
        if (Test-Path $myGames) {
             Write-Log "  -> Backing up 'My Games'..." "INFO"
             $dest = Join-Path $docStaging "My Games"
             New-Item -ItemType Directory -Path $dest -Force | Out-Null
             Copy-Item -Path "$myGames\*" -Destination $dest -Recurse -Force
        }

        # Attempt to grab other folders in Documents that look like games, avoiding Windows/Office stuff
        # We re-use Copy-Filtered logic here but applied to Documents root
        Copy-Filtered -Source $documents -Destination $docStaging -TypeDescription "Documents Root (Filtered)"
    }

    # 4. AppData Scans (Roaming, Local, LocalLow)
    # These contain huge amounts of OS junk. We use strict filtering here.
    
    $roamingStaging = Join-Path $tempFolder "AppData_Roaming"
    New-Item -ItemType Directory -Path $roamingStaging -Force | Out-Null
    Copy-Filtered -Source $appData -Destination $roamingStaging -TypeDescription "AppData Roaming"

    $localStaging = Join-Path $tempFolder "AppData_Local"
    New-Item -ItemType Directory -Path $localStaging -Force | Out-Null
    Copy-Filtered -Source $localAppData -Destination $localStaging -TypeDescription "AppData Local"

    $localLowStaging = Join-Path $tempFolder "AppData_LocalLow"
    New-Item -ItemType Directory -Path $localLowStaging -Force | Out-Null
    # LocalLow is almost exclusively Unity game saves, so we can be less strict or just grab it all except Microsoft
    Copy-Filtered -Source $localLow -Destination $localLowStaging -TypeDescription "AppData LocalLow"

    # 5. Compress to Archive
    try {
        Write-Log "Compressing backup archive..." "INFO"
        Show-Progress "Compressing Data"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolder, $finalZipPath)
        
        if (Test-Path $finalZipPath) {
            $size = "{0:N2} MB" -f ((Get-Item $finalZipPath).Length / 1MB)
            Write-Log "Backup Archive Created: $archiveName ($size)" "SUCCESS"
        }
    } catch {
        Write-Log "Compression failed: $_" "ERROR"
        Write-Log "Data left uncompressed in $tempFolder" "WARNING"
        return
    }

    # 6. Cleanup
    Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Backup Complete." "SUCCESS"
}

function Restore-GameSaves {
    param ()
    
    # 1. Find Backups
    $zips = Get-ChildItem -Path $backupFolder -Filter "*.zip" | Sort-Object LastWriteTime -Descending
    
    if ($zips.Count -eq 0) {
        Write-Log "No backups found." "ERROR"
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

    $confirm = Read-Host "WARNING: This will overwrite existing save files. Type 'RESTORE' to confirm"
    if ($confirm -ne "RESTORE") { return }

    Close-GameProcesses

    # 2. Extract
    if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Log "Extracting archive..." "INFO"
    try {
        Expand-Archive -Path $targetZip.FullName -DestinationPath $tempFolder -Force -ErrorAction Stop
    } catch {
        Write-Log "Extraction failed: $_" "ERROR"
        return
    }

    # 3. Restore Files
    Write-Log "Restoring files..." "INFO"

    # Restore Saved Games
    $srcSaved = Join-Path $tempFolder "User_SavedGames"
    if (Test-Path $srcSaved) {
        Write-Log "Restoring Saved Games folder..." "INFO"
        Copy-Item -Path "$srcSaved\*" -Destination $savedGames -Recurse -Force
    }

    # Restore Documents
    $srcDocs = Join-Path $tempFolder "Documents"
    if (Test-Path $srcDocs) {
        Write-Log "Restoring Documents game folders..." "INFO"
        Copy-Item -Path "$srcDocs\*" -Destination $documents -Recurse -Force
    }

    # Restore AppData (Roaming)
    $srcRoaming = Join-Path $tempFolder "AppData_Roaming"
    if (Test-Path $srcRoaming) {
        Write-Log "Restoring AppData Roaming..." "INFO"
        Copy-Item -Path "$srcRoaming\*" -Destination $appData -Recurse -Force
    }

    # Restore AppData (Local)
    $srcLocal = Join-Path $tempFolder "AppData_Local"
    if (Test-Path $srcLocal) {
        Write-Log "Restoring AppData Local..." "INFO"
        Copy-Item -Path "$srcLocal\*" -Destination $localAppData -Recurse -Force
    }

    # Restore AppData (LocalLow)
    $srcLocalLow = Join-Path $tempFolder "AppData_LocalLow"
    if (Test-Path $srcLocalLow) {
        Write-Log "Restoring AppData LocalLow..." "INFO"
        Copy-Item -Path "$srcLocalLow\*" -Destination $localLow -Recurse -Force
    }

    # Cleanup
    Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Restore Complete." "SUCCESS"
}

function Show-Disclaimer {
    Clear-Host
    Write-Color "===================================================" -ForegroundColor Red
    Write-Color "           !!! IMPORTANT DISCLAIMER !!!            " -ForegroundColor Red
    Write-Color "===================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "You are about to run a Save Game Backup/Restore operation." -ForegroundColor Yellow
    Write-Host "This utility attempts to backup game saves from AppData and Documents." -ForegroundColor Yellow
    Write-Host "It EXCLUDES Microsoft/Windows system folders to prevent OS corruption." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "By proceeding, you acknowledge and agree that:" -ForegroundColor Cyan
    Write-Host "1. You assume ALL RISK of potential data loss or corruption." -ForegroundColor Gray
    Write-Host "2. Some game saves stored in non-standard locations may be missed." -ForegroundColor Gray
    Write-Host "3. The author (Honest Goat) is not liable for lost save files." -ForegroundColor Gray
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
    Write-Host "    OGC Saves and Settings Utility     " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host ""
    Write-Host "Current User: $env:USERNAME" -ForegroundColor DarkGray
    Write-Host "Backup Location: $backupFolder" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "1. BACKUP Game Saves & Program Settings" -ForegroundColor Green
    Write-Host "2. RESTORE from Archive" -ForegroundColor Yellow
    Write-Host "3. Open Backup Folder" -ForegroundColor Cyan
    Write-Host "Q. Quit" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "Select Option"

    switch ($choice) {
        "1" { Backup-GameSaves; Read-Host "Press Enter to continue..." }
        "2" { Restore-GameSaves; Read-Host "Press Enter to continue..." }
        "3" { Invoke-Item $backupFolder }
        "Q" { exit }
        "q" { exit }
        default { Write-Host "Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}