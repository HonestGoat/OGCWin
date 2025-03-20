# Define paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$bin = "$parentFolder\bin"
$ogcScript = "$bin\ogc.ps1"
$profilePath = "$HOME\Documents\WindowsPowerShell\profile.ps1"
$urlsConfigPath = "$parentFolder\configs\urls.cfg"

# Function to load URLs from urls.cfg
function Get-Url {
    param ($key)
    $configData = Get-Content -Path $urlsConfigPath | Where-Object { $_ -match "=" }
    $urlMap = @{}

    foreach ($line in $configData) {
        $parts = $line -split "=", 2
        if ($parts.Count -eq 2) {
            $urlMap[$parts[0].Trim()] = $parts[1].Trim()
        }
    }

    if ($urlMap.ContainsKey($key)) {
        return $urlMap[$key]
    } else {
        Write-Host "Warning: URL key '$key' not found in urls.cfg" -ForegroundColor Red
        return $null
    }
}

# Ensure the bin folder exists
if (!(Test-Path $bin)) {
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
}

# Get the URL for the OGC command script
$ogcUrl = Get-Url "OGCommand"
if ($null -eq $ogcUrl) {
    Write-Host "Error: Unable to find download URL for OGC Command setup." -ForegroundColor Red
    exit
}

# Download the latest OGC command script
Write-Host "Downloading OGCommand..."
try {
    Invoke-WebRequest -Uri $ogcUrl -OutFile $ogcScript -ErrorAction Stop
    Write-Host "Downloaded OGCommand successfully."
} catch {
    Write-Host "Error: Failed to download OGCommand." -ForegroundColor Red
    exit
}

# Add the bin folder to the system PATH if not already there
$envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($envPath -notmatch [regex]::Escape($bin)) {
    [System.Environment]::SetEnvironmentVariable("Path", "$envPath;$bin", "Machine")
    Write-Host "Added $bin to system PATH."
}

# Ensure PowerShell profile exists
if (!(Test-Path $profilePath)) {
    New-Item -ItemType File -Path $profilePath -Force | Out-Null
}

# Set alias in PowerShell profile
$aliasCommand = "`nSet-Alias -Name ogc -Value `"$ogcScript`""
if (!(Select-String -Path $profilePath -Pattern "Set-Alias -Name ogc")) {
    Add-Content -Path $profilePath -Value $aliasCommand -Force
    Write-Host "Added 'OGCommand' to PowerShell profile."
}

Write-Host "OGCommand installed. Opening new window to apply changes."
Start-Sleep -Seconds 3
Start-Process "powershell" -ArgumentList "-NoExit", "-Command `"`$Host.UI.RawUI.BackgroundColor = 'Black'; `$Host.UI.RawUI.WindowTitle = 'OGCommand'; cls`"" -WindowStyle Normal
Start-Sleep -Seconds 2
exit