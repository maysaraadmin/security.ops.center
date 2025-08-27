# Script to enable Security log access for the SIEM application
# Must be run as Administrator

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator. Please right-click and select 'Run as Administrator'." -ForegroundColor Red
    exit 1
}

# Define the privilege to add
$privilege = "SeSecurityPrivilege"

# Get the current user
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Function to grant a privilege
function Grant-Privilege {
    param (
        [string]$User,
        [string]$Privilege
    )
    
    $tmp = [System.IO.Path]::GetTempFileName()
    
    # Export current user rights
    secedit /export /cfg $tmp /areas USER_RIGHTS
    
    # Find the privilege in the file
    $setting = Select-String -Path $tmp -Pattern "^$Privilege"
    $newLine = ""
    
    if ($null -eq $setting) {
        # Add new privilege
        $newLine = "$Privilege = $User"
        Add-Content -Path $tmp -Value $newLine
    }
    else {
        # Check if user already has the privilege
        $users = $setting.Line -split "=" | Select-Object -Last 1 | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        $userList = $users -split "," | ForEach-Object { $_.Trim() }
        
        if ($userList -notcontains $User) {
            # Add user to the privilege
            $newUsers = ($userList + $User) -join ","
            $newLine = "$Privilege = $newUsers"
            (Get-Content $tmp) -replace [regex]::Escape($setting.Line), $newLine | Set-Content $tmp
        }
        else {
            Write-Host "User $User already has the $Privilege privilege." -ForegroundColor Yellow
            return $true
        }
    }
    
    if ($newLine) {
        # Import the modified settings
        secedit /configure /db secedit.sdb /cfg $tmp /areas USER_RIGHTS
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully granted $Privilege to $User" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "Failed to grant $Privilege to $User" -ForegroundColor Red
            return $false
        }
    }
    
    Remove-Item $tmp -Force
    return $false
}

# Grant the privilege
$success = Grant-Privilege -User $currentUser -Privilege $privilege

if ($success) {
    Write-Host "`nSecurity log access has been configured. Please log off and log back in for the changes to take effect." -ForegroundColor Green
    Write-Host "After logging back in, restart the SIEM application." -ForegroundColor Green
}
else {
    Write-Host "`nFailed to configure security log access. Please check the error messages above." -ForegroundColor Red
}

# Also enable the Windows Firewall logging
$firewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall"

# Create the firewall log directory if it doesn't exist
if (-not (Test-Path $firewallLogPath)) {
    try {
        New-Item -Path $firewallLogPath -ItemType Directory -Force | Out-Null
        Write-Host "Created firewall log directory: $firewallLogPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to create firewall log directory: $_" -ForegroundColor Red
    }
}

# Enable firewall logging for all profiles
$fwProfiles = @('DomainProfile', 'PrivateProfile', 'PublicProfile')
$changesMade = $false

foreach ($fwProfile in $fwProfiles) {
    try {
        $current = Get-NetFirewallProfile -Name $fwProfile -ErrorAction Stop
        
        if (-not $current.LogAllowed -or -not $current.LogBlocked -or $current.LogMaxSizeKilobytes -lt 51200) {
            Set-NetFirewallProfile -Name $fwProfile -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 51200 -LogFileName "$firewallLogPath\pfirewall.log" -ErrorAction Stop
            Write-Host "Enabled firewall logging for $fwProfile profile" -ForegroundColor Green
            $changesMade = $true
        }
        else {
            Write-Host "Firewall logging already enabled for $fwProfile profile" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Failed to configure firewall logging for $fwProfile profile: $_" -ForegroundColor Red
    }
}

# Restart the firewall service if changes were made
if ($changesMade) {
    try {
        Restart-Service -Name mpssvc -Force -ErrorAction Stop
        Write-Host "Restarted Windows Firewall service" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to restart Windows Firewall service: $_" -ForegroundColor Red
        Write-Host "Please restart the computer for all changes to take effect." -ForegroundColor Yellow
    }
}

Write-Host "`nConfiguration complete. Please restart the SIEM application." -ForegroundColor Cyan
