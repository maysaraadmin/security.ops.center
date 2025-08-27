# Run this script as Administrator
# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "This script needs to be run as Administrator. Please right-click and select 'Run as Administrator'"
    exit 1
}

# Enable logging for all profiles
$profileList = @('DomainProfile', 'PrivateProfile', 'PublicProfile')
foreach ($fwProfile in $profileList) {
    try {
        # Enable logging for dropped packets and successful connections
        Set-NetFirewallProfile -Profile $fwProfile -LogAllowed $true -LogBlocked $true -LogIgnored $false -LogMaxSizeKilobytes 51200 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -ErrorAction Stop
        
        # Verify the settings
        $settings = Get-NetFirewallProfile -Profile $fwProfile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked, LogIgnored
        Write-Output "Successfully configured $fwProfile":
        $settings | Format-List
    }
    catch {
        Write-Warning "Failed to configure $profile via NetSecurity module. Trying registry method..."
        
        # Registry method as fallback
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        $profileMap = @{
            'DomainProfile' = 'DomainProfile'
            'PrivateProfile' = 'StandardProfile'  # Note: Private profile is called StandardProfile in registry
            'PublicProfile' = 'PublicProfile'
        }
        
        $regProfile = $profileMap[$fwProfile]
        $keyPath = "$regPath\$regProfile\Logging"
        
        try {
            if (-not (Test-Path $keyPath)) {
                New-Item -Path $keyPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $keyPath -Name "LogDroppedPackets" -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $keyPath -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $keyPath -Name "LogFile" -Value "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -Type ExpandString -Force -ErrorAction Stop
            Set-ItemProperty -Path $keyPath -Name "LogFileSize" -Value 51200 -Type DWord -Force -ErrorAction Stop  # 50MB
            
            Write-Output "Successfully configured $profile via registry"
        }
        catch {
            Write-Error "Failed to configure $profile via registry: $_"
        }
    }
}

# Restart the Windows Firewall service to apply changes
try {
    Write-Output "Restarting Windows Firewall service..."
    Restart-Service -Name "mpssvc" -Force -ErrorAction Stop
    Write-Output "Windows Firewall service restarted successfully"
}
catch {
    Write-Warning "Failed to restart Windows Firewall service. Changes might not take effect until next reboot: $_"
}

# Create the log directory if it doesn't exist
$logDir = "$env:SystemRoot\System32\LogFiles\Firewall"
if (-not (Test-Path $logDir)) {
    try {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Output "Created firewall log directory: $logDir"
    }
    catch {
        Write-Error "Failed to create firewall log directory: $_"
    }
}

Write-Output "`nFirewall logging configuration complete. Please restart your SIEM application."
