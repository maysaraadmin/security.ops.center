# Source Computer Configuration Script
# Run this as Administrator on each Windows machine that will forward events

param(
    [Parameter(Mandatory=$true)]
    [string]$SIEMServer,
    
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [PSCredential]$Credential
)

# Configure WinRM
Write-Host "Configuring WinRM..."
winrm quickconfig -q
winrm set winrm/config/service '@{AllowRemoteAccess="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# Add SIEM server to Event Log Readers group
try {
    $computer = $env:COMPUTERNAME
    $group = [ADSI]"WinNT://$computer/Event Log Readers,group"
    $group.Add("WinNT://$DomainName/$SIEMServer$")
    Write-Host "Successfully added $SIEMServer to Event Log Readers group"
} catch {
    Write-Warning "Failed to add to Event Log Readers group: $_"
}

# Configure Windows Event Forwarding
$subscriptionManager = @{
    Server = "http://$SIEMServer`:5985/wsman/SubscriptionManager/WEC"
    ConfigMode = "SourceInitiated"
    Address = "*"
    Enabled = $true
    DeliveryMode = "Push"
    ReadExistingEvents = $true
}

# Create registry keys for source initiated subscription
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

$subscriptionUrl = "Server=$($subscriptionManager.Server),Refresh=60"
Set-ItemProperty -Path $registryPath -Name "1" -Value $subscriptionUrl -Type String

# Configure Windows Firewall
Write-Host "Configuring Windows Firewall..."
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

Write-Host "`nSource computer configuration complete!"
Write-Host "To verify, run: Test-WSMan -ComputerName $SIEMServer"
