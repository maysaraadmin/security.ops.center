# Windows Event Collector Setup Script
# Run this as Administrator on the SIEM server

# Install required Windows features
Write-Host "Installing Windows Event Collector feature..."
Install-WindowsFeature -Name Event-Forwarding -IncludeManagementTools -ErrorAction Stop

# Configure Windows Event Collector
Write-Host "Configuring Windows Event Collector..."
wecutil qc /q /f

# Configure WinRM for remote management
Write-Host "Configuring WinRM..."
winrm quickconfig -q
winrm set winrm/config/service '@{AllowRemoteAccess="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# Create a sample subscription
Write-Host "Creating sample subscription..."
$subscriptionXML = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>SIEM-Collection</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>SIEM Event Collection</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Custom</ConfigurationMode>
    <Delivery Mode="Push">
        <PushSettings>
            <Heartbeat Interval="60000"/>
        </PushSettings>
    </Delivery>
    <Query>
        <![CDATA[<QueryList>
            <Query Id="0" Path="Security">
                <Select Path="Security">*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]</Select>
            </Query>
            <Query Id="1" Path="System">
                <Select Path="System">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
            </Query>
        </QueryList>]]>
    </Query>
    <ReadExistingEvents>true</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
    <PublishToEventLog>true</PublishToEventLog>
</Subscription>
"@

$subscriptionPath = "$env:TEMP\wec_subscription.xml"
$subscriptionXML | Out-File -FilePath $subscriptionPath -Encoding utf8
wecutil cs $subscriptionPath

# Configure firewall rules
Write-Host "Configuring Windows Firewall..."
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" `
    -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow

Write-Host "`nWindows Event Collector setup complete!"
Write-Host "Next steps:"
Write-Host "1. Configure source computers to forward events"
Write-Host "2. Add source computers to the Event Log Readers group"
Write-Host "3. Test the connection using: Test-WSMan -ComputerName <SIEM_IP>"
