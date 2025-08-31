# Agentless Collection System

The Agentless Collection System is a component of the SIEM that collects logs and events from various sources without requiring agents to be installed on the target systems. It supports multiple protocols including Syslog, SNMP Traps, and Windows Event Forwarding (WEF).

## Features

- **Syslog Server**: Collects logs from network devices and applications via Syslog (UDP/TCP)
- **SNMP Trap Receiver**: Receives and processes SNMP traps (v1, v2c, v3)
- **Windows Event Forwarding**: Subscribes to Windows Event Collector (WEC) servers
- **Extensible Architecture**: Easy to add new collection protocols
- **Asynchronous Processing**: High-performance event handling
- **Configurable Filtering**: Filter events based on various criteria
- **Secure Communication**: Supports TLS/SSL for encrypted communications

## Configuration

### Main Configuration File

The agentless collector is configured using a YAML file (default: `config/agentless_config.yaml`). Here's an example configuration:

```yaml
# Syslog server configuration
syslog:
  enabled: true
  host: "0.0.0.0"
  port: 514
  protocol: "udp"  # or "tcp"
  log_level: "INFO"

# SNMP Trap configuration
snmp_trap:
  enabled: true
  host: "0.0.0.0"
  port: 162
  version: "2c"  # "1", "2c", or "3"
  community: "public"  # for v1/v2c
  
  # SNMP v3 settings (if version is "3")
  username: "user"
  auth_key: "authpass"
  priv_key: "privpass"

# Windows Event Forwarding configuration
windows_event_forwarding:
  enabled: true
  host: "wec-server.example.com"
  port: 5985  # 5986 for HTTPS
  use_https: true
  verify_ssl: false  # Set to true in production with valid certificates
  
  # Authentication
  auth_type: "ntlm"  # or "kerberos"
  username: "domain\\user"
  password: "password"
  domain: "DOMAIN"  # Optional, for NTLM
  
  # Query to filter events (WQL syntax)
  query: |
    <QueryList>
      <Query Id="0" Path="Security">
        <Select Path="Security">*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]</Select>
      </Query>
    </QueryList>
  
  # Subscription settings
  subscription_expiry: 60  # minutes
  
  # SSL/TLS settings (for HTTPS)
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
  ca_cert: "/path/to/ca.pem"  # Optional, for custom CA
```

## Usage

### Starting the Agentless Collector

```bash
python -m siem.agentless_collector --config /path/to/config.yaml
```

### Command Line Arguments

- `--config`: Path to the configuration file (default: `config/agentless_config.yaml`)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--log-file`: Path to log file (default: logs/agentless_collector.log)

### Testing the Collector

#### Testing Syslog

Send a test syslog message:

```bash
# Linux/macOS
echo "<13>Test message" | nc -u localhost 514

# Windows (PowerShell)
$udpClient = New-Object System.Net.Sockets.UdpClient
$udpClient.Connect("localhost", 514)
$bytes = [System.Text.Encoding]::ASCII.GetBytes("<13>Test message")
$udpClient.Send($bytes, $bytes.Length)
$udpClient.Close()
```

#### Testing SNMP Traps

Send a test SNMP trap:

```bash
# Using snmptrap (Linux/macOS)
snmptrap -v 2c -c public localhost:162 '' 1.3.6.1.4.1.0.1 1.3.6.1.4.1.0.2 s "Test trap message"

# Using PowerShell (Windows)
Send-SNMPTrap -Version 2 -Community public -Destination localhost -Port 162 -OID 1.3.6.1.4.1.0.1 -TrapObjectID 1.3.6.1.4.1.0.2 -String "Test trap message"
```

#### Testing Windows Event Forwarding

1. Configure a Windows Event Collector (WEC) server
2. Set up a subscription to forward events to the collector
3. Configure the agentless collector with the WEC server details
4. Monitor the logs for received events

## Security Considerations

- Always use encrypted communications (TLS/SSL) for production deployments
- Use strong authentication credentials
- Restrict network access to the collector
- Regularly rotate credentials and certificates
- Monitor and audit access to the collector

## Troubleshooting

### Common Issues

1. **Permission Denied** when binding to privileged ports (<1024)
   - Run as administrator/root, or
   - Use higher port numbers (>1024)

2. **Connection Refused**
   - Check if the service is running
   - Verify the port is not blocked by a firewall
   - Check if another service is using the same port

3. **Authentication Failures**
   - Verify credentials are correct
   - Check domain/username format (DOMAIN\\user or user@DOMAIN)
   - Ensure the account has the necessary permissions

4. **Certificate Errors**
   - Verify certificate paths are correct
   - Check certificate permissions
   - Ensure the certificate is valid and not expired

## Extending the Collector

To add a new protocol:

1. Create a new module in `siem/collectors/`
2. Implement the protocol-specific logic
3. Update the `AgentlessCollector` class to support the new protocol
4. Add configuration options to `agentless_config.yaml`
5. Update the documentation

## License

[Your License Here]

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
