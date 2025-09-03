# SIEM Endpoint Agent

A lightweight agent for collecting and forwarding system logs and security events to a SIEM server.

## Features

- **Windows Event Log Collection**: Collects security, system, and application logs from Windows Event Log
- **Sysmon Integration**: Captures detailed system activity using Microsoft Sysinternals Sysmon
- **System Information**: Gathers comprehensive system inventory and configuration data
- **Secure Communication**: Supports TLS-encrypted communication with the SIEM server
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Configurable**: Highly configurable through YAML configuration files
- **Service Integration**: Can be installed as a system service/daemon

## Requirements

- Python 3.7 or higher
- Windows, Linux, or macOS
- Administrator/root privileges for full functionality

## Installation

### Prerequisites

1. Install Python 3.7 or higher from [python.org](https://www.python.org/downloads/)
2. Ensure pip is up to date:
   ```bash
   python -m pip install --upgrade pip
   ```

### Quick Start

1. Clone the repository or download the source code
2. Navigate to the `siem/endpoint_agent` directory
3. Install the agent in development mode:
   ```bash
   pip install -e .
   ```

### Full Installation

For a complete installation as a system service:

1. Open a terminal/command prompt as administrator/root
2. Run the installer:
   ```bash
   python install.py --siem-server your.siem.server.com --siem-port 514
   ```

### Command Line Options

The installer supports the following options:

- `--siem-server`: SIEM server hostname or IP (default: siem.example.com)
- `--siem-port`: SIEM server port (default: 514)
- `--no-tls`: Disable TLS for communication with the SIEM server
- `--no-verify-ssl`: Disable SSL certificate verification
- `--no-service`: Do not install as a service (manual execution only)
- `--uninstall`: Uninstall the agent

## Configuration

The agent is configured using a YAML file located at:

- **Windows**: `C:\ProgramData\SIEM\endpoint_agent\config.yaml`
- **Linux**: `/etc/siem/endpoint_agent/config.yaml`
- **macOS**: `/Library/Application Support/SIEM/endpoint_agent/config.yaml`

### Example Configuration

```yaml
# SIEM Server Configuration
siem_server: "your.siem.server.com"  # SIEM server hostname or IP
siem_port: 514                      # SIEM server port
use_tls: true                       # Use TLS for communication
verify_ssl: true                    # Verify SSL/TLS certificates

# Logging Configuration
logging:
  level: INFO                       # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "/var/log/siem/siem_agent.log"
  max_size: 10                      # Max log file size in MB
  backup_count: 5                   # Number of backup logs to keep

# Collector Configuration
collectors:
  windows_events:
    enabled: true
    channels:                       # Windows Event Log channels to monitor
      - Security
      - System
      - Application
    
  sysmon:
    enabled: true                   # Requires Sysmon to be installed
    
  system_info:
    enabled: true
    interval: 3600                 # Collect system info every hour (in seconds)

# Advanced Settings
advanced:
  batch_size: 50                   # Number of events to send in each batch
  max_retries: 3                   # Maximum number of retries for failed sends
  retry_delay: 5                   # Delay between retries (in seconds)
  heartbeat_interval: 300          # Send heartbeat every 5 minutes (in seconds)
  cache_dir: "/var/cache/siem"     # Directory for temporary files
```

## Usage

### Running the Agent

#### As a Service

- **Windows**:
  ```
  net start SIEMEndpointAgent
  ```

- **Linux/macOS**:
  ```bash
  systemctl start siem-endpoint-agent
  ```

#### Manually

```bash
python -m siem.endpoint_agent --config /path/to/config.yaml
```

### Testing the Agent

A test script is provided to verify the agent's functionality:

```bash
python test_agent.py --all
```

Available test options:

- `--collectors`: Test all collectors
- `--communication`: Test communication with the SIEM server
- `--system-info`: Test system information collection
- `--windows-events`: Test Windows Event Log collection (Windows only)
- `--sysmon`: Test Sysmon event collection (Windows only)
- `--all`: Run all tests
- `--config`: Path to configuration file
- `--duration`: Test duration in seconds (default: 30)
- `--debug`: Enable debug logging

## Collectors

### Windows Event Log Collector

Collects events from Windows Event Log channels. Supports filtering by event ID, level, and source.

### Sysmon Collector

Collects detailed system activity events from Microsoft Sysinternals Sysmon. Requires Sysmon to be installed.

### System Information Collector

Gathers comprehensive system inventory and configuration data, including:

- Hardware information
- Operating system details
- Installed software
- Network configuration
- Running processes
- User accounts
- System performance metrics

## Security Considerations

- The agent requires administrator/root privileges to access certain system logs and information
- Communication with the SIEM server is encrypted using TLS by default
- Sensitive information (e.g., credentials) should not be stored in the configuration file
- Regular security audits of the agent's configuration and permissions are recommended

## Troubleshooting

### Logs

Check the agent's log file for errors and debugging information:

- **Windows**: `C:\ProgramData\SIEM\logs\siem_agent.log`
- **Linux/macOS**: `/var/log/siem/siem_agent.log`

### Common Issues

1. **Permission Denied Errors**
   - Ensure the agent is running with administrator/root privileges
   - Check file and directory permissions

2. **Connection Issues**
   - Verify network connectivity to the SIEM server
   - Check firewall rules and network policies
   - Ensure the SIEM server is running and accessible

3. **Missing Dependencies**
   - Run `pip install -r requirements.txt` to install required packages
   - On Windows, ensure the Visual C++ Redistributable is installed

## Development

### Building from Source

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install development dependencies:
   ```bash
   pip install -e .[dev]
   ```

### Running Tests

```bash
# Run unit tests
pytest tests/

# Run with coverage report
pytest --cov=siem.endpoint_agent tests/
```

### Building Packages

```bash
# Build a wheel package
python setup.py bdist_wheel

# Build a Windows installer (requires NSIS)
python setup.py bdist_wininst
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## Support

For support, please open an issue on our [GitHub repository](https://github.com/your-org/siem-endpoint-agent/issues).

## Acknowledgments

- Microsoft Sysinternals for Sysmon
- Python core developers and the open-source community
- All contributors who have helped improve this project
