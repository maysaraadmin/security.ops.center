# EDR (Endpoint Detection and Response) System

A lightweight Endpoint Detection and Response (EDR) system that provides real-time monitoring, threat detection, and automated response capabilities for endpoints.

## Features

- **Continuous Endpoint Monitoring**
  - Process monitoring (creation, termination)
  - File system monitoring (changes to critical paths)
  - Network connection monitoring

- **Threat Detection**
  - Rule-based detection engine
  - YARA rule support
  - Regex pattern matching
  - Threshold-based detection

- **Automated Response**
  - Process termination
  - File quarantine
  - Alerting
  - Custom response actions

- **Centralized Management**
  - REST API for agent communication
  - Web-based management interface (coming soon)
  - Alert aggregation and correlation

## Components

- **Agent**: Runs on endpoints to collect and report events
- **Server**: Central server for receiving and processing events
- **Detection Engine**: Analyzes events and identifies threats
- **Response Engine**: Executes automated responses to threats

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements-edr.txt
   ```

2. Configure the EDR server by creating a `config.yaml` file.

3. Start the EDR server:
   ```bash
   python -m edr.server
   ```

4. Install and start the EDR agent on endpoints:
   ```bash
   python -m edr.agent --server http://your-server-address:8000
   ```

## Configuration

### Server Configuration (`config.yaml`)

```yaml
host: 0.0.0.0
port: 8000
database: edr.db
log_level: INFO
jwt_secret: your-secret-key
```

### Agent Configuration

```yaml
server_url: http://your-server-address:8000
endpoint_id: endpoint-001
monitoring:
  process: true
  filesystem: true
  network: true
log_level: INFO
```

## Usage

### Creating Detection Rules

Create YAML or JSON rule files in the `rules` directory:

```yaml
id: suspicious_process
name: Suspicious Process Execution
description: Detects execution of suspicious processes
severity: high
enabled: true
event_types:
  - process_start
regex_patterns:
  - pattern: "(powershell|cmd|wscript|cscript)\\.exe.*\\-enc(odedcommand)?"
    field: "command_line"
    description: "Suspicious command line with encoded command"
```

### API Endpoints

- `POST /api/events` - Submit events from agents
- `GET /api/alerts` - Get alerts
- `GET /api/endpoints` - List monitored endpoints

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Security

Please report any security issues to security@example.com
