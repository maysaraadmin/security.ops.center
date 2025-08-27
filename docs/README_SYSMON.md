# SIEM with Sysmon Integration

This SIEM (Security Information and Event Management) system integrates with Windows Sysmon to provide detailed system monitoring and event logging.

## Prerequisites

- Windows operating system
- Python 3.7+
- Administrator privileges (required for Sysmon installation)

## Installation

1. **Install Python Dependencies**:
   ```
   pip install pywin32 python-dateutil
   ```

2. **Install Sysmon**:
   - Open Command Prompt as Administrator
   - Navigate to the SIEM directory
   - Run: `python install_sysmon.py`
   - This will download and install Sysmon with a default configuration

3. **Verify Sysmon Installation**:
   - Run: `python check_sysmon.py`
   - This will check if Sysmon is installed and running, and start it if necessary

## Running the SIEM

1. Start the SIEM application:
   ```
   python main.py
   ```

2. The application will start collecting and displaying events from various sources including:
   - Windows Security logs
   - System logs
   - Application logs
   - Sysmon logs
   - And more...

## Understanding Sysmon Events

The SIEM processes and displays Sysmon events with detailed information. Here are some of the key event types:

- **Event ID 1**: Process creation
- **Event ID 3**: Network connections
- **Event ID 7**: Image loaded
- **Event ID 8**: CreateRemoteThread API calls
- **Event ID 10**: Process access
- **Event ID 11**: File creation
- **Event ID 12-14**: Registry events
- And many more...

## Customizing Sysmon Configuration

To customize what events Sysmon collects:

1. Create a custom Sysmon configuration file (XML format)
2. Apply it using: `Sysmon64.exe -c your_config.xml`
3. Restart the Sysmon service: `net stop Sysmon && net start Sysmon`

## Troubleshooting

- If events aren't showing up, ensure the Sysmon service is running
- Check the Windows Event Viewer for Sysmon logs under "Applications and Services Logs/Microsoft/Windows/Sysmon/Operational"
- Run the SIEM with administrator privileges if you encounter permission issues

## Security Considerations

- The default Sysmon configuration is designed for general monitoring
- Review and customize the configuration based on your security requirements
- Monitor the SIEM logs for any suspicious activities

## License

This project is open source and available under the MIT License.
