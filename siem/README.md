# SIEM Dashboard

A unified security dashboard for monitoring system events and metrics.

## Features

- Real-time event monitoring
- System resource usage metrics (CPU, memory, disk)
- Interactive charts and visualizations
- Responsive design for all devices
- Sample data generation for testing

## Prerequisites

- Python 3.7+
- Windows OS (for Sysmon event log access)
- Required Python packages (install with `pip install -r requirements.txt`)

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. (Optional) Install Sysmon for Windows event monitoring

## Running the Dashboard

### Windows
Double-click on `start_siem_dashboard.bat` or run:
```
python -m siem.unified_dashboard_new
```

### Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

## Development

### Project Structure

- `siem/unified_dashboard_new.py` - Main dashboard application
- `siem/templates/` - HTML templates
- `siem/static/` - Static files (CSS, JS, images)

### Adding New Features

1. Create a new branch for your feature
2. Make your changes
3. Test thoroughly
4. Submit a pull request

## Troubleshooting

- If you see permission errors, try running as Administrator
- Check `siem_dashboard.log` for error messages
- Ensure Sysmon is properly installed if using Windows event logs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
