# Compliance Module Integration Guide

This document provides detailed instructions for integrating the Compliance Module into the SIEM application, including setup, configuration, and usage.

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Integration Steps](#integration-steps)
6. [API Reference](#api-reference)
7. [Troubleshooting](#troubleshooting)
8. [License](#license)

## Overview

The Compliance Module provides a comprehensive solution for managing and enforcing compliance with various regulatory standards (e.g., GDPR, HIPAA, PCI DSS) within the SIEM application. It includes features for compliance checking, reporting, and alerting.

## Prerequisites

- Python 3.8+
- SIEM Core Application
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone the SIEM repository (if not already done):
   ```bash
   git clone <repository-url>
   cd siem
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create the necessary directories:
   ```bash
   mkdir -p config templates reports
   ```

## Configuration

### Configuration File

Create a configuration file at `config/compliance_config.ini` with the following structure:

```ini
[compliance]
; General settings
auto_checks = true
auto_generate_report = true
default_report_format = pdf
report_dir = ./reports

; Email notifications
email_notifications = false
email_recipient = your.email@example.com
smtp_server = smtp.example.com
smtp_port = 587
smtp_user = your_username
smtp_use_tls = true
```

### Environment Variables

You can also configure the module using environment variables:

```bash
export COMPLIANCE_AUTO_CHECKS=true
export COMPLIANCE_REPORT_FORMAT=pdf
export COMPLIANCE_REPORT_DIR=./reports
# ... etc.
```

## Integration Steps

### 1. Initialize the Compliance Manager

In your main application, import and initialize the `ComplianceManager`:

```python
from compliance.manager import ComplianceManager

# Initialize with custom paths
compliance_manager = ComplianceManager(
    templates_dir='./templates',
    reports_dir='./reports',
    config_file='./config/compliance_config.ini'
)
```

### 2. Add the Compliance View to Your UI

If you're using Tkinter for your UI, you can add the Compliance View like this:

```python
from views.compliance_view import ComplianceView

# Assuming you have a notebook or frame for the compliance tab
compliance_tab = ttk.Frame(notebook)
notebook.add(compliance_tab, text="Compliance")

# Create the compliance view
compliance_view = ComplianceView(
    parent=compliance_tab,
    compliance_manager=compliance_manager
)
compliance_view.pack(fill=tk.BOTH, expand=True)
```

### 3. Schedule Compliance Checks

To schedule automatic compliance checks:

```python
import threading
import time

def schedule_compliance_checks(interval_hours=24):
    """Run compliance checks at regular intervals."""
    while True:
        compliance_manager.check_compliance()
        time.sleep(interval_hours * 3600)  # Convert hours to seconds

# Start the scheduler in a separate thread
scheduler_thread = threading.Thread(
    target=schedule_compliance_checks,
    daemon=True
)
scheduler_thread.start()
```

### 4. Handle Compliance Events

You can listen for compliance events and take appropriate actions:

```python
def handle_compliance_event(event):
    """Handle compliance events."""
    if event['type'] == 'compliance_check_completed':
        if event['status'] == 'success':
            print(f"Compliance check completed: {event['message']}")
        else:
            print(f"Compliance check failed: {event['error']}")
    elif event['type'] == 'report_generated':
        print(f"Report generated: {event['report_path']}")

# Register the event handler
compliance_manager.add_event_listener(handle_compliance_event)
```

## API Reference

### ComplianceManager

#### Methods

- `check_compliance(standard=None)`
  - Run compliance checks for all standards or a specific standard.
  - **Parameters:**
    - `standard` (str, optional): The standard to check. If None, checks all standards.
  - **Returns:**
    - dict: The compliance check results.

- `generate_report(standard, format='pdf')`
  - Generate a compliance report.
  - **Parameters:**
    - `standard` (str): The standard to generate a report for.
    - `format` (str): The report format ('pdf', 'html', or 'json').
  - **Returns:**
    - dict: Report generation status and path.

- `get_available_standards()`
  - Get a list of available compliance standards.
  - **Returns:**
    - list: List of standard names.

- `get_compliance_status(standard=None)`
  - Get the current compliance status.
  - **Parameters:**
    - `standard` (str, optional): The standard to get status for. If None, gets status for all standards.
  - **Returns:**
    - dict: The compliance status.

### ComplianceView

#### Methods

- `check_compliance()`
  - Run compliance checks and update the UI.

- `generate_report_dialog()`
  - Show the report generation dialog.

- `refresh_data()`
  - Refresh the compliance data in the UI.

## Troubleshooting

### Common Issues

1. **Templates not loading**
   - Ensure the `templates` directory exists and contains valid JSON template files.
   - Check file permissions.

2. **Report generation fails**
   - Verify that the `reports` directory exists and is writable.
   - Check that the required report generation tools are installed (e.g., `wkhtmltopdf` for PDF generation).

3. **Email notifications not working**
   - Verify SMTP server settings.
   - Check for firewall or network issues.
   - Ensure the email server accepts connections on the specified port.

### Logging

Enable debug logging for more detailed information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
