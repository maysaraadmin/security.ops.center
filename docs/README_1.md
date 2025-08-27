# Compliance Module

The Compliance Module is a comprehensive solution for managing and enforcing regulatory compliance within the SIEM system. It provides tools for checking compliance against various standards, generating reports, and maintaining an audit trail.

## Features

- **Multiple Compliance Standards**: Support for GDPR, HIPAA, PCI DSS, and SOX out of the box
- **Custom Templates**: Easily add new compliance standards using JSON templates
- **Automated Checks**: Schedule regular compliance checks
- **Detailed Reporting**: Generate reports in multiple formats (JSON, HTML, PDF)
- **Alerting**: Get notified of compliance violations
- **Audit Trail**: Maintain a complete history of compliance activities

## Installation

1. Ensure you have Python 3.7+ installed
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```python
from compliance.manager import ComplianceManager
from models.database import Database

# Initialize the database
db = Database("siem.db")

# Create a ComplianceManager instance
manager = ComplianceManager(db)

# Check compliance with all standards
results = manager.check_compliance()

# Generate a report for a specific standard
report = manager.generate_report("gdpr", "pdf")

# Export the report to a file
manager.export_report(report, "gdpr_compliance_report.pdf")
```

### Running the Demo

A demo script is available to demonstrate the module's capabilities:

```
python examples/compliance_demo.py
```

### Running Tests

To run the test suite:

```
python -m unittest tests/test_compliance.py -v
```

## Compliance Standards

The module includes templates for the following standards:

- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **PCI DSS**: Payment Card Industry Data Security Standard
- **SOX**: Sarbanes-Oxley Act

### Adding a New Standard

To add a new compliance standard:

1. Create a new JSON file in the `compliance/templates` directory
2. Define the standard's requirements, controls, and reporting guidelines
3. The standard will be automatically loaded when the ComplianceManager starts

Example template structure:

```json
{
    "standard": "CUSTOM_STANDARD",
    "version": "1.0",
    "description": "Description of the standard",
    "requirements": [
        {
            "id": "REQ-001",
            "description": "Requirement description",
            "controls": ["control1", "control2"]
        }
    ],
    "reporting_requirements": {
        "report_types": {
            "periodic": {
                "frequency": "quarterly",
                "sections": ["executive_summary", "findings", "recommendations"]
            }
        }
    }
}
```

## API Reference

### ComplianceManager

The main class for managing compliance operations.

#### Methods

- `check_compliance(standard=None, **kwargs)`: Check compliance with the specified standard(s)
- `generate_report(standard, format='json', **kwargs)`: Generate a compliance report
- `export_report(report_data, output_path)`: Export a report to a file
- `get_available_standards()`: Get a list of available compliance standards
- `get_standard_template(standard)`: Get the template for a specific standard
- `add_alert_callback(callback)`: Register a callback for compliance alerts
- `remove_alert_callback(callback)`: Unregister an alert callback
- `get_compliance_status(standard=None)`: Get the current compliance status

## Integration

The Compliance Module can be integrated with other SIEM components:

- **SIEM Dashboard**: Display compliance status and alerts
- **Incident Response**: Trigger workflows based on compliance violations
- **Reporting Engine**: Generate scheduled compliance reports
- **User Management**: Enforce role-based access to compliance features

## Configuration

Configuration options can be set in the `config.ini` file:

```ini
[compliance]
# Enable/disable automatic compliance checks
auto_checks = true

# Check interval in hours
check_interval = 24

# Default report format (json, html, pdf)
default_report_format = pdf

# Report output directory
report_dir = ~/compliance_reports

# Email notifications
email_notifications = true
email_recipient = admin@example.com
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
