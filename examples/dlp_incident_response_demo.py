"""
DLP Incident Response Demo

Demonstrates the DLP alerting and incident response capabilities.
"""
import asyncio
import logging
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from siem.dlp import (
    AlertContext, AlertSeverity, AlertStatus,
    alert_manager, EmailNotifier
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('dlp_incident_response.log')
    ]
)
logger = logging.getLogger(__name__)

# Sample incident response team members
INCIDENT_RESPONSE_TEAM = [
    "security-team@example.com",
    "dlp-admin@example.com"
]

# Sample DLP policies with different severity levels
SAMPLE_POLICIES = [
    {
        "id": "high_risk_data",
        "name": "High Risk Data Protection",
        "severity": "HIGH",
        "description": "Detects and blocks high-risk data like credit cards and SSNs"
    },
    {
        "id": "medium_risk_data",
        "name": "Medium Risk Data Monitoring",
        "severity": "MEDIUM",
        "description": "Monitors for medium risk data like phone numbers and addresses"
    },
    {
        "id": "low_risk_data",
        "name": "Low Risk Data Logging",
        "severity": "LOW",
        "description": "Logs low risk data for compliance purposes"
    }
]

# Sample data patterns and their corresponding policies
SAMPLE_VIOLATIONS = [
    {
        "content": "Credit card 4111-1111-1111-1111 detected in document",
        "pattern": "credit card",
        "policy_id": "high_risk_data",
        "severity": "HIGH"
    },
    {
        "content": "SSN 123-45-6789 found in email attachment",
        "pattern": "SSN",
        "policy_id": "high_risk_data",
        "severity": "HIGH"
    },
    {
        "content": "Phone number +1 (555) 123-4567 shared externally",
        "pattern": "phone number",
        "policy_id": "medium_risk_data",
        "severity": "MEDIUM"
    },
    {
        "content": "Home address 123 Main St, Anytown, USA found in document",
        "pattern": "address",
        "policy_id": "medium_risk_data",
        "severity": "MEDIUM"
    },
    {
        "content": "Generic document with no sensitive data",
        "pattern": "generic",
        "policy_id": "low_risk_data",
        "severity": "LOW"
    }
]

class MockDLPEngine:
    """Mock DLP engine for demo purposes."""
    
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
    
    async def process_content(self, content: str, user: str = "demo-user", source_ip: str = "192.168.1.100"):
        """Process content and generate alerts if violations are found."""
        logger.info(f"Processing content from {user} at {source_ip}")
        
        # Check for policy violations
        for violation in SAMPLE_VIOLATIONS:
            if violation["content"] == content:
                await self._create_alert(violation, user, source_ip)
                return True
        
        logger.info("No policy violations detected")
        return False
    
    async def _create_alert(self, violation: dict, user: str, source_ip: str):
        """Create an alert for a policy violation."""
        context = AlertContext(
            policy_id=violation["policy_id"],
            rule_id=f"rule_{violation['severity'].lower()}_{len(violation['pattern'])}",
            action_taken="blocked" if violation["severity"] == "HIGH" else "logged",
            severity=AlertSeverity[violation["severity"]],
            source_ip=source_ip,
            username=user,
            content_sample=violation["content"],
            matched_pattern=violation["pattern"],
            metadata={
                "content_type": "text/plain",
                "file_name": "document.txt",
                "file_size": len(violation["content"]),
                "detection_time": datetime.utcnow().isoformat()
            }
        )
        
        alert = await self.alert_manager.create_alert(context)
        logger.info(f"Created alert {alert.alert_id} for {violation['policy_id']} violation")
        return alert

async def demo_alert_management():
    """Demonstrate alert management features."""
    logger.info("\n=== DLP Alert Management Demo ===")
    
    # List all open alerts
    open_alerts = await alert_manager.list_alerts(status=AlertStatus.OPEN)
    logger.info(f"Found {len(open_alerts)} open alerts")
    
    if open_alerts:
        # Update an alert
        alert = open_alerts[0]
        logger.info(f"Updating alert {alert.alert_id} to IN_PROGRESS")
        
        updated_alert = await alert_manager.update_alert(
            alert.alert_id,
            {
                "status": AlertStatus.IN_PROGRESS,
                "assigned_to": "security-analyst@example.com",
                "comments": [
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "user": "system",
                        "comment": "Alert assigned for investigation"
                    }
                ]
            }
        )
        
        # Add a resolution
        await alert_manager.update_alert(
            alert.alert_id,
            {
                "status": AlertStatus.CLOSED,
                "resolution": "Verified as legitimate business need",
                "comments": [
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "user": "analyst@example.com",
                        "comment": "Confirmed with department head - legitimate business use case"
                    }
                ]
            }
        )
        
        # Get the updated alert
        resolved_alert = await alert_manager.get_alert(alert.alert_id)
        logger.info(f"Alert {resolved_alert.alert_id} is now {resolved_alert.status}")

async def main():
    """Run the DLP incident response demo."""
    logger.info("Starting DLP Incident Response Demo")
    
    # Setup email notifier (commented out as it requires SMTP configuration)
    # email_notifier = EmailNotifier(
    #     smtp_server="smtp.example.com",
    #     smtp_port=587,
    #     sender="dlp-alerts@example.com",
    #     username="smtp_username",
    #     password="smtp_password"
    # )
    # 
    # def email_alert_handler(alert):
    #     """Send email notification for high severity alerts."""
    #     if alert.context.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
    #         email_notifier(alert, INCIDENT_RESPONSE_TEAM)
    # 
    # alert_manager.add_handler(email_alert_handler)
    
    # Create a console alert handler
    def console_alert_handler(alert):
        """Log alerts to console."""
        logger.warning(
            f"[ALERT] {alert.alert_id}: {alert.context.severity.name} - "
            f"{alert.context.policy_id} - {alert.context.rule_id}"
        )
    
    alert_manager.add_handler(console_alert_handler)
    
    # Create mock DLP engine
    dlp_engine = MockDLPEngine(alert_manager)
    
    # Simulate some DLP violations
    logger.info("\n=== Simulating DLP Violations ===")
    for i, violation in enumerate(SAMPLE_VIOLATIONS):
        logger.info(f"\nViolation {i+1}: {violation['content']}")
        await dlp_engine.process_content(
            content=violation["content"],
            user=f"user{i+1}@example.com",
            source_ip=f"192.168.1.{i+10}"
        )
        await asyncio.sleep(1)  # Add delay for distinct timestamps
    
    # Demonstrate alert management
    await demo_alert_management()
    
    # Generate a report
    logger.info("\n=== Generating DLP Incident Report ===")
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)
    
    all_alerts = await alert_manager.list_alerts()
    high_alerts = [a for a in all_alerts if a.context.severity == AlertSeverity.HIGH]
    medium_alerts = [a for a in all_alerts if a.context.severity == AlertSeverity.MEDIUM]
    low_alerts = [a for a in all_alerts if a.context.severity == AlertSeverity.LOW]
    
    report = {
        "report_time": datetime.utcnow().isoformat(),
        "time_range": {
            "start": start_time.isoformat(),
            "end": end_time.isoformat()
        },
        "alerts_summary": {
            "total": len(all_alerts),
            "high_priority": len(high_alerts),
            "medium_priority": len(medium_alerts),
            "low_priority": len(low_alerts),
            "by_policy": {},
            "by_severity": {
                "HIGH": len(high_alerts),
                "MEDIUM": len(medium_alerts),
                "LOW": len(low_alerts)
            }
        },
        "recent_incidents": [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "policy": a.context.policy_id,
                "severity": a.context.severity.name,
                "action": a.context.action_taken,
                "source_ip": a.context.source_ip,
                "username": a.context.username
            }
            for a in sorted(all_alerts, key=lambda x: x.timestamp, reverse=True)[:5]
        ]
    }
    
    # Count alerts by policy
    for policy in SAMPLE_POLICIES:
        policy_alerts = [a for a in all_alerts if a.context.policy_id == policy["id"]]
        report["alerts_summary"]["by_policy"][policy["name"]] = len(policy_alerts)
    
    # Save report to file
    report_file = "dlp_incident_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"\nDLP Incident Report generated: {report_file}")
    logger.info(f"Total alerts: {len(all_alerts)}")
    logger.info(f"High severity: {len(high_alerts)}")
    logger.info(f"Medium severity: {len(medium_alerts)}")
    logger.info(f"Low severity: {len(low_alerts)}")
    
    logger.info("\nDLP Incident Response Demo completed!")

if __name__ == "__main__":
    asyncio.run(main())
