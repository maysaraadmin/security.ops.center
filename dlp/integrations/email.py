""
Email Integration for DLP Notifications

This module provides email notification capabilities for DLP events.
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
import logging

from ..user_interaction import NotificationType, UserNotification, DLPUserInteraction

logger = logging.getLogger(__name__)

class EmailNotifier:
    """Handles sending email notifications for DLP events."""
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int = 587,
        use_tls: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_addr: Optional[str] = None,
        admin_emails: Optional[List[str]] = None,
        template_dir: Optional[str] = None
    ):
        """
        Initialize the email notifier.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP server port (default: 587)
            use_tls: Whether to use TLS (default: True)
            username: SMTP username (if authentication is required)
            password: SMTP password
            from_addr: Email address to send from
            admin_emails: List of admin email addresses to notify
            template_dir: Directory containing email templates
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.from_addr = from_addr or username
        self.admin_emails = admin_emails or []
        self.template_dir = template_dir
        
        # Register with the global user interaction system
        user_interaction = DLPUserInteraction()
        user_interaction.register_notification_handler(NotificationType.EMAIL, self.send_notification)
    
    async def send_notification(self, title: str, notification: Dict[str, Any]) -> bool:
        """
        Send an email notification.
        
        Args:
            title: Email subject
            notification: Notification data (from UserInteraction)
            
        Returns:
            bool: True if the email was sent successfully
        """
        try:
            # Determine recipients
            recipients = notification.get('metadata', {}).get('recipients', [])
            if not recipients and notification.get('severity') in ['error', 'critical']:
                recipients = self.admin_emails
            
            if not recipients:
                logger.warning("No recipients specified for email notification")
                return False
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = f"[DLP Alert] {title}"
            message["From"] = self.from_addr
            message["To"] = ", ".join(recipients)
            
            # Create email body
            text = self._create_text_body(title, notification)
            html = self._create_html_body(title, notification)
            
            # Attach both plain text and HTML versions
            part1 = MIMEText(text, "plain")
            part2 = MIMEText(html, "html")
            
            message.attach(part1)
            message.attach(part2)
            
            # Send email
            with self._get_smtp_connection() as server:
                server.send_message(message)
            
            logger.info(f"Sent email notification to {', '.join(recipients)}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}", exc_info=True)
            return False
    
    def _get_smtp_connection(self):
        """Create and return an SMTP connection."""
        context = ssl.create_default_context()
        
        if self.use_tls:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls(context=context)
        else:
            server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context)
        
        if self.username and self.password:
            server.login(self.username, self.password)
            
        return server
    
    def _create_text_body(self, title: str, notification: Dict[str, Any]) -> str:
        """Create plain text email body."""
        lines = [
            f"DLP Notification: {title}",
            "=" * 50,
            f"Severity: {notification.get('severity', 'info')}",
            "",
            notification.get('message', 'No message provided'),
            ""
        ]
        
        # Add actions if any
        actions = notification.get('actions', [])
        if actions:
            lines.extend(["Available Actions:", ""])
            for i, action in enumerate(actions, 1):
                lines.append(f"{i}. {action.get('label', 'Unlabeled action')}")
            lines.append("")
        
        # Add metadata
        metadata = notification.get('metadata', {})
        if metadata:
            lines.extend(["Details:", ""])
            for key, value in metadata.items():
                if key not in ['recipients']:  # Skip internal fields
                    lines.append(f"- {key}: {value}")
        
        return "\n".join(lines)
    
    def _create_html_body(self, title: str, notification: Dict[str, Any]) -> str:
        """Create HTML email body."""
        severity = notification.get('severity', 'info')
        severity_colors = {
            'info': '#3498db',
            'warning': '#f39c12',
            'error': '#e74c3c',
            'success': '#2ecc71'
        }
        color = severity_colors.get(severity, '#3498db')
        
        # Create action buttons
        action_buttons = ""
        actions = notification.get('actions', [])
        if actions:
            action_buttons = "<div style=\"margin: 20px 0;\">"
            for action in actions:
                action_buttons += f"""
                <a href=\"#\" style=\"
                    display: inline-block;
                    padding: 10px 20px;
                    margin: 5px;
                    background-color: {color};
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    font-weight: bold;
                \">{action.get('label', 'Action')}</a>
                """
            action_buttons += "</div>"
        
        # Create metadata table
        metadata_rows = ""
        metadata = notification.get('metadata', {})
        for key, value in metadata.items():
            if key not in ['recipients']:  # Skip internal fields
                metadata_rows += f"""
                <tr>
                    <td style=\"padding: 8px; border-bottom: 1px solid #eee; text-align: left;\">{key}</td>
                    <td style=\"padding: 8px; border-bottom: 1px solid #eee; text-align: left;\">{value}</td>
                </tr>
                """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset=\"UTF-8\">
            <title>DLP Notification: {title}</title>
        </head>
        <body style=\"font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px;\">
            <div style=\"border-left: 4px solid {color}; padding-left: 15px; margin-bottom: 20px;\">
                <h1 style=\"color: {color}; margin-top: 0;\">{title}</h1>
                <p><strong>Severity:</strong> <span style=\"color: {color}; font-weight: bold;\">{severity.upper()}</span></p>
            </div>
            
            <div style=\"background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin-bottom: 20px;\">
                <p style=\"margin: 0;\">{notification.get('message', 'No message provided')}</p>
            </div>
            
            {action_buttons}
            
            {self._get_metadata_table_html(notification)}
            
            <div style=\"margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 12px; color: #777;\">
                <p>This is an automated message from the Data Loss Prevention system.</p>
                <p>Please do not reply to this email.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _get_metadata_table_html(self, notification: Dict[str, Any]) -> str:
        """Create HTML table for metadata."""
        metadata = notification.get('metadata', {})
        if not metadata:
            return ""
            
        rows = ""
        for key, value in metadata.items():
            if key not in ['recipients']:  # Skip internal fields
                rows += f"""
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: left; font-weight: bold; width: 200px;">{key}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: left;">{value}</td>
                </tr>
                """
        
        if not rows:
            return ""
            
        return f"""
        <div style="margin: 20px 0;">
            <h3 style="margin-bottom: 10px; color: #555;">Details</h3>
            <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_email():
        # Initialize email notifier with your SMTP settings
        notifier = EmailNotifier(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="your-email@example.com",
            password="your-password",
            from_addr="dlp-notifications@yourdomain.com",
            admin_emails=["admin@yourdomain.com"]
        )
        
        # Send a test notification
        await notifier.send_notification(
            "Test DLP Notification",
            {
                'message': 'This is a test of the DLP email notification system.',
                'severity': 'warning',
                'actions': [
                    {'label': 'Approve', 'action': 'approve'},
                    {'label': 'Reject', 'action': 'reject'}
                ],
                'metadata': {
                    'policy_name': 'Test Policy',
                    'user': 'testuser',
                    'timestamp': '2023-01-01T12:00:00Z',
                    'recipients': ['admin@yourdomain.com']
                }
            }
        )
    
    asyncio.run(test_email())
