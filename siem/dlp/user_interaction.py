"""
DLP User Interaction Module

Handles user notifications and automated remediation for DLP policy violations.
"""
import os
import sys
import json
import logging
import platform
import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any, List, Callable, Awaitable, Union
from pathlib import Path

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    """Types of user notifications."""
    WARNING = auto()
    ERROR = auto()
    INFO = auto()
    BLOCK = auto()

@dataclass
class RemediationAction:
    """Represents a remediation action that can be taken."""
    id: str
    label: str
    description: str
    is_required: bool = False
    is_default: bool = False
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class UserNotification:
    """Represents a notification to be shown to the user."""
    notification_id: str
    title: str
    message: str
    notification_type: NotificationType
    policy_id: str
    rule_id: str
    severity: str
    actions: List[RemediationAction] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timeout: Optional[int] = None  # in seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification to dictionary."""
        return {
            "notification_id": self.notification_id,
            "title": self.title,
            "message": self.message,
            "type": self.notification_type.name,
            "policy_id": self.policy_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "actions": [
                {
                    "id": action.id,
                    "label": action.label,
                    "description": action.description,
                    "is_required": action.is_required,
                    "is_default": action.is_default
                }
                for action in self.actions
            ],
            "metadata": self.metadata,
            "timeout": self.timeout
        }

class UserInteractionHandler:
    """Handles user interactions and notifications."""
    
    def __init__(self, alert_manager=None):
        self.alert_manager = alert_manager
        self._notification_handlers = []
        self._remediation_actions = {}
        
        # Register built-in remediation actions
        self._register_builtin_actions()
    
    def register_notification_handler(self, handler: Callable[[UserNotification], Awaitable[bool]]):
        """Register a handler for showing notifications to users."""
        self._notification_handlers.append(handler)
    
    def register_remediation_action(self, action_id: str, handler: Callable[[Dict[str, Any]], Awaitable[bool]]):
        """Register a remediation action handler."""
        self._remediation_actions[action_id] = handler
    
    async def notify_user(self, notification: UserNotification) -> bool:
        """Notify the user about a policy violation."""
        logger.info(f"Sending notification: {notification.title}")
        
        # Try all registered notification handlers until one succeeds
        for handler in self._notification_handlers:
            try:
                if await handler(notification):
                    return True
            except Exception as e:
                logger.error(f"Error in notification handler: {e}", exc_info=True)
        
        logger.warning("No notification handler was able to deliver the message")
        return False
    
    async def execute_remediation(self, action_id: str, params: Dict[str, Any]) -> bool:
        """Execute a remediation action."""
        handler = self._remediation_actions.get(action_id)
        if not handler:
            logger.error(f"Unknown remediation action: {action_id}")
            return False
        
        try:
            return await handler(params)
        except Exception as e:
            logger.error(f"Error executing remediation action {action_id}: {e}", exc_info=True)
            return False
    
    def _register_builtin_actions(self):
        """Register built-in remediation actions."""
        self.register_remediation_action("encrypt_file", self._remediate_encrypt_file)
        self.register_remediation_action("block_action", self._remediate_block_action)
        self.register_remediation_action("quarantine_file", self._remediate_quarantine_file)
        self.register_remediation_action("redact_content", self._remediate_redact_content)
        self.register_remediation_action("request_approval", self._remediate_request_approval)
    
    async def _remediate_encrypt_file(self, params: Dict[str, Any]) -> bool:
        """Encrypt a file as remediation."""
        file_path = params.get("file_path")
        if not file_path or not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        # In a real implementation, this would encrypt the file
        logger.info(f"[REMEDIATION] Encrypting file: {file_path}")
        await asyncio.sleep(1)  # Simulate encryption time
        return True
    
    async def _remediate_block_action(self, params: Dict[str, Any]) -> bool:
        """Block an action as remediation."""
        action = params.get("action", "unknown")
        logger.info(f"[REMEDIATION] Blocking action: {action}")
        return True  # Blocking is always "successful"
    
    async def _remediate_quarantine_file(self, params: Dict[str, Any]) -> bool:
        """Quarantine a file as remediation."""
        file_path = params.get("file_path")
        if not file_path or not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        # In a real implementation, this would move the file to quarantine
        logger.info(f"[REMEDIATION] Quarantining file: {file_path}")
        await asyncio.sleep(0.5)  # Simulate quarantine time
        return True
    
    async def _remediate_redact_content(self, params: Dict[str, Any]) -> bool:
        """Redact sensitive content as remediation."""
        content = params.get("content", "")
        patterns = params.get("patterns", [])
        
        if not content or not patterns:
            logger.error("Content or patterns not provided for redaction")
            return False
        
        # In a real implementation, this would redact the content
        logger.info("[REMEDIATION] Redacting sensitive content")
        await asyncio.sleep(0.5)  # Simulate redaction time
        return True
    
    async def _remediate_request_approval(self, params: Dict[str, Any]) -> bool:
        """Request approval for an action as remediation."""
        action = params.get("action", "unknown")
        approvers = params.get("approvers", [])
        
        if not approvers:
            logger.error("No approvers specified")
            return False
        
        # In a real implementation, this would send approval requests
        logger.info(f"[REMEDIATION] Requesting approval for: {action}")
        logger.info(f"Approvers: {', '.join(approvers)}")
        
        # Simulate approval process
        await asyncio.sleep(2)
        return True  # Assume approved for demo purposes

class ConsoleNotifier:
    """Simple console-based notifier for demo purposes."""
    
    async def __call__(self, notification: UserNotification) -> bool:
        """Display notification in the console."""
        print("\n" + "=" * 80)
        print(f"DLP {notification.notification_type.name}: {notification.title}")
        print("-" * 80)
        print(notification.message)
        print("\nActions:")
        
        for i, action in enumerate(notification.actions, 1):
            print(f"  {i}. [{action.id}] {action.label}")
            if action.description:
                print(f"     {action.description}")
        
        print("\nEnter action number (or press Enter to use default): ", end="")
        
        try:
            choice = input().strip()
            if not choice and notification.actions:
                # Use default action if available
                default_actions = [a for a in notification.actions if a.is_default]
                if default_actions:
                    return await self._handle_action(notification, default_actions[0].id)
                return await self._handle_action(notification, notification.actions[0].id)
            
            if choice.isdigit() and 1 <= int(choice) <= len(notification.actions):
                action_id = notification.actions[int(choice) - 1].id
                return await self._handle_action(notification, action_id)
            
            print("Invalid choice. Please try again.")
            return False
        except Exception as e:
            logger.error(f"Error handling console notification: {e}", exc_info=True)
            return False
    
    async def _handle_action(self, notification: UserNotification, action_id: str) -> bool:
        """Handle the selected action."""
        print(f"\nExecuting action: {action_id}")
        # In a real implementation, this would trigger the actual remediation
        # For now, we'll just log it
        logger.info(f"User selected action: {action_id} for notification {notification.notification_id}")
        return True

# Default instance
user_interaction = UserInteractionHandler()

# Register default notifier if running in a console
if sys.stdout.isatty():
    user_interaction.register_notification_handler(ConsoleNotifier())

# Platform-specific notifiers
if platform.system() == "Windows":
    try:
        import win32gui
        import win32con
        import win32api
        
        class WindowsNotifier:
            """Windows-specific notifier using message boxes."""
            
            async def __call__(self, notification: UserNotification) -> bool:
                """Show a Windows message box."""
                try:
                    # For simplicity, we'll just show a message box
                    # In a real implementation, you'd create a custom UI
                    message = f"{notification.title}\n\n{notification.message}"
                    
                    if notification.notification_type == NotificationType.ERROR:
                        style = win32con.MB_ICONERROR | win32con.MB_OK
                    elif notification.notification_type == NotificationType.WARNING:
                        style = win32con.MB_ICONWARNING | win32con.MB_OKCANCEL
                    else:
                        style = win32con.MB_ICONINFORMATION | win32con.MB_OK
                    
                    result = win32api.MessageBox(
                        0,  # No owner window
                        message,
                        "DLP Policy Violation",
                        style
                    )
                    
                    # Return True if user clicked OK, False otherwise
                    return result == win32con.IDOK
                except Exception as e:
                    logger.error(f"Error showing Windows notification: {e}", exc_info=True)
                    return False
        
        user_interaction.register_notification_handler(WindowsNotifier())
    except ImportError:
        logger.warning("pywin32 module not available. Windows notifications disabled.")

# Similarly, you could add notifiers for macOS and Linux

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def demo():
        # Create a sample notification
        notification = UserNotification(
            notification_id="test_123",
            title="Sensitive Data Detected",
            message="You are about to send an email containing sensitive information.",
            notification_type=NotificationType.WARNING,
            policy_id="email_policy_1",
            rule_id="block_pii",
            severity="HIGH",
            actions=[
                RemediationAction(
                    id="encrypt_and_send",
                    label="Encrypt & Send",
                    description="Encrypt the email and send it securely",
                    is_default=True
                ),
                RemediationAction(
                    id="edit_message",
                    label="Edit Message",
                    description="Go back and edit the message to remove sensitive data"
                ),
                RemediationAction(
                    id="cancel",
                    label="Cancel",
                    description="Cancel sending the email"
                )
            ]
        )
        
        # Send the notification
        await user_interaction.notify_user(notification)
    
    asyncio.run(demo())
