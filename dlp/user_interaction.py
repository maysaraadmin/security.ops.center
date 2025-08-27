"""
DLP User Interaction Module

Provides user education and remediation features for DLP, including:
- Pop-up warnings for risky actions
- Automated remediation actions
- User notifications
"""
import logging
from enum import Enum
from typing import Dict, Any, Optional, List, Union, Callable, Awaitable
from dataclasses import dataclass, field

# Type alias for notification callbacks
NotificationCallback = Callable[[str, Dict[str, Any]], Awaitable[None]]
RemediationCallback = Callable[[Dict[str, Any], Dict[str, Any]], Awaitable[Dict[str, Any]]]

class NotificationType(Enum):
    """Types of user notifications."""
    POPUP = "popup"
    TOAST = "toast"
    EMAIL = "email"
    LOG = "log"
    AUDIT = "audit"

class RemediationAction(Enum):
    """Available remediation actions."""
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    FORCE_ENCRYPTION = "force_encryption"
    WARN = "warn"

@dataclass
class UserNotification:
    """Represents a notification to be shown to the user."""
    title: str
    message: str
    notification_type: NotificationType = NotificationType.POPUP
    severity: str = "warning"  # info, warning, error, success
    actions: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RemediationResult:
    """Result of a remediation action."""
    success: bool
    message: str
    action_taken: str
    metadata: Dict[str, Any] = field(default_factory=dict)

class DLPUserInteraction:
    """
    Handles user interaction for DLP events including notifications and remediation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.notification_handlers: Dict[NotificationType, List[NotificationCallback]] = {}
        self.remediation_handlers: Dict[RemediationAction, RemediationCallback] = {}
        self.logger = logging.getLogger(__name__)
        
        # Register default handlers
        self._register_default_handlers()
    
    def register_notification_handler(
        self, 
        notification_type: NotificationType, 
        callback: NotificationCallback
    ) -> None:
        """Register a callback for handling notifications of a specific type."""
        if notification_type not in self.notification_handlers:
            self.notification_handlers[notification_type] = []
        self.notification_handlers[notification_type].append(callback)
    
    def register_remediation_handler(
        self, 
        action: RemediationAction, 
        callback: RemediationCallback
    ) -> None:
        """Register a callback for handling remediation actions."""
        self.remediation_handlers[action] = callback
    
    async def notify_user(
        self, 
        title: str, 
        message: str, 
        notification_type: NotificationType = NotificationType.POPUP,
        severity: str = "warning",
        actions: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Send a notification to the user.
        
        Args:
            title: Notification title
            message: Notification message
            notification_type: Type of notification (popup, toast, email, etc.)
            severity: Severity level (info, warning, error, success)
            actions: List of actions the user can take
            metadata: Additional metadata for the notification
        """
        notification = UserNotification(
            title=title,
            message=message,
            notification_type=notification_type,
            severity=severity,
            actions=actions or [],
            metadata=metadata or {}
        )
        
        # Get handlers for this notification type
        handlers = self.notification_handlers.get(notification_type, [])
        
        # Also get any catch-all handlers
        all_handlers = self.notification_handlers.get(None, [])
        
        # Combine and execute handlers
        for handler in handlers + all_handlers:
            try:
                await handler(notification.title, notification.__dict__)
            except Exception as e:
                self.logger.error(
                    f"Error in notification handler for {notification_type}: {e}",
                    exc_info=True
                )
    
    async def apply_remediation(
        self, 
        action: Union[str, RemediationAction], 
        context: Dict[str, Any],
        user_info: Optional[Dict[str, Any]] = None
    ) -> RemediationResult:
        """
        Apply a remediation action.
        
        Args:
            action: The remediation action to take
            context: Context about the DLP event
            user_info: Information about the current user
            
        Returns:
            RemediationResult indicating success/failure and details
        """
        if isinstance(action, str):
            try:
                action = RemediationAction(action.lower())
            except ValueError:
                return RemediationResult(
                    success=False,
                    message=f"Unknown remediation action: {action}",
                    action_taken="none"
                )
        
        handler = self.remediation_handlers.get(action)
        if not handler:
            return RemediationResult(
                success=False,
                message=f"No handler registered for action: {action}",
                action_taken="none"
            )
        
        try:
            result = await handler(context, user_info or {})
            return RemediationResult(
                success=True,
                message=result.get("message", f"Successfully applied {action.value}"),
                action_taken=action.value,
                metadata=result.get("metadata", {})
            )
        except Exception as e:
            self.logger.error(f"Error applying remediation {action}: {e}", exc_info=True)
            return RemediationResult(
                success=False,
                message=f"Failed to apply {action.value}: {str(e)}",
                action_taken=action.value,
                metadata={"error": str(e)}
            )
    
    def _register_default_handlers(self):
        """Register default notification and remediation handlers."""
        # Default console logger for notifications
        async def console_notification_handler(title: str, notification: Dict[str, Any]) -> None:
            print(f"[DLP {notification['severity'].upper()}] {title}: {notification['message']}")
        
        self.register_notification_handler(None, console_notification_handler)
        
        # Default remediation handler for warnings
        async def warn_handler(context: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
            message = context.get("message", "This action may violate data protection policies.")
            title = context.get("title", "Security Warning")
            await self.notify_user(
                title=title,
                message=message,
                notification_type=NotificationType.POPUP,
                severity="warning"
            )
            return {"message": "User was warned about the policy violation"}
        
        self.register_remediation_handler(RemediationAction.WARN, warn_handler)
        
        # Default handler for forcing encryption
        async def force_encryption_handler(context: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
            # In a real implementation, this would integrate with an encryption service
            content = context.get("content", "")
            # Simulate encryption
            encrypted_content = f"[ENCRYPTED] {content} [ENCRYPTED]"
            
            # Notify user
            await self.notify_user(
                title="Content Encrypted",
                message="The content has been automatically encrypted to comply with security policies.",
                notification_type=NotificationType.TOAST,
                severity="info"
            )
            
            return {
                "message": "Content was automatically encrypted",
                "encrypted_content": encrypted_content,
                "original_length": len(content),
                "encrypted_length": len(encrypted_content)
            }
        
        self.register_remediation_handler(RemediationAction.FORCE_ENCRYPTION, force_encryption_handler)
        
        # Default handler for blocking actions
        async def block_handler(context: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
            policy_name = context.get("policy_name", "security policy")
            action = context.get("action_description", "This action")
            
            await self.notify_user(
                title="Action Blocked",
                message=f"{action} has been blocked by {policy_name}.",
                notification_type=NotificationType.POPUP,
                severity="error"
            )
            
            return {
                "message": "Action was blocked by policy",
                "policy": policy_name,
                "action_blocked": True
            }
        
        self.register_remediation_handler(RemediationAction.BLOCK, block_handler)

# Global instance for convenience
user_interaction = DLPUserInteraction()

# Example usage:
if __name__ == "__main__":
    import asyncio
    
    async def test_notifications():
        # Test popup notification
        await user_interaction.notify_user(
            title="Suspicious Activity Detected",
            message="You are about to send unencrypted sensitive data.",
            notification_type=NotificationType.POPUP,
            severity="warning",
            actions=[
                {"label": "Encrypt and Send", "action": "encrypt"},
                {"label": "Cancel", "action": "cancel"}
            ]
        )
        
        # Test remediation
        result = await user_interaction.apply_remediation(
            "force_encryption",
            {
                "content": "Sensitive data here",
                "policy_name": "Encryption Policy",
                "action_description": "Sending unencrypted data"
            }
        )
        print(f"Remediation result: {result}")
    
    asyncio.run(test_notifications())
