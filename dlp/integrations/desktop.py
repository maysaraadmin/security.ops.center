"""
Desktop Integration for DLP Notifications

This module provides desktop notification capabilities for DLP events,
including popup warnings for risky actions.
"""
import platform
import logging
from typing import Dict, Any, Optional, List, Callable, Awaitable
import asyncio

from ..user_interaction import NotificationType, UserNotification, DLPUserInteraction

logger = logging.getLogger(__name__)

# Try to import platform-specific notification libraries
try:
    import plyer.platforms.win.notification as win_notification
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    logger.warning("Plyer not available. Desktop notifications will be simulated.")

try:
    import win32api
    import win32con
    import win32gui
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    logger.warning("pywin32 not available. Some Windows-specific features will be disabled.")

class DesktopNotifier:
    """Handles desktop notifications for DLP events."""
    
    def __init__(self, app_name: str = "DLP System"):
        """
        Initialize the desktop notifier.
        
        Args:
            app_name: Name of the application to show in notifications
        """
        self.app_name = app_name
        self.active_windows = {}
        
        # Register with the global user interaction system
        user_interaction = DLPUserInteraction()
        user_interaction.register_notification_handler(NotificationType.POPUP, self.show_popup)
        user_interaction.register_notification_handler(NotificationType.TOAST, self.show_toast)
    
    async def show_popup(self, title: str, notification: Dict[str, Any]) -> bool:
        """
        Show a popup notification to the user.
        
        Args:
            title: Popup title
            notification: Notification data (from UserInteraction)
            
        Returns:
            bool: True if the popup was shown successfully
        """
        try:
            message = notification.get('message', '')
            severity = notification.get('severity', 'info')
            actions = notification.get('actions', [])
            
            # On Windows, we can create a custom dialog with buttons
            if platform.system() == 'Windows' and WIN32_AVAILABLE:
                return await self._show_win32_popup(title, message, severity, actions, notification)
            
            # Fall back to system notification
            return await self.show_toast(title, notification)
            
        except Exception as e:
            logger.error(f"Failed to show popup: {e}", exc_info=True)
            return False
    
    async def show_toast(self, title: str, notification: Dict[str, Any]) -> bool:
        """
        Show a toast notification to the user.
        
        Args:
            title: Notification title
            notification: Notification data (from UserInteraction)
            
        Returns:
            bool: True if the toast was shown successfully
        """
        try:
            if not PLYER_AVAILABLE:
                logger.warning("Plyer not available. Cannot show desktop notification.")
                print(f"[DLP NOTIFICATION] {title}: {notification.get('message', '')}")
                return True
                
            message = notification.get('message', '')
            timeout = notification.get('timeout', 10)  # Default 10 seconds
            
            # Show notification using plyer
            notification.notify(
                title=title,
                message=message,
                app_name=self.app_name,
                timeout=timeout
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to show toast: {e}", exc_info=True)
            return False
    
    async def _show_win32_popup(
        self, 
        title: str, 
        message: str, 
        severity: str = 'info',
        actions: List[Dict[str, Any]] = None,
        notification_data: Dict[str, Any] = None
    ) -> bool:
        """
        Show a Windows popup dialog with custom buttons.
        
        Args:
            title: Popup title
            message: Popup message
            severity: Severity level (info, warning, error, success)
            actions: List of actions/buttons to show
            notification_data: Original notification data
            
        Returns:
            bool: True if the popup was shown successfully
        """
        if not WIN32_AVAILABLE:
            logger.warning("win32api not available. Cannot show Windows popup.")
            return False
            
        try:
            # Map severity to Windows icon
            icon_map = {
                'info': win32con.MB_ICONINFORMATION,
                'warning': win32con.MB_ICONWARNING,
                'error': win32con.MB_ICONERROR,
                'success': win32con.MB_ICONINFORMATION
            }
            icon = icon_map.get(severity.lower(), win32con.MB_ICONINFORMATION)
            
            # Default button configuration
            buttons = win32con.MB_OK
            
            # If we have actions, create custom buttons
            if actions and len(actions) > 0:
                if len(actions) == 1:
                    buttons = win32con.MB_OKCANCEL
                elif len(actions) == 2:
                    buttons = win32con.MB_YESNO
                elif len(actions) > 2:
                    buttons = win32con.MB_ABORTRETRYIGNORE
            
            # Show the message box
            result = win32api.MessageBox(
                0,  # No parent window
                message,
                f"{self.app_name} - {title}",
                buttons | icon
            )
            
            # Map the result back to our action
            action_result = None
            if result == win32con.IDOK or result == win32con.IDYES:
                action_result = actions[0] if actions else None
            elif result == win32con.IDCANCEL or result == win32con.IDNO:
                action_result = actions[1] if len(actions) > 1 else None
            elif result == win32con.IDABORT or result == win32con.IDRETRY or result == win32con.IDIGNORE:
                # For ABORTRETRYIGNORE, map to the appropriate action
                if len(actions) > 2:
                    if result == win32con.IDABORT:
                        action_result = actions[0]
                    elif result == win32con.IDRETRY:
                        action_result = actions[1]
                    else:  # IDIGNORE
                        action_result = actions[2] if len(actions) > 2 else None
            
            # If we have an action result and a callback, trigger it
            if action_result and 'action' in action_result:
                user_interaction = DLPUserInteraction()
                await user_interaction.apply_remediation(
                    action_result['action'],
                    notification_data or {},
                    {'action': action_result}
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Error showing Windows popup: {e}", exc_info=True)
            return False
    
    def _on_win32_callback(self, hwnd, msg, wparam, lparam):
        """Callback for Windows message handling."""
        if msg == win32con.WM_DESTROY:
            win32gui.PostQuitMessage(0)
            return 0
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

# Global instance for convenience
desktop_notifier = DesktopNotifier()

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_desktop():
        # Initialize the notifier
        notifier = DesktopNotifier("DLP Test")
        
        # Test toast notification
        await notifier.show_toast(
            "Test Toast",
            {
                'message': 'This is a test toast notification.',
                'severity': 'info',
                'timeout': 5
            }
        )
        
        # Test popup with actions (Windows only)
        if platform.system() == 'Windows':
            await notifier.show_popup(
                "Security Warning",
                {
                    'message': 'You are about to send unencrypted sensitive data.\n\nDo you want to continue?',
                    'severity': 'warning',
                    'actions': [
                        {'label': 'Encrypt and Send', 'action': 'encrypt'},
                        {'label': 'Send Anyway', 'action': 'bypass'},
                        {'label': 'Cancel', 'action': 'cancel'}
                    ]
                }
            )
        
        # Keep the script running to see the notifications
        await asyncio.sleep(10)
    
    asyncio.run(test_desktop())
