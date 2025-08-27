"""
Endpoint DLP Monitor

Monitors and controls data-in-use activities on endpoints including:
- USB device connections and file transfers
- Clipboard operations
- Screen capture activities
- File operations (copy, move, delete)
"""
import os
import sys
import logging
import threading
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import platform
import json
from datetime import datetime

# Platform-specific imports
try:
    if platform.system() == 'Windows':
        import win32api
        import win32con
        import win32file
        import pythoncom
        import pyWinhook as hook
        from ctypes import windll, byref, c_ulong, c_void_p
    elif platform.system() == 'Darwin':  # macOS
        import subprocess
        from AppKit import NSWorkspace, NSWorkspaceDidActivateApplicationNotification
        from Foundation import NSObject, NSRunLoop, NSDefaultRunLoopMode
        from Quartz import (
            CGEventSourceCreate, 
            CGEventSourceKeyState,
            CGEventCreateKeyboardEvent,
            CGEventPost,
            kCGHIDEventTap,
            kCGEventMaskForAllEvents,
            CGEventTapCreate,
            kCGEventTapOptionDefault,
            kCGEventTapCreateOptions(0),
            kCGEventLeftMouseDown,
            kCGEventRightMouseDown,
            kCGEventKeyDown,
            kCGEventFlagsChanged
        )
    # Linux support can be added here

except ImportError as e:
    logging.warning(f"Some monitoring features may be limited: {str(e)}")

from .policies import DLPPolicyManager
from .enforcer import PolicyEnforcer, PolicyScope
from .actions import ActionContext

class EndpointActivityType(Enum):
    """Types of endpoint activities that can be monitored."""
    USB_DEVICE_CONNECTED = auto()
    USB_DEVICE_REMOVED = auto()
    CLIPBOARD_COPY = auto()
    SCREEN_CAPTURE = auto()
    FILE_OPERATION = auto()
    PRINT_OPERATION = auto()

@dataclass
class EndpointActivity:
    """Represents an endpoint activity event."""
    activity_type: EndpointActivityType
    timestamp: float = field(default_factory=time.time)
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    user: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

class EndpointMonitor:
    """Monitors endpoint activities for DLP enforcement."""
    
    def __init__(self, policy_enforcer: Optional[PolicyEnforcer] = None):
        """Initialize the endpoint monitor.
        
        Args:
            policy_enforcer: Optional PolicyEnforcer instance for evaluating policies
        """
        self.logger = logging.getLogger(__name__)
        self.policy_enforcer = policy_enforcer
        self.running = False
        self.monitoring_thread = None
        self.callbacks = []
        self.usb_devices = set()
        self.platform = platform.system()
        
        # Platform-specific initialization
        if self.platform == 'Windows':
            self._init_windows()
        elif self.platform == 'Darwin':
            self._init_macos()
        # Linux initialization can be added here
    
    def _init_windows(self) -> None:
        """Initialize Windows-specific monitoring."""
        self.logger.info("Initializing Windows endpoint monitor")
        
        # Initialize COM for thread safety
        pythoncom.CoInitialize()
        
        # Set up keyboard and mouse hooks
        self.hm = hook.HookManager()
        
        # Register callbacks
        self.hm.KeyDown = self._on_keyboard_event
        self.hm.MouseAllButtonsDown = self._on_mouse_event
        self.hm.SubscribeMouseAllButtonsDown(self._on_mouse_event)
        
        # Set up USB device change notification
        self._setup_usb_monitoring()
    
    def _init_macos(self) -> None:
        """Initialize macOS-specific monitoring."""
        self.logger.info("Initializing macOS endpoint monitor")
        # Set up event taps for keyboard and mouse
        self._setup_macos_event_taps()
        
        # Set up USB monitoring
        self._setup_macos_usb_monitoring()
    
    def _setup_macos_event_taps(self) -> None:
        """Set up event taps for macOS."""
        # This is a simplified version - in a real implementation, you would use
        # Quartz event taps to monitor keyboard and mouse events
        pass
    
    def _setup_macos_usb_monitoring(self) -> None:
        """Set up USB device monitoring for macOS."""
        # In a real implementation, this would use IOKit to monitor USB devices
        pass
    
    def _setup_usb_monitoring(self) -> None:
        """Set up USB device monitoring."""
        if self.platform == 'Windows':
            # On Windows, we'll use a separate thread to monitor device changes
            self.usb_monitor_thread = threading.Thread(
                target=self._monitor_usb_devices_windows,
                daemon=True
            )
            self.usb_monitor_thread.start()
    
    def _monitor_usb_devices_windows(self) -> None:
        """Monitor USB device changes on Windows."""
        # This is a simplified version - in a real implementation, you would use
        # Windows Device Notifications to detect device changes
        while self.running:
            try:
                # Check for new USB devices
                drives = win32api.GetLogicalDriveStrings()
                drives = drives.split('\x00')[:-1]
                drives = [d for d in drives if win32file.GetDriveType(d) == win32file.DRIVE_REMOVABLE]
                
                current_devices = set(drives)
                
                # Check for new devices
                new_devices = current_devices - self.usb_devices
                for device in new_devices:
                    self._handle_usb_device_connected(device)
                
                # Check for removed devices
                removed_devices = self.usb_devices - current_devices
                for device in removed_devices:
                    self._handle_usb_device_removed(device)
                
                self.usb_devices = current_devices
                
            except Exception as e:
                self.logger.error(f"Error monitoring USB devices: {str(e)}")
            
            time.sleep(5)  # Check every 5 seconds
    
    def _on_keyboard_event(self, event) -> bool:
        """Handle keyboard events."""
        try:
            # Check for print screen key or other screenshot shortcuts
            if event.Key.lower() in ['snapshot', 'printscreen', 'print_screen']:
                self._handle_screen_capture()
            
            # Check for copy/paste shortcuts
            if event.Key.lower() == 'c' and event.Ctrl:
                self._handle_clipboard_copy()
            
        except Exception as e:
            self.logger.error(f"Error handling keyboard event: {str(e)}")
        
        return True  # Allow the event to propagate
    
    def _on_mouse_event(self, event) -> bool:
        """Handle mouse events."""
        # Can be used to detect right-click copy operations
        return True  # Allow the event to propagate
    
    def _handle_usb_device_connected(self, device_path: str) -> None:
        """Handle USB device connection."""
        try:
            volume_name = win32api.GetVolumeInformation(device_path)[0]
            serial_number = self._get_usb_serial_number(device_path)
            
            activity = EndpointActivity(
                activity_type=EndpointActivityType.USB_DEVICE_CONNECTED,
                process_name=sys.executable,
                process_id=os.getpid(),
                user=os.getlogin(),
                details={
                    'device_path': device_path,
                    'volume_name': volume_name,
                    'serial_number': serial_number,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            self._notify_activity(activity)
            
            # Check if the device contains sensitive data
            if self.policy_enforcer:
                self._check_usb_device(device_path, activity)
                
        except Exception as e:
            self.logger.error(f"Error handling USB device connection: {str(e)}")
    
    def _handle_usb_device_removed(self, device_path: str) -> None:
        """Handle USB device removal."""
        try:
            activity = EndpointActivity(
                activity_type=EndpointActivityType.USB_DEVICE_REMOVED,
                process_name=sys.executable,
                process_id=os.getpid(),
                user=os.getlogin(),
                details={
                    'device_path': device_path,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            self._notify_activity(activity)
            
        except Exception as e:
            self.logger.error(f"Error handling USB device removal: {str(e)}")
    
    def _handle_clipboard_copy(self) -> None:
        """Handle clipboard copy operations."""
        try:
            import win32clipboard
            
            win32clipboard.OpenClipboard()
            
            # Check different clipboard formats
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                data_type = 'text'
            elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                data_type = 'unicode_text'
            elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_HDROP):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                data_type = 'file_list'
            else:
                data = None
                data_type = 'unknown'
            
            win32clipboard.CloseClipboard()
            
            if data:
                activity = EndpointActivity(
                    activity_type=EndpointActivityType.CLIPBOARD_COPY,
                    process_name=self._get_foreground_process_name(),
                    process_id=self._get_foreground_process_id(),
                    user=os.getlogin(),
                    details={
                        'data_type': data_type,
                        'data_preview': str(data)[:500] if data else None,
                        'timestamp': datetime.now().isoformat()
                    }
                )
                
                self._notify_activity(activity)
                
                # Check if the clipboard data contains sensitive information
                if self.policy_enforcer and isinstance(data, str):
                    self._check_clipboard_data(data, activity)
                    
        except Exception as e:
            self.logger.error(f"Error handling clipboard copy: {str(e)}")
    
    def _handle_screen_capture(self) -> None:
        """Handle screen capture operations."""
        try:
            activity = EndpointActivity(
                activity_type=EndpointActivityType.SCREEN_CAPTURE,
                process_name=self._get_foreground_process_name(),
                process_id=self._get_foreground_process_id(),
                user=os.getlogin(),
                details={
                    'timestamp': datetime.now().isoformat(),
                    'window_title': self._get_foreground_window_title()
                }
            )
            
            self._notify_activity(activity)
            
            # Check if screen capture is allowed
            if self.policy_enforcer:
                self._check_screen_capture(activity)
                
        except Exception as e:
            self.logger.error(f"Error handling screen capture: {str(e)}")
    
    def _check_usb_device(self, device_path: str, activity: EndpointActivity) -> None:
        """Check if a USB device contains sensitive data."""
        try:
            # In a real implementation, you would scan the device for sensitive files
            # For now, we'll just check the device name and serial number
            context = {
                'source': 'endpoint',
                'operation': 'usb_device_connected',
                'device_path': device_path,
                'activity': activity.details
            }
            
            # Evaluate policies
            results = self.policy_enforcer.evaluate_content(
                content=None,  # In a real implementation, you would scan the device
                scope=PolicyScope.ENDPOINT,
                context=context
            )
            
            # Process results
            for result in results:
                for action_result in result.get('actions_executed', []):
                    if not action_result.get('success', True):
                        self.logger.warning(
                            f"Action failed: {action_result.get('error', 'Unknown error')}"
                        )
                        
        except Exception as e:
            self.logger.error(f"Error checking USB device: {str(e)}")
    
    def _check_clipboard_data(self, data: str, activity: EndpointActivity) -> None:
        """Check if clipboard data contains sensitive information."""
        try:
            context = {
                'source': 'endpoint',
                'operation': 'clipboard_copy',
                'process_name': activity.process_name,
                'process_id': activity.process_id,
                'user': activity.user,
                'activity': activity.details
            }
            
            # Evaluate policies
            results = self.policy_enforcer.evaluate_content(
                content=data,
                scope=PolicyScope.ENDPOINT,
                context=context
            )
            
            # Process results
            for result in results:
                for action_result in result.get('actions_executed', []):
                    if not action_result.get('success', True):
                        self.logger.warning(
                            f"Action failed: {action_result.get('error', 'Unknown error')}"
                        )
                        
        except Exception as e:
            self.logger.error(f"Error checking clipboard data: {str(e)}")
    
    def _check_screen_capture(self, activity: EndpointActivity) -> None:
        """Check if screen capture is allowed."""
        try:
            context = {
                'source': 'endpoint',
                'operation': 'screen_capture',
                'process_name': activity.process_name,
                'process_id': activity.process_id,
                'user': activity.user,
                'activity': activity.details
            }
            
            # Evaluate policies
            results = self.policy_enforcer.evaluate_content(
                content=None,  # No content to check for screen capture
                scope=PolicyScope.ENDPOINT,
                context=context
            )
            
            # Process results
            for result in results:
                for action_result in result.get('actions_executed', []):
                    if action_result.get('type') == 'block' and action_result.get('success', False):
                        # Block the screen capture
                        self._block_screen_capture()
                        break
                        
        except Exception as e:
            self.logger.error(f"Error checking screen capture: {str(e)}")
    
    def _block_screen_capture(self) -> None:
        """Block the current screen capture attempt."""
        try:
            if self.platform == 'Windows':
                # On Windows, we can't directly block the screen capture,
                # but we can show a notification to the user
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    0,
                    "Screen capture blocked by security policy.",
                    "Security Alert",
                    0x40 | 0x1  # MB_ICONINFORMATION | MB_OK
                )
                
        except Exception as e:
            self.logger.error(f"Error blocking screen capture: {str(e)}")
    
    def _get_foreground_process_name(self) -> str:
        """Get the name of the foreground process."""
        try:
            if self.platform == 'Windows':
                import win32process
                import win32gui
                
                hwnd = win32gui.GetForegroundWindow()
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                
                import psutil
                process = psutil.Process(pid)
                return process.name()
                
        except Exception as e:
            self.logger.error(f"Error getting foreground process name: {str(e)}")
            
        return "unknown"
    
    def _get_foreground_process_id(self) -> int:
        """Get the process ID of the foreground window."""
        try:
            if self.platform == 'Windows':
                import win32process
                import win32gui
                
                hwnd = win32gui.GetForegroundWindow()
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                return pid
                
        except Exception as e:
            self.logger.error(f"Error getting foreground process ID: {str(e)}")
            
        return -1
    
    def _get_foreground_window_title(self) -> str:
        """Get the title of the foreground window."""
        try:
            if self.platform == 'Windows':
                import win32gui
                return win32gui.GetWindowText(win32gui.GetForegroundWindow())
                
        except Exception as e:
            self.logger.error(f"Error getting window title: {str(e)}")
            
        return ""
    
    def _get_usb_serial_number(self, device_path: str) -> Optional[str]:
        """Get the serial number of a USB device."""
        # This is a simplified version - in a real implementation, you would
        # use the Windows SetupAPI to get detailed device information
        try:
            # Try to get volume serial number as a fallback
            volume_info = win32api.GetVolumeInformation(device_path)
            return str(volume_info[1]) if volume_info[1] else None
            
        except Exception as e:
            self.logger.error(f"Error getting USB serial number: {str(e)}")
            return None
    
    def _notify_activity(self, activity: EndpointActivity) -> None:
        """Notify registered callbacks of an activity."""
        for callback in self.callbacks:
            try:
                callback(activity)
            except Exception as e:
                self.logger.error(f"Error in activity callback: {str(e)}")
    
    def register_callback(self, callback: Callable[[EndpointActivity], None]) -> None:
        """Register a callback for activity notifications.
        
        Args:
            callback: A function that takes an EndpointActivity object
        """
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[EndpointActivity], None]) -> None:
        """Unregister a callback."""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def start(self) -> None:
        """Start monitoring endpoint activities."""
        if not self.running:
            self.running = True
            
            if self.platform == 'Windows':
                # Start the keyboard/mouse hook
                self.hm.HookKeyboard()
                self.hm.HookMouse()
                
                # Start the message pump in a separate thread
                self.monitoring_thread = threading.Thread(
                    target=self._message_pump,
                    daemon=True
                )
                self.monitoring_thread.start()
                
            self.logger.info("Endpoint monitoring started")
    
    def stop(self) -> None:
        """Stop monitoring endpoint activities."""
        if self.running:
            self.running = False
            
            if self.platform == 'Windows':
                # Stop the hooks
                self.hm.UnhookKeyboard()
                self.hm.UnhookMouse()
                
                # Stop the message pump
                if hasattr(self, 'hm'):
                    import win32con
                    import win32gui_struct
                    
                    # Post a quit message to the message queue
                    hwnd = win32gui_struct.GetSpecialFolderLocation(0, 0x0000)  # CSIDL_DESKTOP
                    win32gui.PostMessage(hwnd, win32con.WM_QUIT, 0, 0)
            
            self.logger.info("Endpoint monitoring stopped")
    
    def _message_pump(self) -> None:
        """Windows message pump for processing events."""
        import pyWinhook as hook
        import pythoncom
        
        while self.running:
            try:
                pythoncom.PumpWaitingMessages()
                time.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Error in message pump: {str(e)}")
                time.sleep(1)  # Prevent tight loop on error
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def monitor_endpoint_activities(policy_enforcer: Optional[PolicyEnforcer] = None) -> EndpointMonitor:
    """Create and start an endpoint monitor.
    
    Args:
        policy_enforcer: Optional PolicyEnforcer instance
        
    Returns:
        A running EndpointMonitor instance
    """
    monitor = EndpointMonitor(policy_enforcer)
    monitor.start()
    return monitor
