"""
Agentless Monitoring Dashboard with proper asyncio support.
"""
import sys
import yaml
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional

from PyQt5.QtWidgets import (QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLabel, 
                           QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
                           QTextEdit, QSplitter, QStatusBar, QMessageBox, QTabWidget,
                           QGroupBox, QFormLayout, QComboBox, QCheckBox, QLineEdit,
                           QSpinBox, QDoubleSpinBox, QProgressBar, QAction, QMenuBar, 
                           QMenu, QFileDialog, QApplication, QDialog)

from .wef_manager import WEFManager
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QSettings, pyqtSlot, QMetaObject, Q_ARG, QObject
from PyQt5.QtGui import QIcon, QFont

from siem.services.agentless.manager import AgentlessServiceManager
from .config_dialog import ConfigDialog

class AgentlessDashboard(QMainWindow):
    """Main window for the Agentless Monitoring Dashboard."""
    
    def __init__(self, config_path=None):
        super().__init__()
        self.config_path = config_path or Path(__file__).parent.parent.parent / 'config' / 'agentless_config.yaml'
        self.config = self.load_config()
        self.service_manager = None
        self.status_timer = QTimer()
        self.loop = None  # Will be set by the event loop thread
        
        # Initialize service status
        self.service_status = {
            'syslog': {'status': QLabel("Stopped"), 'button': QPushButton("Start")},
            'snmp': {'status': QLabel("Stopped"), 'button': QPushButton("Start")},
            'wef': {'status': QLabel("Stopped"), 'button': QPushButton("Start")}
        }
        
        # Initialize UI first
        self.setup_ui()
        
        # Then setup connections (needs UI elements to be initialized first)
        self.setup_connections()
        
        # Start status updates
        self.status_timer.timeout.connect(self.safe_update_status)
        self.status_timer.start(1000)  # Update every second

    def toggle_service(self, service_name):
        """Toggle the state of a service (start/stop)."""
        def toggle():
            if self.service_manager is not None:
                if hasattr(self.service_manager, f"{service_name}_running"):
                    if getattr(self.service_manager, f"{service_name}_running"):
                        getattr(self.service_manager, f"stop_{service_name}")()
                    else:
                        getattr(self.service_manager, f"start_{service_name}")()
                    self.update_status()
        
        self.loop.call_soon_threadsafe(toggle)

    def setup_connections(self):
        """Set up signal/slot connections for UI elements."""
        # Connect menu actions
        self.action_configure.triggered.connect(self.show_config_dialog)
        self.action_about.triggered.connect(self.show_about_dialog)
        self.action_exit.triggered.connect(self.close)
        
        # Connect buttons
        self.refresh_btn.clicked.connect(self.update_status)
        self.block_btn.clicked.connect(self.toggle_block_device)
        self.details_btn.clicked.connect(self.show_device_details)
        
        # Connect table selection changes
        self.devices_table.itemSelectionChanged.connect(self.update_device_buttons)
        
        # Set up status timer
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(5000)  # Update every 5 seconds

    def load_config(self):
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Error loading config: {e}", exc_info=True)
            return {}

    def save_config(self):
        """Save configuration to YAML file."""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except Exception as e:
            logging.error(f"Error saving config: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {e}")

    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("Agentless Monitoring Dashboard")
        self.setMinimumSize(1024, 768)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create main tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create dashboard tab
        self.setup_dashboard_tab()
        
        # Create devices tab
        self.setup_devices_tab()
        
        # Create logs tab
        self.setup_logs_tab()
        
        # Connect service buttons
        for service, data in self.service_status.items():
            data['button'].clicked.connect(lambda _, s=service: self.toggle_service(s))
    
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        self.action_configure = QAction("&Configure...", self)
        self.action_configure.setShortcut("Ctrl+,")
        file_menu.addAction(self.action_configure)
        
        file_menu.addSeparator()
        
        self.action_exit = QAction("E&xit", self)
        self.action_exit.setShortcut("Ctrl+Q")
        self.action_exit.triggered.connect(self.close)
        file_menu.addAction(self.action_exit)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        self.action_about = QAction("&About", self)
        help_menu.addAction(self.action_about)
    
    def setup_dashboard_tab(self):
        """Set up the dashboard tab."""
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        # Status group
        status_group = QGroupBox("Service Status")
        status_layout = QFormLayout(status_group)
        
        for service, data in self.service_status.items():
            status_layout.addRow(f"{service.upper()}:", data['status'])
            data['button'].setFixedWidth(80)
            status_layout.addRow("", data['button'])
        
        layout.addWidget(status_group)
        
        # Stats group
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_table = QTableWidget(3, 2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stats_table.verticalHeader().setVisible(False)
        
        stats_layout.addWidget(self.stats_table)
        layout.addWidget(stats_group)
        
        self.tabs.addTab(dashboard_tab, "Dashboard")
    
    def setup_devices_tab(self):
        """Set up the devices tab."""
        devices_tab = QWidget()
        layout = QVBoxLayout(devices_tab)
        
        # Devices table
        self.devices_table = QTableWidget(0, 4)
        self.devices_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Last Seen", "Status"])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setSelectionMode(QTableWidget.SingleSelection)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh")
        self.block_btn = QPushButton("Block Device")
        self.details_btn = QPushButton("View Details")
        
        self.block_btn.setEnabled(False)
        self.details_btn.setEnabled(False)
        
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.block_btn)
        btn_layout.addWidget(self.details_btn)
        
        layout.addWidget(self.devices_table)
        layout.addLayout(btn_layout)
        
        self.tabs.addTab(devices_tab, "Devices")
    
    def setup_logs_tab(self):
        """Set up the logs tab."""
        logs_tab = QWidget()
        layout = QVBoxLayout(logs_tab)
        
        # Log level filter
        filter_layout = QHBoxLayout()
        
        log_level_label = QLabel("Log Level:")
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setCurrentText("INFO")
        self.log_level_combo.currentTextChanged.connect(self.update_logs)
        
        filter_layout.addWidget(log_level_label)
        filter_layout.addWidget(self.log_level_combo)
        filter_layout.addStretch()
        
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 10))
        
        layout.addLayout(filter_layout)
        layout.addWidget(self.log_text)
        
        self.tabs.addTab(logs_tab, "Logs")
    
    def initialize_services(self):
        """Initialize the agentless services."""
        try:
            self.service_manager = AgentlessServiceManager(self.config)
            self.status_bar.showMessage("Services initialized", 3000)
            # Schedule the update_status coroutine to run in the event loop
            asyncio.ensure_future(self.update_status())
        except Exception as e:
            logging.error(f"Error initializing services: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to initialize services: {e}")
    
    def _on_services_initialized(self, future):
        """Callback when services are initialized."""
        try:
            future.result()
            self.status_bar.showMessage("Services started successfully", 3000)
        except Exception as e:
            logging.error(f"Error starting services: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to start services: {e}")
    
    def start_services(self):
        """Start agentless services."""
        if self.service_manager is not None:
            self.loop.call_soon_threadsafe(self.start_services_async)
    
    async def start_services_async(self):
        """Start agentless services asynchronously."""
        try:
            if self.service_manager is not None:
                await self.service_manager.start_all()
                self.status_bar.showMessage("All services started", 3000)
                self.update_status()
        except Exception as e:
            logging.error(f"Error starting services: {e}", exc_info=True)
            self.status_bar.showMessage(f"Error starting services: {e}", 5000)
    
    async def stop_services_async(self):
        """Stop agentless services asynchronously."""
        try:
            if self.service_manager is not None:
                await self.service_manager.stop_all()
                self.status_bar.showMessage("All services stopped", 3000)
                self.update_status()
        except Exception as e:
            logging.error(f"Error stopping services: {e}", exc_info=True)
            self.status_bar.showMessage(f"Error stopping services: {e}", 5000)
    
    def safe_update_status(self):
        """Safely update status by scheduling the coroutine."""
        if not hasattr(self, 'loop') or self.loop is None:
            return False
            
        # Create a task from the coroutine and add a done callback
        helper = AsyncHelper(
            self,
            self.update_status,
            self.loop
        )
        helper.start()
        return True
        
    @pyqtSlot(object)
    def handle_async_result(self, result):
        """Handle the result of an async operation in the main thread."""
        # This method runs in the main thread and can safely update the UI
        pass
    
    async def update_status(self):
        """Update the status of all services and connected devices."""
        try:
            if self.service_manager is not None:
                # Update service status
                status = self.service_manager.get_status()
                status_data = await status if asyncio.iscoroutine(status) else status
                self.update_ui_status(status_data)
                
                # Update devices
                devices = self.service_manager.get_connected_devices()
                devices_data = await devices if asyncio.iscoroutine(devices) else devices
                self.update_devices_table(devices_data)
                
                # Update logs
                self.update_logs()
                
                return status_data
        except Exception as e:
            logging.error(f"Error updating status: {e}", exc_info=True)
            self.status_bar.showMessage(f"Error updating status: {e}", 5000)
    
    def update_ui_status(self, status_data):
        """Update the UI with the latest status data."""
        if not hasattr(self, 'service_status'):
            return
            
        for service, data in status_data.items():
            if service in self.service_status:
                status_text = "Running" if data.get('running', False) else "Stopped"
                self.service_status[service]['status'].setText(status_text)
                self.service_status[service]['button'].setText("Stop" if data.get('running', False) else "Start")
    
    def update_devices_table(self, devices):
        """Update the devices table with the latest device information."""
        try:
            self.devices_table.setRowCount(len(devices))
            self.devices_data = {}
            
            for row, (device_id, device) in enumerate(devices.items()):
                self.devices_data[device_id] = device
                
                # IP Address
                ip_item = QTableWidgetItem(device.get('ip', 'N/A'))
                ip_item.setData(Qt.UserRole, device_id)
                self.devices_table.setItem(row, 0, ip_item)
                
                # Hostname
                hostname_item = QTableWidgetItem(device.get('hostname', 'N/A'))
                self.devices_table.setItem(row, 1, hostname_item)
                
                # Last Seen
                last_seen = device.get('last_seen', 'N/A')
                if isinstance(last_seen, (int, float)):
                    from datetime import datetime
                    last_seen = datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d %H:%M:%S')
                last_seen_item = QTableWidgetItem(str(last_seen))
                self.devices_table.setItem(row, 2, last_seen_item)
                
                # Status
                status = device.get('status', 'unknown')
                status_item = QTableWidgetItem(status.capitalize())
                self.devices_table.setItem(row, 3, status_item)
                
                # Color code based on status
                if status == 'blocked':
                    for col in range(self.devices_table.columnCount()):
                        self.devices_table.item(row, col).setBackground(Qt.red)
                        self.devices_table.item(row, col).setForeground(Qt.white)
                elif status == 'allowed':
                    for col in range(self.devices_table.columnCount()):
                        self.devices_table.item(row, col).setBackground(Qt.green)
                
            # Update button states
            self.update_device_buttons()
            
        except Exception as e:
            logging.error(f"Error updating devices table: {e}", exc_info=True)
            
    def update_logs(self):
        """Update the logs display with the latest log entries."""
        try:
            if not hasattr(self, 'log_text') or not hasattr(self, 'log_level_combo'):
                return
                
            log_level = self.log_level_combo.currentText().upper()
            log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            min_level = log_levels.index(log_level) if log_level in log_levels else 1  # Default to INFO
            
            # Get log entries from the service manager if available
            logs = []
            if hasattr(self, 'service_manager') and hasattr(self.service_manager, 'get_logs'):
                logs = self.service_manager.get_logs()
            
            # Filter logs by level
            filtered_logs = []
            for log in logs:
                if not log.get('level'):
                    continue
                level = log['level'].upper()
                if level in log_levels and log_levels.index(level) >= min_level:
                    filtered_logs.append(log)
            
            # Update the log display
            self.log_text.clear()
            for log in filtered_logs[-1000:]:  # Limit to last 1000 entries
                timestamp = log.get('timestamp', '')
                level = log.get('level', 'INFO').upper()
                message = log.get('message', '')
                self.log_text.append(f"[{timestamp}] {level}: {message}")
                
        except Exception as e:
            logging.error(f"Error updating logs: {e}", exc_info=True)
    
    def update_device_buttons(self):
        """Update the state of device action buttons based on selection."""
        selected = self.devices_table.selectedItems()
        has_selection = len(selected) > 0
        
        self.block_btn.setEnabled(has_selection)
        self.details_btn.setEnabled(has_selection)
        
        if has_selection:
            # Get the device ID from the first column's UserRole
            device_id = selected[0].data(Qt.UserRole)
            if device_id and device_id in getattr(self, 'devices_data', {}):
                device = self.devices_data[device_id]
                status = device.get('status', '').lower()
                
                # Update block button text based on current status
                if status == 'blocked':
                    self.block_btn.setText("Unblock Device")
                    self.block_btn.setToolTip("Unblock the selected device")
                else:
                    self.block_btn.setText("Block Device")
                    self.block_btn.setToolTip("Block the selected device")
    
    def show_device_details(self):
        """Show detailed information about the selected device."""
        try:
            selected = self.devices_table.selectedItems()
            if not selected:
                return
                
            # Get the device ID from the first column's UserRole
            device_id = selected[0].data(Qt.UserRole)
            if not device_id or device_id not in getattr(self, 'devices_data', {}):
                QMessageBox.warning(self, "Error", "Could not find device details.")
                return
                
            device = self.devices_data[device_id]
            
            # Create and show the device details dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Device Details - {device.get('ip', 'Unknown')}")
            dialog.setMinimumWidth(400)
            
            layout = QVBoxLayout(dialog)
            
            # Create form layout for device details
            form_layout = QFormLayout()
            
            # Add device details to the form
            form_layout.addRow("IP Address:", QLabel(device.get('ip', 'N/A')))
            form_layout.addRow("Hostname:", QLabel(device.get('hostname', 'N/A')))
            form_layout.addRow("MAC Address:", QLabel(device.get('mac', 'N/A')))
            form_layout.addRow("Vendor:", QLabel(device.get('vendor', 'N/A')))
            form_layout.addRow("Status:", QLabel(device.get('status', 'N/A').capitalize()))
            
            # Add last seen time
            last_seen = device.get('last_seen', 'N/A')
            if isinstance(last_seen, (int, float)):
                from datetime import datetime
                last_seen = datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d %H:%M:%S')
            form_layout.addRow("Last Seen:", QLabel(str(last_seen)))
            
            # Add any additional device properties
            for key, value in device.items():
                if key not in ['ip', 'hostname', 'mac', 'vendor', 'status', 'last_seen']:
                    form_layout.addRow(f"{key.capitalize()}:", QLabel(str(value)))
            
            layout.addLayout(form_layout)
            
            # Add close button
            btn_box = QHBoxLayout()
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            btn_box.addStretch()
            btn_box.addWidget(close_btn)
                
            layout.addLayout(btn_box)
            dialog.setLayout(layout)
                
            # Show the dialog
            dialog.exec_()
        except Exception as e:
            logging.error(f"Error showing device details: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to show device details: {str(e)}")
    
    def toggle_block_device(self):
        """Toggle block status of the selected device."""
        try:
            selected = self.devices_table.selectedItems()
            if not selected:
                return
                
            # Get the device ID from the first column's UserRole
            device_id = selected[0].data(Qt.UserRole)
            if not device_id or device_id not in getattr(self, 'devices_data', {}):
                QMessageBox.warning(self, "Error", "Could not find device.")
                return
                
            device = self.devices_data[device_id]
            ip = device.get('ip')
            current_status = device.get('status', '').lower()
                
            if not ip:
                QMessageBox.warning(self, "Error", "Device has no IP address.")
                return
                
            # Determine action based on current status
            block = current_status != 'blocked'
            action = "block" if block else "unblock"
                
            # Confirm with user
            reply = QMessageBox.question(
                self,
                f"{action.capitalize()} Device",
                f"Are you sure you want to {action} {ip}?\n"
                f"This will {'prevent' if block else 'allow'} future connections from this IP.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
                
            if reply == QMessageBox.Yes:
                # Call the service manager to block/unblock the device
                if hasattr(self.service_manager, 'block_device'):
                    # Run in a thread to avoid blocking the UI
                    def do_block():
                        try:
                            if asyncio.iscoroutinefunction(self.service_manager.block_device):
                                self.loop.call_soon_threadsafe(
                                    asyncio.create_task,
                                    self.service_manager.block_device(ip, block)
                                )
                            else:
                                self.service_manager.block_device(ip, block)
                                
                            # Update status after a short delay
                            QTimer.singleShot(1000, self.safe_update_status)
                                
                        except Exception as e:
                            logging.error(f"Error {action}ing device: {e}", exc_info=True)
                            self.status_bar.showMessage(f"Failed to {action} device: {str(e)}", 5000)
                    
                    import threading
                    threading.Thread(target=do_block, daemon=True).start()
                        
                    # Show feedback
                    self.status_bar.showMessage(f"{action.capitalize()}ing device {ip}...", 3000)
                
        except Exception as e:
            logging.error(f"Error toggling block status: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to toggle block status: {str(e)}")
            self.status_bar.showMessage(f"Error updating devices: {str(e)}", 5000)
    
    def show_config_dialog(self):
        """Show the configuration dialog."""
        dialog = ConfigDialog(self.config, self)
        if dialog.exec_() == QDialog.DialogCode.Accepted:
            self.config = dialog.get_config()
            self.save_config()
            self.status_bar.showMessage("Configuration saved", 3000)
    
    def show_about_dialog(self):
        """Show the about dialog."""
        about_text = ("<h2>Agentless Monitoring Dashboard</h2>"
                     "<p>Version: 1.0.0</p>"
                     "<p>A comprehensive monitoring solution for agentless data collection.</p>"
                     "<p> 2025 Security Ops Center. All rights reserved.</p>")
        QMessageBox.about(self, "About Agentless Monitoring", about_text)
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop all services
        if self.service_manager is not None:
            try:
                # Stop the status timer first
                if hasattr(self, 'status_timer') and self.status_timer.isActive():
                    self.status_timer.stop()
                    
                # Stop all services
                for service in ['syslog', 'snmp', 'wef']:
                    if service in self.service_status and self.service_status[service]['status'].text() == "Running":
                        self.toggle_service(service)
                    
                # Clean up the service manager
                if hasattr(self.service_manager, 'cleanup') and callable(self.service_manager.cleanup):
                    if asyncio.iscoroutinefunction(self.service_manager.cleanup):
                        asyncio.create_task(self.service_manager.cleanup())
                    else:
                        self.service_manager.cleanup()
            except Exception as e:
                logging.error(f"Error stopping services: {e}", exc_info=True)
            
        # Let the application handle the rest of the cleanup
        QTimer.singleShot(100, QApplication.instance().quit)
        event.accept()

class AsyncHelper(QObject):
    """Helper class to run asyncio coroutines from Qt."""
    def __init__(self, worker, entry, loop):
        super().__init__()
        self.entry = entry
        self.loop = loop
        self.worker = worker
        
    def start(self):
        """Start the asyncio task."""
        asyncio.run_coroutine_threadsafe(self._run_task(), self.loop)
        
    async def _run_task(self):
        """Run the coroutine and handle its result."""
        try:
            result = await self.entry()
            if hasattr(self.worker, 'handle_async_result'):
                QMetaObject.invokeMethod(
                    self.worker, 
                    'handle_async_result', 
                    Qt.QueuedConnection,
                    Q_ARG(object, result)
                )
        except Exception as e:
            logging.error(f"Error in async task: {e}", exc_info=True)

def run_async():
    """Run the application with proper asyncio event loop."""
    # Set up asyncio for Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # Create the application
    app = QApplication(sys.argv)
    
    # Create and show the main window
    window = AgentlessDashboard()
    window.show()
    
    # Create a timer to process asyncio events
    timer = QTimer()
    timer.timeout.connect(lambda: None)  # Just keep the event loop running
    timer.start(100)  # Process events every 100ms
    
    # Set up the asyncio event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    window.loop = loop
    
    # Create a task to keep the event loop alive
    async def keep_alive():
        while True:
            await asyncio.sleep(1)
    
    # Start the asyncio loop in a separate thread
    def run_async_loop():
        try:
            loop.run_until_complete(keep_alive())
        except Exception as e:
            print(f"Error in async loop: {e}")
    
    import threading
    thread = threading.Thread(target=run_async_loop, daemon=True)
    thread.start()
    
    try:
        # Start the Qt event loop
        app_ret = app.exec_()
        
        # Clean up
        timer.stop()
        if loop.is_running():
            loop.stop()
        loop.close()
        
        return app_ret
        
    except Exception as e:
        error_msg = f"Application error: {e}"
        print(error_msg, file=sys.stderr)
        logging.error(error_msg, exc_info=True)
        return 1
        
    finally:
        # Clean up
        timer.stop()
        
        # Cancel all running tasks
        pending = asyncio.all_tasks(loop=loop)
        for task in pending:
            task.cancel()
        
        # Run the event loop one more time to process cancellations
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        
        # Close the loop
        if not loop.is_closed():
            loop.close()
        
        # Ensure the application exits cleanly
        app.quit()

def main():
    """Entry point for the application."""
    try:
        sys.exit(run_async())
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
