"""
EDR Agent GUI
------------
A PyQt5-based graphical interface for managing the EDR agent.
"""
import sys
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QTabWidget, QLabel, QPushButton, QTextEdit, QTableWidget,
                           QTableWidgetItem, QHeaderView, QStatusBar, QGroupBox,
                           QFormLayout, QLineEdit, QComboBox, QCheckBox, QMessageBox)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QIcon

# Local imports
from edr.agent.edr_agent import EDRAgent, EDREvent, EventSeverity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('edr.agent.gui')

class EDREventTable(QTableWidget):
    """Table widget for displaying EDR events."""
    
    HEADERS = ["Time", "Severity", "Source", "Event Type", "Details"]
    SEVERITY_COLORS = {
        EventSeverity.INFO: QColor(220, 240, 255),      # Light blue
        EventSeverity.LOW: QColor(200, 255, 200),      # Light green
        EventSeverity.MEDIUM: QColor(255, 255, 150),   # Light yellow
        EventSeverity.HIGH: QColor(255, 200, 150),     # Light orange
        EventSeverity.CRITICAL: QColor(255, 180, 180), # Light red
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setEditTriggers(self.NoEditTriggers)
        self.setSelectionBehavior(self.SelectRows)
        self.setSelectionMode(self.SingleSelection)
        self.verticalHeader().setVisible(False)
        
        # Set column widths
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Event Type
        header.setSectionResizeMode(4, QHeaderView.Stretch)           # Details
    
    def add_event(self, event: EDREvent):
        """Add a new event to the table."""
        row = self.rowCount()
        self.insertRow(row)
        
        # Format time
        time_str = datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
        
        # Add items to the row
        self.setItem(row, 0, QTableWidgetItem(time_str))
        self.setItem(row, 1, QTableWidgetItem(event.severity.value))
        self.setItem(row, 2, QTableWidgetItem(event.source))
        self.setItem(row, 3, QTableWidgetItem(event.event_type))
        self.setItem(row, 4, QTableWidgetItem(str(event.details)))
        
        # Set row color based on severity
        color = self.SEVERITY_COLORS.get(event.severity, QColor(255, 255, 255))
        for col in range(self.columnCount()):
            if self.item(row, col):
                self.item(row, col).setBackground(color)
        
        # Auto-scroll to the bottom
        self.scrollToBottom()


class AgentStatusWidget(QGroupBox):
    """Widget for displaying agent status and controls."""
    
    def __init__(self, parent=None):
        super().__init__("Agent Status", parent)
        self.agent = None
        self.init_ui()
    
    def init_ui(self):
        layout = QFormLayout()
        
        # Status indicators
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("font-weight: bold; color: red;")
        
        self.uptime_label = QLabel("00:00:00")
        self.event_count_label = QLabel("0")
        
        # Buttons
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        
        # Add to layout
        layout.addRow("Status:", self.status_label)
        layout.addRow("Uptime:", self.uptime_label)
        layout.addRow("Events:", self.event_count_label)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addRow(button_layout)
        
        self.setLayout(layout)
        
        # Connect signals
        self.start_button.clicked.connect(self.start_agent)
        self.stop_button.clicked.connect(self.stop_agent)
    
    def set_agent(self, agent):
        """Set the agent instance to control."""
        self.agent = agent
    
    def start_agent(self):
        """Start the EDR agent."""
        if self.agent and not self.agent.running:
            try:
                self.agent.start()
                self.status_label.setText("Running")
                self.status_label.setStyleSheet("font-weight: bold; color: green;")
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
                logger.info("EDR agent started")
            except Exception as e:
                logger.error(f"Failed to start EDR agent: {e}")
                QMessageBox.critical(self, "Error", f"Failed to start EDR agent: {e}")
    
    def stop_agent(self):
        """Stop the EDR agent."""
        if self.agent and self.agent.running:
            try:
                self.agent.stop()
                self.status_label.setText("Stopped")
                self.status_label.setStyleSheet("font-weight: bold; color: red;")
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                logger.info("EDR agent stopped")
            except Exception as e:
                logger.error(f"Failed to stop EDR agent: {e}")
                QMessageBox.critical(self, "Error", f"Failed to stop EDR agent: {e}")
    
    def update_status(self):
        """Update the status display."""
        if self.agent and self.agent.running:
            # Update uptime
            uptime = int(time.time() - self.agent.start_time)
            hours, remainder = divmod(uptime, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.uptime_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update event count
            self.event_count_label.setText(str(len(self.agent.events)))


class EDRAgentWindow(QMainWindow):
    """Main window for the EDR Agent GUI."""
    
    def __init__(self):
        super().__init__()
        self.agent = EDRAgent()
        self.init_ui()
        self.setup_agent()
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)  # Update every second
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("EDR Agent Manager")
        self.setGeometry(100, 100, 1000, 700)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        
        # Dashboard tab
        self.dashboard_tab = self.create_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        
        # Events tab
        self.events_tab = self.create_events_tab()
        self.tabs.addTab(self.events_tab, "Events")
        
        # Configuration tab
        self.config_tab = self.create_config_tab()
        self.tabs.addTab(self.config_tab, "Configuration")
        
        # Add tabs to layout
        layout.addWidget(self.tabs)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Set window icon
        try:
            self.setWindowIcon(QIcon("edr_icon.png"))
        except:
            pass  # Icon not found, use default
    
    def create_dashboard_tab(self) -> QWidget:
        """Create the dashboard tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Agent status
        self.status_widget = AgentStatusWidget()
        self.status_widget.set_agent(self.agent)
        
        # Add widgets to layout
        layout.addWidget(self.status_widget)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        return tab
    
    def create_events_tab(self) -> QWidget:
        """Create the events tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Event table
        self.event_table = EDREventTable()
        
        # Add widgets to layout
        layout.addWidget(self.event_table)
        
        # Add buttons
        button_layout = QHBoxLayout()
        
        self.clear_events_btn = QPushButton("Clear Events")
        self.clear_events_btn.clicked.connect(self.clear_events)
        
        self.export_events_btn = QPushButton("Export Events")
        self.export_events_btn.clicked.connect(self.export_events)
        
        button_layout.addWidget(self.clear_events_btn)
        button_layout.addWidget(self.export_events_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return tab
    
    def create_config_tab(self) -> QWidget:
        """Create the configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Configuration form
        form = QFormLayout()
        
        # Agent ID
        self.agent_id_edit = QLineEdit(self.agent.config.get('agent_id', ''))
        form.addRow("Agent ID:", self.agent_id_edit)
        
        # Log level
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        current_level = self.agent.config.get('log_level', 'INFO')
        index = self.log_level_combo.findText(current_level.upper())
        if index >= 0:
            self.log_level_combo.setCurrentIndex(index)
        form.addRow("Log Level:", self.log_level_combo)
        
        # Enable/disable components
        self.enable_file_monitoring = QCheckBox()
        self.enable_file_monitoring.setChecked(self.agent.config.get('enable_file_monitoring', True))
        form.addRow("File Monitoring:", self.enable_file_monitoring)
        
        self.enable_process_monitoring = QCheckBox()
        self.enable_process_monitoring.setChecked(self.agent.config.get('enable_process_monitoring', True))
        form.addRow("Process Monitoring:", self.enable_process_monitoring)
        
        self.enable_network_monitoring = QCheckBox()
        self.enable_network_monitoring.setChecked(self.agent.config.get('enable_network_monitoring', True))
        form.addRow("Network Monitoring:", self.enable_network_monitoring)
        
        # Add form to layout
        layout.addLayout(form)
        
        # Save button
        self.save_config_btn = QPushButton("Save Configuration")
        self.save_config_btn.clicked.connect(self.save_config)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.save_config_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        return tab
    
    def setup_agent(self):
        """Set up the EDR agent with callbacks."""
        # Register callbacks
        self.agent.register_callback('event', self.on_agent_event)
        self.agent.register_callback('start', self.on_agent_start)
        self.agent.register_callback('stop', self.on_agent_stop)
    
    def on_agent_event(self, event: EDREvent):
        """Handle agent events."""
        try:
            # Ensure we're in the main thread when updating the UI
            if not isinstance(event, EDREvent):
                logger.error(f"Received invalid event type: {type(event)}")
                return
                
            # Add event to the table
            self.event_table.add_event(event)
            
            # Update status bar
            details = str(event.details)[:50] + '...' if len(str(event.details)) > 50 else str(event.details)
            self.status_bar.showMessage(f"New {event.severity.value} event: {event.event_type} - {details}", 5000)
            
            # Log the event
            logger.info(f"Event received - Type: {event.event_type}, Severity: {event.severity}")
            
        except Exception as e:
            logger.error(f"Error handling agent event: {e}", exc_info=True)
    
    def on_agent_start(self):
        """Handle agent start event."""
        self.status_bar.showMessage("EDR agent started", 3000)
    
    def on_agent_stop(self):
        """Handle agent stop event."""
        self.status_bar.showMessage("EDR agent stopped", 3000)
    
    def update_status(self):
        """Update the status display."""
        self.status_widget.update_status()
    
    def clear_events(self):
        """Clear all events from the table."""
        reply = QMessageBox.question(
            self, 'Clear Events',
            'Are you sure you want to clear all events?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.event_table.setRowCount(0)
            if self.agent:
                self.agent.events.clear()
    
    def export_events(self):
        """Export events to a file."""
        if not self.agent or not self.agent.events:
            QMessageBox.information(self, "No Events", "There are no events to export.")
            return
        
        # TODO: Implement file dialog and export logic
        QMessageBox.information(self, "Export Events", "Export functionality will be implemented here.")
    
    def save_config(self):
        """Save the configuration."""
        try:
            # Update agent config
            self.agent.config.update({
                'agent_id': self.agent_id_edit.text(),
                'log_level': self.log_level_combo.currentText().lower(),
                'enable_file_monitoring': self.enable_file_monitoring.isChecked(),
                'enable_process_monitoring': self.enable_process_monitoring.isChecked(),
                'enable_network_monitoring': self.enable_network_monitoring.isChecked(),
            })
            
            # TODO: Save config to file
            
            QMessageBox.information(self, "Success", "Configuration saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {e}")
    
    def closeEvent(self, event):
        """Handle window close event."""
        if self.agent and self.agent.running:
            reply = QMessageBox.question(
                self, 'Agent Running',
                'The EDR agent is still running. Are you sure you want to quit?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.agent.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    """Main entry point for the EDR Agent GUI."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = EDRAgentWindow()
    window.show()
    
    # Start the application event loop
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
