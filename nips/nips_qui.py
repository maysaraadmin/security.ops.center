"""
NIPS GUI Module - PyQt5 Version

Provides a graphical interface for the Network Intrusion Prevention System.
Using PyQt5 for the user interface.
"""
import sys
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Callable
import queue
import threading
import json
import os
import ipaddress
import socket
import time
import uuid
from datetime import datetime
from dataclasses import dataclass

# PyQt5 imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QWidget, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QStatusBar, QToolBar, QAction, QDockWidget, QTextEdit,
    QComboBox, QLineEdit, QMessageBox, QFileDialog, QSplitter, QCheckBox,
    QDialog, QFormLayout, QSpinBox, QGroupBox, QScrollArea, QSpacerItem,
    QSizePolicy, QMenu, QInputDialog, QSystemTrayIcon
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QObject
from PyQt5.QtGui import QIcon, QFont, QColor, QTextCursor, QTextCharFormat, QDoubleSpinBox, QProgressBar

# Import NIPS modules
from nips.anomaly import base_detector
from nips.cluster.cluster_manager import ClusterManager
from nips.forensics.logger import ForensicLogger
from nips.inspection.tls_inspector import TLSInspector
from nips.response.blocking_engine import BlockingEngine
from nips.rules.base_rule import BaseRule
from nips.threat_intel.feed_manager import ThreatFeedManager
from nips.threat_intel.ioc_processor import IOCProcessor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='nips_qt5.log',
    filemode='a'
)
logger = logging.getLogger('nips.qt5gui')

@dataclass
class Alert:
    """Class to represent a security alert."""
    id: str
    timestamp: str
    severity: str
    source_ip: str
    destination_ip: str
    protocol: str
    description: str
    rule_id: str = ""
    action: str = "detected"
    details: str = ""

class AlertProcessor(QThread):
    """Worker thread for processing alerts in the background."""
    alert_received = pyqtSignal(dict)  # Signal emitted when a new alert is received
    
    def __init__(self, alert_queue):
        super().__init__()
        self.alert_queue = alert_queue
        self.running = True
        self.paused = False
        self.alert_count = 0
        self.severity_counts = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }
        self.alert_history = []
        self.max_history = 1000  # Maximum number of alerts to keep in history
    
    def run(self):
        """Main thread loop for processing alerts."""
        self.process_alerts()
    
    def process_alerts(self):
        """Process alerts from the queue."""
        while self.running:
            try:
                if not self.paused and not self.alert_queue.empty():
                    alert = self.alert_queue.get()
                    if alert:
                        self.alert_count += 1
                        
                        # Update severity counts
                        severity = alert.get('severity', 'low').lower()
                        if severity in self.severity_counts:
                            self.severity_counts[severity] += 1
                        
                        # Add timestamp if not present
                        if 'timestamp' not in alert:
                            alert['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Add to history and trim if needed
                        self.alert_history.append(alert)
                        if len(self.alert_history) > self.max_history:
                            self.alert_history.pop(0)
                        
                        # Emit the alert to the main thread
                        self.alert_received.emit(alert)
                        
                        # Mark task as done
                        self.alert_queue.task_done()
                
                # Small sleep to prevent high CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in alert processor: {e}", exc_info=True)
    
    def pause(self):
        """Pause alert processing."""
        self.paused = True
    
    def resume(self):
        """Resume alert processing."""
        self.paused = False
    
    def get_alert_stats(self):
        """Get statistics about processed alerts.
        
        Returns:
            dict: Dictionary containing alert statistics
        """
        return {
            'total': self.alert_count,
            'severity': self.severity_counts,
            'active_alerts': len([a for a in self.alert_history if a.get('status') != 'resolved'])
        }
    
    def get_recent_alerts(self, limit=50):
        """Get the most recent alerts.
        
        Args:
            limit (int): Maximum number of alerts to return
            
        Returns:
            list: List of recent alert dictionaries
        """
        return self.alert_history[-limit:]
    
    def clear_alerts(self):
        """Clear all alerts and reset counters."""
        self.alert_history.clear()
        self.alert_count = 0
        self.severity_counts = {k: 0 for k in self.severity_counts}
    
    def stop(self):
        """Stop the alert processor."""
        self.running = False
        self.wait()  # Wait for the thread to finish

class AlertWorker(QObject):
    """Worker thread for processing alerts in the background."""
    alert_received = pyqtSignal(dict)  # Signal emitted when a new alert is received
    
    def __init__(self, alert_queue):
        super().__init__()
        self.alert_queue = alert_queue
        self.running = True
        self.paused = False
    
    def process_alerts(self):
        """Process alerts from the queue."""
        while self.running:
            try:
                if not self.paused and not self.alert_queue.empty():
                    alert = self.alert_queue.get()
                    if alert:
                        # Add timestamp if not present
                        if 'timestamp' not in alert:
                            alert['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Emit the alert to the main thread
                        self.alert_received.emit(alert)
                        
                        # Mark task as done
                        self.alert_queue.task_done()
                
                # Small sleep to prevent high CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in alert worker: {e}", exc_info=True)
    
    def pause(self):
        """Pause alert processing."""
        self.paused = True
    
    def resume(self):
        """Resume alert processing."""
        self.paused = False
    
    def stop(self):
        """Stop the alert worker."""
        self.running = False

class RuleEditorDialog(QDialog):
    """Dialog for adding/editing NIPS rules."""
    
    def __init__(self, parent=None, rule_data=None):
        """Initialize the rule editor dialog.
        
        Args:
            parent: Parent widget
            rule_data: Dictionary containing rule data to edit, or None for a new rule
        """
        super().__init__(parent)
        self.rule_data = rule_data or {}
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("Edit Rule" if self.rule_data else "Add New Rule")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        
        # Create form layout for rule properties
        form_layout = QFormLayout()
        
        # Rule ID
        self.id_edit = QLineEdit(self.rule_data.get('id', ''))
        if self.rule_data:
            self.id_edit.setReadOnly(True)  # Don't allow changing ID of existing rules
        form_layout.addRow("Rule ID:", self.id_edit)
        
        # Rule Name
        self.name_edit = QLineEdit(self.rule_data.get('name', ''))
        form_layout.addRow("Name*:", self.name_edit)
        
        # Description
        self.desc_edit = QTextEdit(self.rule_data.get('description', ''))
        self.desc_edit.setMaximumHeight(100)
        form_layout.addRow("Description*:", self.desc_edit)
        
        # Severity
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["Low", "Medium", "High", "Critical"])
        if 'severity' in self.rule_data:
            index = self.severity_combo.findText(self.rule_data['severity'])
            if index >= 0:
                self.severity_combo.setCurrentIndex(index)
        form_layout.addRow("Severity*:", self.severity_combo)
        
        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItems(["alert", "block", "log"])
        if 'action' in self.rule_data:
            index = self.action_combo.findText(self.rule_data['action'])
            if index >= 0:
                self.action_combo.setCurrentIndex(index)
        form_layout.addRow("Action*:", self.action_combo)
        
        # Protocol
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["any", "tcp", "udp", "icmp", "http", "https", "dns"])
        if 'protocol' in self.rule_data:
            index = self.protocol_combo.findText(self.rule_data['protocol'])
            if index >= 0:
                self.protocol_combo.setCurrentIndex(index)
        form_layout.addRow("Protocol*:", self.protocol_combo)
        
        # Source IP
        self.src_ip_edit = QLineEdit(self.rule_data.get('source_ip', 'any'))
        form_layout.addRow("Source IP/CIDR*:", self.src_ip_edit)
        
        # Source Port
        self.src_port_edit = QLineEdit(self.rule_data.get('source_port', 'any'))
        form_layout.addRow("Source Port(s):", self.src_port_edit)
        
        # Destination IP
        self.dst_ip_edit = QLineEdit(self.rule_data.get('destination_ip', 'any'))
        form_layout.addRow("Destination IP/CIDR*:", self.dst_ip_edit)
        
        # Destination Port
        self.dst_port_edit = QLineEdit(self.rule_data.get('destination_port', 'any'))
        form_layout.addRow("Destination Port(s):", self.dst_port_edit)
        
        # Pattern/Content (for content-based rules)
        self.pattern_edit = QLineEdit(self.rule_data.get('pattern', ''))
        form_layout.addRow("Content Pattern (regex):", self.pattern_edit)
        
        # Enabled
        self.enabled_check = QCheckBox()
        self.enabled_check.setChecked(self.rule_data.get('enabled', True))
        form_layout.addRow("Enabled:", self.enabled_check)
        
        # Add form to a scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_content.setLayout(form_layout)
        scroll.setWidget(scroll_content)
        
        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.validate_and_accept)
        button_box.rejected.connect(self.reject)
        
        # Add widgets to main layout
        layout.addWidget(scroll)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def validate_and_accept(self):
        """Validate the form and accept if valid."""
        # Basic validation
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation Error", "Rule name is required.")
            return
        
        if not self.desc_edit.toPlainText().strip():
            QMessageBox.warning(self, "Validation Error", "Rule description is required.")
            return
        
        # Validate IP addresses if provided
        for field, name in [
            (self.src_ip_edit, "Source IP"),
            (self.dst_ip_edit, "Destination IP")
        ]:
            ip = field.text().strip()
            if ip.lower() != 'any':
                try:
                    if '/' in ip:  # CIDR notation
                        ipaddress.ip_network(ip, strict=False)
                    else:  # Single IP
                        ipaddress.ip_address(ip)
                except ValueError as e:
                    QMessageBox.warning(self, "Validation Error", f"Invalid {name}: {str(e)}")
                    return
        
        # Validate ports if provided
        for field, name in [
            (self.src_port_edit, "Source Port"),
            (self.dst_port_edit, "Destination Port")
        ]:
            port_str = field.text().strip()
            if port_str.lower() != 'any':
                try:
                    for port in port_str.split(','):
                        port = port.strip()
                        if '-' in port:  # Port range
                            start, end = map(int, port.split('-'))
                            if not (0 <= start <= 65535 and 0 <= end <= 65535):
                                raise ValueError("Ports must be between 0 and 65535")
                            if start > end:
                                raise ValueError("Start port must be less than or equal to end port")
                        else:  # Single port
                            port_num = int(port)
                            if not (0 <= port_num <= 65535):
                                raise ValueError("Ports must be between 0 and 65535")
                except ValueError as e:
                    QMessageBox.warning(self, "Validation Error", f"Invalid {name}: {str(e)}")
                    return
        
        self.accept()
    
    def get_rule_data(self):
        """Get the rule data from the form.
        
        Returns:
            dict: Dictionary containing the rule data
        """
        rule = {
            'id': self.id_edit.text().strip() or self.generate_rule_id(),
            'name': self.name_edit.text().strip(),
            'description': self.desc_edit.toPlainText().strip(),
            'severity': self.severity_combo.currentText(),
            'action': self.action_combo.currentText(),
            'protocol': self.protocol_combo.currentText(),
            'source_ip': self.src_ip_edit.text().strip(),
            'source_port': self.src_port_edit.text().strip() or 'any',
            'destination_ip': self.dst_ip_edit.text().strip(),
            'destination_port': self.dst_port_edit.text().strip() or 'any',
            'pattern': self.pattern_edit.text().strip(),
            'enabled': self.enabled_check.isChecked(),
            'created_at': self.rule_data.get('created_at', datetime.now().isoformat()),
            'updated_at': datetime.now().isoformat()
        }
        
        # Preserve any additional fields from the original rule
        for key, value in self.rule_data.items():
            if key not in rule:
                rule[key] = value
        
        return rule
    
    def generate_rule_id(self):
        """Generate a new rule ID.
        
        Returns:
            str: A new rule ID
        """
        # This is a simple implementation - you might want to use a more robust method
        return f"R{int(time.time()) % 1000000:06d}"


class NIPSGUI(QMainWindow):
    """Main NIPS GUI application using PyQt5."""
    
    def __init__(self):
        """Initialize the NIPS GUI."""
        super().__init__()
        logger.info("Initializing NIPS Qt5 GUI...")
        
        try:
            # Initialize NIPS components
            self.monitoring = False
            self.alerts = []
            self.alert_queue = queue.Queue()
            self.rules = {}
            self.rules_modified = False  # Track if rules have been modified since last save
            self.current_ruleset_path = None  # Path to the currently loaded ruleset
            self.threats_blocked = 0
            self.packets_analyzed = 0
            self.connections_active = 0
            self.start_time = datetime.now()
            
            # Alert processing
            self.alert_processor = AlertProcessor(self.alert_queue)
            self.alert_processor.alert_received.connect(self.handle_new_alert)
            
            # Alert statistics
            self.alert_stats = {
                'total': 0,
                'severity': {
                    'low': 0,
                    'medium': 0,
                    'high': 0,
                    'critical': 0
                },
                'active_alerts': 0
            }
            
            # Set up the UI
            self.init_ui()
            
            # Start alert processor
            self.start_alert_processor()
            
            logger.info("NIPS Qt5 GUI initialization complete")
            
        except Exception as e:
            logger.error(f"Error initializing NIPS Qt5 GUI: {e}")
            raise
    
    def init_ui(self):
        """Set up the user interface."""
        # Set window properties
        self.setWindowTitle("Network Intrusion Prevention System (NIPS) - PyQt5")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)
        
        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbars
        self.create_toolbars()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create main content area
        self.create_main_content()
        
        # Create dock widgets
        self.create_dock_widgets()
        
        # Start the alert processing thread
        self.start_alert_processor()
    
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        # Add File menu actions
        new_action = QAction(QIcon.fromTheme("document-new"), "&New Ruleset", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_ruleset)
        file_menu.addAction(new_action)
        
        open_action = QAction(QIcon.fromTheme("document-open"), "&Open Ruleset...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_ruleset)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        self.save_action = QAction(QIcon.fromTheme("document-save"), "&Save Ruleset", self)
        self.save_action.setShortcut("Ctrl+S")
        self.save_action.triggered.connect(lambda: self.save_ruleset())
        file_menu.addAction(self.save_action)
        
        save_as_action = QAction("Save Ruleset &As...", self)
        save_as_action.triggered.connect(lambda: self.save_ruleset(None))
        file_menu.addAction(save_as_action)
        
        file_menu.addSeparator()
        
        export_alerts_action = QAction("Export &Alerts...", self)
        export_alerts_action.triggered.connect(self.export_alerts)
        file_menu.addAction(export_alerts_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Monitoring menu
        monitoring_menu = menubar.addMenu("&Monitoring")
        
        # Add Monitoring menu actions
        self.start_action = QAction(QIcon.fromTheme("media-playback-start"), "&Start Monitoring", self)
        self.start_action.setShortcut("Ctrl+M")
        self.start_action.triggered.connect(self.start_monitoring)
        monitoring_menu.addAction(self.start_action)
        
        self.stop_action = QAction(QIcon.fromTheme("media-playback-stop"), "S&top Monitoring", self)
        self.stop_action.setShortcut("Ctrl+T")
        self.stop_action.triggered.connect(self.stop_monitoring)
        self.stop_action.setEnabled(False)
        monitoring_menu.addAction(self.stop_action)
        
        # View menu
        self.view_menu = menubar.addMenu("&View")
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        # Will be populated with tools
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbars(self):
        """Create toolbars."""
        # Main toolbar
        self.main_toolbar = self.addToolBar("Main Toolbar")
        self.main_toolbar.setIconSize(QSize(24, 24))
        
        # Add actions to toolbar
        self.main_toolbar.addAction(self.start_action)
        self.main_toolbar.addAction(self.stop_action)
        self.main_toolbar.addSeparator()
        
        # Add spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.main_toolbar.addWidget(spacer)
        
        # Status indicators
        self.status_indicator = QLabel("Status: Stopped")
        self.main_toolbar.addWidget(self.status_indicator)
    
    def create_main_content(self):
        """Create the main content area."""
        # Create a splitter for the main content
        splitter = QSplitter(Qt.Vertical)
        
        # Create tabs for different views
        self.tabs = QTabWidget()
        
        # Dashboard tab
        self.dashboard_tab = QWidget()
        self.setup_dashboard()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        
        # Alerts tab
        self.alerts_tab = QWidget()
        self.setup_alerts_tab()
        self.tabs.addTab(self.alerts_tab, "Alerts")
        
        # Rules tab
        self.rules_tab = QWidget()
        self.setup_rules_tab()
        self.tabs.addTab(self.rules_tab, "Rules")
        
        # Logs tab
        self.logs_tab = QWidget()
        self.setup_logs_tab()
        self.tabs.addTab(self.logs_tab, "Logs")
        
        # Add tabs to splitter
        splitter.addWidget(self.tabs)
        
        # Set the splitter as the central widget
        self.main_layout.addWidget(splitter)
    
    def create_dock_widgets(self):
        """Create dockable widgets."""
        # Alert details dock
        self.alert_details_dock = QDockWidget("Alert Details", self)
        self.alert_details_dock.setObjectName("AlertDetailsDock")
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        self.alert_details_dock.setWidget(self.alert_details)
        self.addDockWidget(Qt.RightDockWidgetArea, self.alert_details_dock)
        
        # System status dock
        self.status_dock = QDockWidget("System Status", self)
        self.status_dock.setObjectName("StatusDock")
        status_widget = QWidget()
        status_layout = QVBoxLayout()
        
        # Add status indicators
        self.uptime_label = QLabel("Uptime: 00:00:00")
        self.packets_label = QLabel("Packets Analyzed: 0")
        self.threats_label = QLabel("Threats Blocked: 0")
        self.connections_label = QLabel("Active Connections: 0")
        
        for widget in [self.uptime_label, self.packets_label, 
                      self.threats_label, self.connections_label]:
            status_layout.addWidget(widget)
        
        status_widget.setLayout(status_layout)
        self.status_dock.setWidget(status_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.status_dock)
        
        # Update the view menu with dock widget toggle actions
        self.view_menu = self.menuBar().findChild(QMenu, "View")
        if self.view_menu:
            self.view_menu.addAction(self.alert_details_dock.toggleViewAction())
            self.view_menu.addAction(self.status_dock.toggleViewAction())
    
    def setup_dashboard(self):
        """Set up the dashboard tab."""
        layout = QVBoxLayout()
        
        # Add a welcome label
        welcome_label = QLabel("Network Intrusion Prevention System - Dashboard")
        welcome_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(welcome_label)
        
        # Add some statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QGridLayout()
        
        # Add stats widgets here
        self.dashboard_uptime = QLabel("Uptime: 00:00:00")
        self.dashboard_packets = QLabel("Packets Analyzed: 0")
        self.dashboard_threats = QLabel("Threats Blocked: 0")
        self.dashboard_connections = QLabel("Active Connections: 0")
        
        stats_layout.addWidget(self.dashboard_uptime, 0, 0)
        stats_layout.addWidget(self.dashboard_packets, 0, 1)
        stats_layout.addWidget(self.dashboard_threats, 1, 0)
        stats_layout.addWidget(self.dashboard_connections, 1, 1)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Add a start/stop button
        self.dashboard_start_btn = QPushButton("Start Monitoring")
        self.dashboard_start_btn.clicked.connect(self.toggle_monitoring)
        layout.addWidget(self.dashboard_start_btn)
        
        # Add a stretch to push everything to the top
        layout.addStretch()
        
        self.dashboard_tab.setLayout(layout)
    
    def setup_alerts_tab(self):
        """Set up the alerts tab with filtering and detailed view capabilities."""
        self.alerts_tab = QWidget()
        main_layout = QVBoxLayout()
        
        # Create a splitter for alerts list and details
        splitter = QSplitter(Qt.Vertical)
        
        # Top panel - Alerts table with filter controls
        top_panel = QWidget()
        layout = QVBoxLayout()
        
        # Add filter controls
        filter_layout = QHBoxLayout()
        
        # Severity filter
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Low", "Medium", "High", "Critical"])
        self.severity_filter.currentTextChanged.connect(self.filter_alerts)
        filter_layout.addWidget(self.severity_filter)
        
        # Time filter
        filter_layout.addWidget(QLabel("Time:"))
        self.time_filter = QComboBox()
        self.time_filter.addItems(["All Time", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"])
        self.time_filter.currentTextChanged.connect(self.filter_alerts)
        filter_layout.addWidget(self.time_filter)
        
        # Search box
        filter_layout.addWidget(QLabel("Search:"))
        self.alert_search = QLineEdit()
        self.alert_search.setPlaceholderText("Search alerts...")
        self.alert_search.textChanged.connect(self.filter_alerts)
        filter_layout.addWidget(self.alert_search)
        
        # Apply filter button (kept for backward compatibility)
        apply_filter_btn = QPushButton("Apply Filters")
        apply_filter_btn.clicked.connect(self.filter_alerts)
        filter_layout.addWidget(apply_filter_btn)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(8)  # ID, Timestamp, Severity, Source, Destination, Protocol, Description, Status
        self.alerts_table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Severity", "Source", "Destination", "Protocol", "Description", "Status"
        ])
        self.alerts_table.setColumnHidden(0, True)  # Hide ID column
        
        # Configure table properties
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._sort_alerts_table)
        
        # Set column widths
        self.alerts_table.setColumnWidth(1, 150)  # Timestamp
        self.alerts_table.setColumnWidth(2, 80)   # Severity
        self.alerts_table.setColumnWidth(3, 150)  # Source
        self.alerts_table.setColumnWidth(4, 150)  # Destination
        self.alerts_table.setColumnWidth(5, 80)   # Protocol
        self.alerts_table.setColumnWidth(7, 100)  # Status
        
        # Configure table behavior
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alerts_table.setSelectionMode(QTableWidget.ExtendedSelection)  # Allow multiple selection
        self.alerts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alerts_table.setSortingEnabled(True)
        
        # Set up context menu
        self.alerts_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.alerts_table.customContextMenuRequested.connect(self._show_alerts_context_menu)
        
        # Connect double-click to view details
        self.alerts_table.doubleClicked.connect(
            lambda: self._view_alert_details() if self.alerts_table.currentRow() >= 0 else None
        )
        
        # Add table to layout with stretch
        layout.addWidget(self.alerts_table)
        
        # Bottom panel - Alert details
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        self.alert_details.setMaximumHeight(150)
        self.alert_details.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        
        # Add widgets to splitter
        top_panel.setLayout(layout)
        splitter.addWidget(top_panel)
        splitter.addWidget(self.alert_details)
        splitter.setStretchFactor(0, 3)  # 3/4 for alerts table
        splitter.setStretchFactor(1, 1)  # 1/4 for details
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Action buttons
        self.acknowledge_btn = QPushButton("Acknowledge")
        self.acknowledge_btn.setToolTip("Mark selected alert(s) as acknowledged")
        self.acknowledge_btn.clicked.connect(self.acknowledge_alert)
        button_layout.addWidget(self.acknowledge_btn)
        
        self.escalate_btn = QPushButton("Escalate")
        self.escalate_btn.setToolTip("Escalate selected alert(s)")
        self.escalate_btn.clicked.connect(self.escalate_alert)
        button_layout.addWidget(self.escalate_btn)
        
        self.view_btn = QPushButton("View Details")
        self.view_btn.setToolTip("View detailed information about the selected alert")
        self.view_btn.clicked.connect(self._view_alert_details)
        button_layout.addWidget(self.view_btn)
        
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setToolTip("Copy selected alert details to clipboard")
        self.copy_btn.clicked.connect(self._copy_alert_to_clipboard)
        button_layout.addWidget(self.copy_btn)
        
        button_layout.addStretch()
        
        # Utility buttons
        clear_btn = QPushButton("Clear All")
        clear_btn.setToolTip("Clear all alerts")
        clear_btn.clicked.connect(self.clear_alerts)
        button_layout.addWidget(clear_btn)
        
        self.export_btn = QPushButton("Export...")
        self.export_btn.setToolTip("Export alerts to file (CSV, JSON, or text)")
        self.export_btn.clicked.connect(self.export_alerts)
        button_layout.addWidget(self.export_btn)
        
        # Disable export button if no alerts
        self.export_btn.setEnabled(len(self.alerts) > 0)
        
        # Add widgets to main layout
        main_layout.addWidget(splitter)
        main_layout.addLayout(button_layout)
        self.alerts_tab.setLayout(main_layout)
        
        # Initialize alert filters
        self.alert_filters = {
            'severity': None,
            'search_text': '',
            'time_range': None
        }
        
        # Connect signals for filter updates
        self.severity_filter.currentTextChanged.connect(self.update_alert_filters)
        self.alert_search.textChanged.connect(self.update_alert_filters)
        self.time_filter.currentTextChanged.connect(self.update_alert_filters)
    
    def setup_rules_tab(self):
        """Set up the rules tab with a table and management controls."""
        layout = QVBoxLayout()
        
        # Add a label
        label = QLabel("Intrusion Detection/Prevention Rules")
        label.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(label)
        
        # Create a search/filter bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.rule_search = QLineEdit()
        self.rule_search.setPlaceholderText("Search rules...")
        self.rule_search.textChanged.connect(self.filter_rules)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.rule_search)
        layout.addLayout(search_layout)
        
        # Add a table for rules with better styling
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(6)
        self.rules_table.setHorizontalHeaderLabels(["", "ID", "Name", "Severity", "Action", "Description"])
        
        # Set column widths
        header = self.rules_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Checkbox
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # ID
        header.setSectionResizeMode(2, QHeaderView.Stretch)          # Name
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents) # Severity
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents) # Action
        header.setSectionResizeMode(5, QHeaderView.Stretch)          # Description
        
        # Enable sorting
        self.rules_table.setSortingEnabled(True)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Set alternating row colors for better readability
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #e0e0e0;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #b8d6f7;
                color: #000000;
            }
        """)
        
        layout.addWidget(self.rules_table)
        
        # Add rule management buttons
        button_layout = QHBoxLayout()
        
        # Action buttons
        self.add_rule_btn = QPushButton("Add Rule")
        self.add_rule_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_FileIcon')))
        self.add_rule_btn.clicked.connect(self.add_rule)
        
        self.edit_rule_btn = QPushButton("Edit Rule")
        self.edit_rule_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_DesktopIcon')))
        self.edit_rule_btn.clicked.connect(self.edit_rule)
        self.edit_rule_btn.setEnabled(False)
        
        self.delete_rule_btn = QPushButton("Delete Rule")
        self.delete_rule_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_TrashIcon')))
        self.delete_rule_btn.clicked.connect(self.delete_rule)
        self.delete_rule_btn.setEnabled(False)
        
        # Toggle buttons
        self.enable_rule_btn = QPushButton("Enable")
        self.enable_rule_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_DialogYesButton')))
        self.enable_rule_btn.clicked.connect(lambda: self.toggle_rules(True))
        self.enable_rule_btn.setEnabled(False)
        
        self.disable_rule_btn = QPushButton("Disable")
        self.disable_rule_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_DialogNoButton')))
        self.disable_rule_btn.clicked.connect(lambda: self.toggle_rules(False))
        self.disable_rule_btn.setEnabled(False)
        
        # Import/Export buttons
        self.import_btn = QPushButton("Import Rules")
        self.import_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_ArrowUp')))
        self.import_btn.clicked.connect(self.import_rules)
        
        self.export_btn = QPushButton("Export Rules")
        self.export_btn.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_ArrowDown')))
        self.export_btn.clicked.connect(self.export_rules)
        
        # Add buttons to layout
        button_layout.addWidget(self.add_rule_btn)
        button_layout.addWidget(self.edit_rule_btn)
        button_layout.addWidget(self.delete_rule_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.enable_rule_btn)
        button_layout.addWidget(self.disable_rule_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.import_btn)
        button_layout.addWidget(self.export_btn)
        
        # Connect selection changes to update button states
        self.rules_table.itemSelectionChanged.connect(self.update_rule_buttons)
        
        layout.addLayout(button_layout)
        self.rules_tab.setLayout(layout)
        
        # Initialize save action state
        self.update_save_action_state()
        
        # Load initial rules
        self.load_rules()
    
    def load_rules(self):
        """Load rules from the NIPS rules engine."""
        try:
            # Clear existing rules
            self.rules_table.setRowCount(0)
            self.rules = {}
            self.mark_rules_modified(False)
            
            # TODO: Load rules from the NIPS rules engine
            # For now, add some sample rules
            sample_rules = [
                {"id": "1001", "name": "SQL Injection Attempt", "severity": "High", 
                 "action": "block", "enabled": True, "description": "Detects common SQL injection patterns"},
                {"id": "1002", "name": "XSS Attack", "severity": "High", 
                 "action": "block", "enabled": True, "description": "Detects cross-site scripting attempts"},
                {"id": "1003", "name": "Port Scan Detection", "severity": "Medium", 
                 "action": "alert", "enabled": True, "description": "Detects potential port scanning activities"},
                {"id": "1004", "name": "Brute Force Attempt", "severity": "High", 
                 "action": "block", "enabled": False, "description": "Detects multiple failed login attempts"},
                {"id": "1005", "name": "Malware Download", "severity": "Critical", 
                 "action": "block", "enabled": True, "description": "Blocks known malware hashes and URLs"}
            ]
            
            # Add rules to the table
            for rule in sample_rules:
                self.add_rule_to_table(rule)
                self.rules[rule['id']] = rule
            
            self.log_message(f"Loaded {len(sample_rules)} rules")
            
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load rules: {e}")
    
    def add_rule_to_table(self, rule):
        """Add a rule to the rules table."""
        try:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            
            # Add checkbox for enabled state
            enabled_widget = QWidget()
            enabled_layout = QHBoxLayout(enabled_widget)
            enabled_layout.setContentsMargins(0, 0, 0, 0)
            enabled_layout.setAlignment(Qt.AlignCenter)
            
            checkbox = QCheckBox()
            is_enabled = rule.get('enabled', False)
            checkbox.setChecked(is_enabled)
            
            # Connect the checkbox state change to update the rule's enabled state
            checkbox.stateChanged.connect(
                lambda state, rid=rule['id']: self.toggle_rule(rid, state == Qt.Checked)
            )
            enabled_layout.addWidget(checkbox)
            
            self.rules_table.setCellWidget(row, 0, enabled_widget)
            
            # Add rule details
            rule_id_item = QTableWidgetItem(rule.get('id', ''))
            rule_name_item = QTableWidgetItem(rule.get('name', ''))
            severity_item = QTableWidgetItem(rule.get('severity', 'Medium'))
            action_item = QTableWidgetItem(rule.get('action', 'alert'))
            desc_item = QTableWidgetItem(rule.get('description', ''))
            
            # Store the rule ID in the first column for easy lookup
            rule_id_item.setData(Qt.UserRole, rule['id'])
            
            # Set items
            self.rules_table.setItem(row, 1, rule_id_item)
            self.rules_table.setItem(row, 2, rule_name_item)
            self.rules_table.setItem(row, 3, severity_item)
            self.rules_table.setItem(row, 4, action_item)
            self.rules_table.setItem(row, 5, desc_item)
            
            # Set text alignment
            for col in range(self.rules_table.columnCount()):
                item = self.rules_table.item(row, col)
                if item:
                    item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            
            # Resize columns to fit content with a max width
            self.rules_table.resizeColumnsToContents()
            
            # Set column widths with reasonable limits
            for col in range(self.rules_table.columnCount()):
                width = self.rules_table.columnWidth(col)
                if width > 300:  # Max width for any column
                    self.rules_table.setColumnWidth(col, 300)
            
            # Make name and description columns take remaining space
            self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            self.rules_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
            
        except Exception as e:
            logger.error(f"Error adding rule to table: {e}")
            raise

    def delete_rule(self):
        """Delete the selected rule(s)."""
        try:
            selected_rows = self.rules_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "No Selection", "Please select one or more rules to delete.")
                return

            # Confirm deletion
            reply = QMessageBox.question(
                self, "Confirm Deletion",
                f"Are you sure you want to delete {len(selected_rows)} selected rule(s)?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                # Sort rows in reverse order to avoid index shifting issues
                rows = sorted([row.row() for row in selected_rows], reverse=True)
                deleted_rules = []

                for row in rows:
                    rule_id = self.rules_table.item(row, 1).text()
                    deleted_rules.append(rule_id)
                    
                    # Remove from the rules dictionary and table
                    if rule_id in self.rules:
                        del self.rules[rule_id]
                    self.rules_table.removeRow(row)
                
                # Update UI
                self.update_rule_buttons()
                self.mark_rules_modified()
                self.log_message(f"Deleted {len(selected_rows)} rule(s)")
                
        except Exception as e:
            logger.error(f"Error deleting rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete rule: {e}")
    
    def add_rule(self):
        """Open a dialog to add a new rule."""
        try:
            # Create and show the rule editor dialog
            dialog = RuleEditorDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                new_rule = dialog.get_rule_data()
                
                # Add to the rules dictionary
                self.rules[new_rule['id']] = new_rule
                
                # Add to the table
                self.add_rule_to_table(new_rule)
                
                # Mark rules as modified
                self.mark_rules_modified()
                
                # Log the action
                self.log_message(f"Added new rule: {new_rule['name']}")
                
                # Select the new rule
                self.rules_table.selectRow(self.rules_table.rowCount() - 1)
                
                # TODO: Save the new rule to the NIPS rules engine
                
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add rule: {e}")
    
    def edit_rule(self):
        """Edit the selected rule."""
        try:
            selected_rows = self.rules_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "No Selection", "Please select a rule to edit.")
                return
                
            if len(selected_rows) > 1:
                QMessageBox.warning(self, "Multiple Selection", "Please select only one rule to edit.")
                return
                
            # Get the selected row and rule ID
            row = selected_rows[0].row()
            rule_id = self.rules_table.item(row, 1).text()
            
            # Get the current rule data
            current_rule = self.rules.get(rule_id, {})
            
            # Open the rule editor with the current rule data
            dialog = RuleEditorDialog(self, current_rule)
            if dialog.exec_() == QDialog.Accepted:
                updated_rule = dialog.get_rule_data()
                
                # Update the rule in the rules dictionary
                self.rules[rule_id] = updated_rule
                
                # Update the table row
                self.rules_table.removeRow(row)
                self.rules_table.insertRow(row)
                self.add_rule_to_table(updated_rule)
                
                # TODO: Update the rule in the NIPS rules engine
                self.log_message(f"Updated rule: {updated_rule['name']}")
                
                # Reselect the edited rule
                self.rules_table.selectRow(row)
                
                # Mark rules as modified
                self.mark_rules_modified()
                
        except Exception as e:
            logger.error(f"Error editing rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to edit rule: {e}")
    
    def delete_rule(self):
        """Delete the selected rule(s)."""
        try:
            selected_rows = self.rules_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "No Selection", "Please select one or more rules to delete.")
                return
            
            # Confirm deletion
            reply = QMessageBox.question(
                self, "Confirm Deletion",
                f"Are you sure you want to delete {len(selected_rows)} selected rule(s)?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Sort rows in reverse order to avoid index shifting issues
                rows = sorted([row.row() for row in selected_rows], reverse=True)
                deleted_rules = []
                
                for row in rows:
                    rule_id = self.rules_table.item(row, 1).text()
                    deleted_rules.append(rule_id)
                    # Remove from the rules dictionary
                    if rule_id in self.rules:
                        del self.rules[rule_id]
                    # Remove from the table
                    self.rules_table.removeRow(row)
                
                # TODO: Delete rules from the NIPS rules engine
                self.log_message(f"Deleted {len(deleted_rules)} rule(s)")
                
                # Clear selection and update button states
                self.rules_table.clearSelection()
                self.update_rule_buttons()
                
                # Mark rules as modified
                self.mark_rules_modified()
                
        except Exception as e:
            logger.error(f"Error deleting rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete rule: {e}")
    
    def toggle_rule(self, rule_id, enabled):
        """Toggle a rule's enabled state."""
        try:
            if rule_id in self.rules:
                self.rules[rule_id]['enabled'] = enabled
                status = "enabled" if enabled else "disabled"
                self.log_message(f"Rule {rule_id} {status}")
                
                # TODO: Update the rule in the NIPS rules engine
                
                # Mark rules as modified
                self.mark_rules_modified()
                
        except Exception as e:
            logger.error(f"Error toggling rule {rule_id}: {e}")
    
    def toggle_rules(self, enable):
        """Enable or disable selected rules."""
        try:
            selected_rows = self.rules_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(
                    self, 
                    "No Selection", 
                    "Please select one or more rules to {}.".format("enable" if enable else "disable")
                )
                return
            
            for row in selected_rows:
                checkbox = self.rules_table.cellWidget(row.row(), 0).findChild(QCheckBox)
                if checkbox:
                    checkbox.setChecked(enable)
                    # The stateChanged signal will handle the rest
            
            action = "enabled" if enable else "disabled"
            self.log_message(f"{action.capitalize()} {len(selected_rows)} rule(s)")
            
            # Mark rules as modified
            self.mark_rules_modified()
            
        except Exception as e:
            logger.error(f"Error toggling rules: {e}")
            QMessageBox.critical(
                self, 
                "Error", 
                f"Failed to {'enable' if enable else 'disable'} rules: {e}"
            )
    
    def import_rules(self):
        """Import rules from a file."""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, 
                "Import Rules", 
                "", 
                "JSON Files (*.json);;YAML Files (*.yaml *.yml);;All Files (*)"
            )
            
            if not file_path:
                return  # User cancelled
            
            # TODO: Implement rule import logic
            # This would typically parse the file and add rules to the NIPS rules engine
            
            QMessageBox.information(
                self, 
                "Import Rules", 
                "Rule import functionality will be implemented in a future version."
            )
            
        except Exception as e:
            logger.error(f"Error importing rules: {e}")
            QMessageBox.critical(self, "Error", f"Failed to import rules: {e}")
    
    def export_rules(self):
        """Export selected rules to a file."""
        try:
            selected_rows = self.rules_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "No Selection", "Please select one or more rules to export.")
                return
            
            file_path, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Rules", 
                "nips_rules_export.json", 
                "JSON Files (*.json);;YAML Files (*.yaml);;All Files (*)"
            )
            
            if not file_path:
                return  # User cancelled
            
            # Collect selected rules
            rules_to_export = []
            for row in selected_rows:
                rule_id = self.rules_table.item(row.row(), 1).text()
                if rule_id in self.rules:
                    rules_to_export.append(self.rules[rule_id])
            
            # Export to file
            with open(file_path, 'w') as f:
                json.dump(rules_to_export, f, indent=2)
            
            self.log_message(f"Exported {len(rules_to_export)} rule(s) to {file_path}")
            QMessageBox.information(
                self, 
                "Export Successful", 
                f"Successfully exported {len(rules_to_export)} rule(s) to:\n{file_path}"
            )
            
        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export rules: {e}")
    
    def filter_rules(self, text):
        """Filter rules based on search text."""
        try:
            search_text = text.lower()
            
            for row in range(self.rules_table.rowCount()):
                match = False
                # Check each column for a match
                for col in range(1, self.rules_table.columnCount()):  # Skip checkbox column
                    item = self.rules_table.item(row, col)
                    if item and search_text in item.text().lower():
                        match = True
                        break
                
                # Show/hide the row based on the match
                self.rules_table.setRowHidden(row, not match if search_text else False)
                
        except Exception as e:
            logger.error(f"Error filtering rules: {e}")
    
    def update_rule_buttons(self):
        """Update the state of rule action buttons based on selection."""
        selected_rows = self.rules_table.selectionModel().selectedRows()
        has_selection = len(selected_rows) > 0
        
        # Enable/disable buttons based on selection
        self.edit_rule_btn.setEnabled(len(selected_rows) == 1)  # Only enable for single selection
        self.delete_rule_btn.setEnabled(has_selection)
        self.enable_rule_btn.setEnabled(has_selection)
        self.disable_rule_btn.setEnabled(has_selection)
        self.export_btn.setEnabled(has_selection)
        
        # If no rows are selected, disable all action buttons
        if not has_selection:
            return
        
        # Check if all selected rules are enabled/disabled
        all_enabled = True
        all_disabled = True
        
        for row in selected_rows:
            checkbox = self.rules_table.cellWidget(row.row(), 0).findChild(QCheckBox)
            if checkbox:
                if checkbox.isChecked():
                    all_disabled = False
                else:
                    all_enabled = False
        
        # Update enable/disable buttons based on selection state
        self.enable_rule_btn.setEnabled(not all_enabled)
        self.disable_rule_btn.setEnabled(not all_disabled)
    
    def setup_threat_intel_tab(self):
        """Set up the threat intelligence tab."""
        layout = QVBoxLayout()
        
        # Toolbar for threat intel actions
        toolbar = QHBoxLayout()
        
        # Add threat feed button
        self.add_feed_btn = QPushButton("Add Feed")
        self.add_feed_btn.setToolTip("Add a new threat intelligence feed")
        self.add_feed_btn.clicked.connect(self.add_threat_feed)
        toolbar.addWidget(self.add_feed_btn)
        
        # Remove feed button
        self.remove_feed_btn = QPushButton("Remove Feed")
        self.remove_feed_btn.setToolTip("Remove selected threat feed")
        self.remove_feed_btn.clicked.connect(self.remove_threat_feed)
        self.remove_feed_btn.setEnabled(False)
        toolbar.addWidget(self.remove_feed_btn)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh All")
        refresh_btn.setToolTip("Refresh all threat intelligence feeds")
        refresh_btn.clicked.connect(self.refresh_threat_feeds)
        toolbar.addWidget(refresh_btn)
        
        # Spacer
        toolbar.addStretch()
        
        # Search box
        self.threat_search = QLineEdit()
        self.threat_search.setPlaceholderText("Search threat feeds...")
        self.threat_search.textChanged.connect(self.filter_threat_feeds)
        toolbar.addWidget(QLabel("Search:"))
        toolbar.addWidget(self.threat_search)
        
        layout.addLayout(toolbar)
        
        # Threat feeds table
        self.threat_feeds_table = QTableWidget()
        self.threat_feeds_table.setColumnCount(5)
        self.threat_feeds_table.setHorizontalHeaderLabels(["", "Name", "Type", "Last Updated", "Status"])
        self.threat_feeds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.threat_feeds_table.horizontalHeader().setStretchLastSection(True)
        self.threat_feeds_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.threat_feeds_table.setSelectionMode(QTableWidget.SingleSelection)
        self.threat_feeds_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.threat_feeds_table.itemSelectionChanged.connect(self.update_threat_buttons)
        
        # Set column widths
        self.threat_feeds_table.setColumnWidth(0, 30)  # Checkbox
        self.threat_feeds_table.setColumnWidth(1, 200)  # Name
        self.threat_feeds_table.setColumnWidth(2, 100)  # Type
        self.threat_feeds_table.setColumnWidth(3, 150)  # Last Updated
        self.threat_feeds_table.setColumnWidth(4, 100)  # Status
        
        layout.addWidget(self.threat_feeds_table)
        
        # Threat indicators table
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(5)
        self.indicators_table.setHorizontalHeaderLabels(["Type", "Value", "First Seen", "Last Seen", "Source"])
        self.indicators_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.indicators_table.horizontalHeader().setStretchLastSection(True)
        self.indicators_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.indicators_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Add to splitter
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.threat_feeds_table)
        splitter.addWidget(self.indicators_table)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        layout.addWidget(splitter)
        
        # Create the tab and set the layout
        self.threat_intel_tab = QWidget()
        self.threat_intel_tab.setLayout(layout)
        self.tab_widget.addTab(self.threat_intel_tab, "Threat Intel")
        
        # Load sample feeds
        self.load_sample_feeds()
    
    def load_sample_feeds(self):
        """Load sample threat intelligence feeds."""
        try:
            sample_feeds = [
                {
                    "name": "Abuse.ch C2 Tracker",
                    "type": "C2",
                    "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
                    "enabled": True,
                    "last_updated": "",
                    "status": "Not loaded"
                },
                {
                    "name": "AlienVault OTX",
                    "type": "General",
                    "url": "https://otx.alienvault.com/api/v1/indicators/export",
                    "enabled": True,
                    "last_updated": "",
                    "status": "Not loaded"
                },
                {
                    "name": "FireEye Threat Intelligence",
                    "type": "Malware",
                    "url": "https://www.fireeye.com/blog/threat-research.html",
                    "enabled": False,
                    "last_updated": "",
                    "status": "Disabled"
                }
            ]
            
            self.threat_feeds = {}
            for i, feed in enumerate(sample_feeds):
                feed_id = f"feed_{i+1}"
                self.threat_feeds[feed_id] = feed
                self._add_feed_to_table(feed_id, feed)
                
            logger.info("Loaded sample threat intelligence feeds")
            
        except Exception as e:
            logger.error(f"Error loading sample feeds: {e}")
    
    def _add_feed_to_table(self, feed_id, feed_data):
        """Add a feed to the threat feeds table."""
        try:
            row = self.threat_feeds_table.rowCount()
            self.threat_feeds_table.insertRow(row)
            
            # Add checkbox for enabled state
            enabled_item = QTableWidgetItem()
            enabled_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            enabled_item.setCheckState(Qt.Checked if feed_data.get('enabled', False) else Qt.Unchecked)
            self.threat_feeds_table.setItem(row, 0, enabled_item)
            
            # Add feed data
            self.threat_feeds_table.setItem(row, 1, QTableWidgetItem(feed_data.get('name', '')))
            self.threat_feeds_table.setItem(row, 2, QTableWidgetItem(feed_data.get('type', '')))
            self.threat_feeds_table.setItem(row, 3, QTableWidgetItem(feed_data.get('last_updated', 'Never')))
            
            # Add status with color coding
            status_item = QTableWidgetItem(feed_data.get('status', 'Unknown'))
            if feed_data.get('status') == 'Active':
                status_item.setForeground(Qt.darkGreen)
            elif feed_data.get('status') == 'Error':
                status_item.setForeground(Qt.red)
            self.threat_feeds_table.setItem(row, 4, status_item)
            
            # Store feed ID in the first column
            self.threat_feeds_table.item(row, 1).setData(Qt.UserRole, feed_id)
            
        except Exception as e:
            logger.error(f"Error adding feed to table: {e}")
    
    def add_threat_feed(self):
        """Add a new threat intelligence feed."""
        try:
            # Create and show the add feed dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Add Threat Feed")
            dialog.setMinimumWidth(500)
            
            layout = QFormLayout(dialog)
            
            # Feed name
            name_edit = QLineEdit()
            layout.addRow("Name:", name_edit)
            
            # Feed type
            type_combo = QComboBox()
            type_combo.addItems(["C2", "Malware", "Phishing", "Exploit", "Vulnerability", "General"])
            layout.addRow("Type:", type_combo)
            
            # Feed URL
            url_edit = QLineEdit()
            url_edit.setPlaceholderText("https://example.com/feed.json")
            layout.addRow("URL:", url_edit)
            
            # Buttons
            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            button_box.accepted.connect(dialog.accept)
            button_box.rejected.connect(dialog.reject)
            layout.addRow(button_box)
            
            if dialog.exec_() == QDialog.Accepted and name_edit.text() and url_edit.text():
                # Create new feed
                feed_id = f"feed_{len(self.threat_feeds) + 1}"
                new_feed = {
                    "name": name_edit.text(),
                    "type": type_combo.currentText(),
                    "url": url_edit.text(),
                    "enabled": True,
                    "last_updated": "",
                    "status": "Not loaded"
                }
                
                # Add to feeds and table
                self.threat_feeds[feed_id] = new_feed
                self._add_feed_to_table(feed_id, new_feed)
                
                self.log_message(f"Added new threat feed: {new_feed['name']}")
                
        except Exception as e:
            logger.error(f"Error adding threat feed: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add threat feed: {e}")
    
    def remove_threat_feed(self):
        """Remove the selected threat feed."""
        try:
            selected = self.threat_feeds_table.selectedItems()
            if not selected:
                return
                
            # Get the feed ID from the first selected item's row
            row = selected[0].row()
            feed_id = self.threat_feeds_table.item(row, 1).data(Qt.UserRole)
            
            if feed_id in self.threat_feeds:
                feed_name = self.threat_feeds[feed_id]['name']
                reply = QMessageBox.question(
                    self,
                    'Confirm Removal',
                    f'Are you sure you want to remove the threat feed "{feed_name}"?',
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    # Remove from table and feeds dictionary
                    self.threat_feeds_table.removeRow(row)
                    del self.threat_feeds[feed_id]
                    self.log_message(f"Removed threat feed: {feed_name}")
        
        except Exception as e:
            logger.error(f"Error removing threat feed: {e}")
            QMessageBox.critical(self, "Error", f"Failed to remove threat feed: {e}")
    
    def refresh_threat_feeds(self):
        """Refresh all enabled threat feeds."""
        try:
            refresh_thread = threading.Thread(target=self._refresh_feeds_thread, daemon=True)
            refresh_thread.start()
            
        except Exception as e:
            logger.error(f"Error starting feed refresh: {e}")
            QMessageBox.critical(self, "Error", f"Failed to refresh threat feeds: {e}")
    
    def _refresh_feeds_thread(self):
        """Background thread for refreshing threat feeds."""
        try:
            self.log_message("Refreshing threat intelligence feeds...")
            
            # Update UI on the main thread
            self._update_feed_status("Refreshing...", "#FFA500")  # Orange for refreshing
            
            # Simulate feed refresh (in a real app, this would make HTTP requests)
            time.sleep(2)
            
            # Update status on the main thread
            self._update_feed_status("Active", "#006400")  # Dark green for active
            self.log_message("Threat intelligence feeds refreshed successfully")
            
        except Exception as e:
            logger.error(f"Error in feed refresh thread: {e}")
            self._update_feed_status("Error", "#FF0000")  # Red for error
    
    def _update_feed_status(self, status, color):
        """Update the status of feeds in the table (thread-safe)."""
        def update():
            for row in range(self.threat_feeds_table.rowCount()):
                status_item = self.threat_feeds_table.item(row, 4)
                if status_item:
                    status_item.setText(status)
                    status_item.setForeground(QColor(color))
        
        # Ensure UI updates happen on the main thread
        QMetaObject.invokeMethod(self, "_update_feed_status_callback", 
                               Qt.QueuedConnection,
                               Q_ARG(str, status),
                               Q_ARG(str, color))
    
    @pyqtSlot(str, str)
    def _update_feed_status_callback(self, status, color):
        """Callback for updating feed status (runs on main thread)."""
        for row in range(self.threat_feeds_table.rowCount()):
            status_item = self.threat_feeds_table.item(row, 4)
            if status_item:
                status_item.setText(status)
                status_item.setForeground(QColor(color))
    
    def filter_threat_feeds(self, text):
        """Filter the threat feeds table based on search text."""
        try:
            search_text = text.lower()
            
            for row in range(self.threat_feeds_table.rowCount()):
                match = False
                # Check each column for a match
                for col in range(self.threat_feeds_table.columnCount()):
                    item = self.threat_feeds_table.item(row, col)
                    if item and search_text in item.text().lower():
                        match = True
                        break
                
                # Show/hide row based on match
                self.threat_feeds_table.setRowHidden(row, not match)
                
        except Exception as e:
            logger.error(f"Error filtering threat feeds: {e}")
    
    def update_threat_buttons(self):
        """Update the state of threat intel action buttons based on selection."""
        selected = bool(self.threat_feeds_table.selectedItems())
        self.remove_feed_btn.setEnabled(selected)
    
    def setup_network_tools_tab(self):
        """Set up the network tools tab with traffic monitor and scanner."""
        layout = QVBoxLayout()
        
        # Create tab widget for different network tools
        self.tools_tab_widget = QTabWidget()
        
        # Traffic Monitor Tab
        self.setup_traffic_monitor_tab()
        
        # Network Scanner Tab
        self.setup_network_scanner_tab()
        
        layout.addWidget(self.tools_tab_widget)
        
        # Create the tab and set the layout
        self.network_tools_tab = QWidget()
        self.network_tools_tab.setLayout(layout)
        self.tab_widget.addTab(self.network_tools_tab, "Network Tools")
    
    def setup_traffic_monitor_tab(self):
        """Set up the traffic monitor tool tab."""
        traffic_tab = QWidget()
        layout = QVBoxLayout()
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # Start/Stop button
        self.traffic_start_btn = QPushButton("Start Monitoring")
        self.traffic_start_btn.setToolTip("Start/Stop traffic monitoring")
        self.traffic_start_btn.clicked.connect(self.toggle_traffic_monitor)
        toolbar.addWidget(self.traffic_start_btn)
        
        # Clear button
        clear_btn = QPushButton("Clear")
        clear_btn.setToolTip("Clear the traffic log")
        clear_btn.clicked.connect(self.clear_traffic_log)
        toolbar.addWidget(clear_btn)
        
        # Save button
        save_btn = QPushButton("Save Log")
        save_btn.setToolTip("Save traffic log to file")
        save_btn.clicked.connect(self.save_traffic_log)
        toolbar.addWidget(save_btn)
        
        # Spacer
        toolbar.addStretch()
        
        # Filter options
        filter_label = QLabel("Filter:")
        toolbar.addWidget(filter_label)
        
        self.traffic_filter = QComboBox()
        self.traffic_filter.addItems(["All Traffic", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"])
        self.traffic_filter.currentTextChanged.connect(self.filter_traffic)
        toolbar.addWidget(self.traffic_filter)
        
        layout.addLayout(toolbar)
        
        # Traffic table
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(7)
        self.traffic_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length", "Info", "Action"])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.traffic_table.horizontalHeader().setStretchLastSection(True)
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.traffic_table.setSortingEnabled(True)
        
        # Set column widths
        self.traffic_table.setColumnWidth(0, 150)  # Time
        self.traffic_table.setColumnWidth(1, 150)  # Source
        self.traffic_table.setColumnWidth(2, 150)  # Destination
        self.traffic_table.setColumnWidth(3, 80)   # Protocol
        self.traffic_table.setColumnWidth(4, 80)   # Length
        self.traffic_table.setColumnWidth(5, 250)  # Info
        self.traffic_table.setColumnWidth(6, 100)  # Action
        
        layout.addWidget(self.traffic_table)
        
        # Status bar
        self.traffic_status = QStatusBar()
        self.traffic_status.showMessage("Ready")
        layout.addWidget(self.traffic_status)
        
        traffic_tab.setLayout(layout)
        self.tools_tab_widget.addTab(traffic_tab, "Traffic Monitor")
        
        # Initialize traffic monitoring variables
        self.traffic_monitoring = False
        self.traffic_packets = []
        self.traffic_thread = None
    
    def setup_network_scanner_tab(self):
        """Set up the network scanner tool tab."""
        scanner_tab = QWidget()
        layout = QVBoxLayout()
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # Target input
        toolbar.addWidget(QLabel("Target:"))
        self.scan_target = QLineEdit()
        self.scan_target.setPlaceholderText("e.g., 192.168.1.0/24 or example.com")
        toolbar.addWidget(self.scan_target)
        
        # Port range
        toolbar.addWidget(QLabel("Ports:"))
        self.scan_ports = QLineEdit()
        self.scan_ports.setPlaceholderText("e.g., 1-1024 or 80,443,8080")
        toolbar.addWidget(self.scan_ports)
        
        # Scan type
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Quick Scan", "Full Scan", "Service Detection", "OS Detection"])
        toolbar.addWidget(self.scan_type)
        
        # Scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setToolTip("Start network scan")
        self.scan_btn.clicked.connect(self.start_network_scan)
        toolbar.addWidget(self.scan_btn)
        
        # Stop button
        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.setToolTip("Stop current scan")
        self.stop_scan_btn.clicked.connect(self.stop_network_scan)
        self.stop_scan_btn.setEnabled(False)
        toolbar.addWidget(self.stop_scan_btn)
        
        layout.addLayout(toolbar)
        
        # Scan results
        self.scan_results = QTreeWidget()
        self.scan_results.setHeaderLabels(["Host", "Status", "Ports", "OS", "Details"])
        self.scan_results.setSortingEnabled(True)
        self.scan_results.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.scan_results.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_results.customContextMenuRequested.connect(self.show_scan_context_menu)
        layout.addWidget(self.scan_results)
        
        # Scan progress
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setTextVisible(True)
        layout.addWidget(self.scan_progress)
        
        # Status bar
        self.scan_status = QStatusBar()
        self.scan_status.showMessage("Ready")
        layout.addWidget(self.scan_status)
        
        scanner_tab.setLayout(layout)
        self.tools_tab_widget.addTab(scanner_tab, "Network Scanner")
        
        # Initialize scanning variables
        self.scan_running = False
        self.scan_thread = None
    
    def toggle_traffic_monitor(self):
        """Toggle traffic monitoring on/off."""
        try:
            if self.traffic_monitoring:
                self.stop_traffic_monitor()
                self.traffic_start_btn.setText("Start Monitoring")
                self.traffic_status.showMessage("Traffic monitoring stopped")
            else:
                self.start_traffic_monitor()
                self.traffic_start_btn.setText("Stop Monitoring")
                self.traffic_status.showMessage("Traffic monitoring started")
            
            self.traffic_monitoring = not self.traffic_monitoring
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to toggle traffic monitoring: {e}")
            logger.error(f"Error toggling traffic monitoring: {e}")
    
    def start_traffic_monitor(self):
        """Start monitoring network traffic."""
        try:
            # Clear previous data
            self.traffic_packets = []
            self.traffic_table.setRowCount(0)
            
            # Start capture in a separate thread
            self.traffic_thread = threading.Thread(target=self._capture_traffic, daemon=True)
            self.traffic_thread.start()
            
            self.log_message("Started traffic monitoring")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start traffic monitoring: {e}")
            logger.error(f"Error starting traffic monitoring: {e}")
    
    def stop_traffic_monitor(self):
        """Stop monitoring network traffic."""
        try:
            # Signal the capture thread to stop
            self.traffic_monitoring = False
            
            if self.traffic_thread and self.traffic_thread.is_alive():
                self.traffic_thread.join(timeout=2.0)
            
            self.log_message("Stopped traffic monitoring")
            
        except Exception as e:
            logger.error(f"Error stopping traffic monitoring: {e}")
    
    def _capture_traffic(self):
        """Background thread for capturing network traffic."""
        try:
            self.traffic_monitoring = True
            
            # This is a placeholder for actual packet capture
            # In a real implementation, you would use a library like scapy or pyshark
            while self.traffic_monitoring:
                # Simulate packet capture
                time.sleep(0.1)
                
                # Update UI on the main thread
                self._update_traffic_table("192.168.1.100", "8.8.8.8", "TCP", 64, "HTTP GET /")
                
        except Exception as e:
            logger.error(f"Error in traffic capture thread: {e}")
    
    def _update_traffic_table(self, src, dst, protocol, length, info):
        """Update the traffic table with a new packet (thread-safe)."""
        def update():
            row = self.traffic_table.rowCount()
            self.traffic_table.insertRow(row)
            
            # Add packet data
            self.traffic_table.setItem(row, 0, QTableWidgetItem(time.strftime("%Y-%m-%d %H:%M:%S")))
            self.traffic_table.setItem(row, 1, QTableWidgetItem(src))
            self.traffic_table.setItem(row, 2, QTableWidgetItem(dst))
            self.traffic_table.setItem(row, 3, QTableWidgetItem(protocol))
            self.traffic_table.setItem(row, 4, QTableWidgetItem(str(length)))
            self.traffic_table.setItem(row, 5, QTableWidgetItem(info))
            
            # Add action button
            btn = QPushButton("Block")
            btn.clicked.connect(lambda: self.block_traffic(src, dst, protocol))
            self.traffic_table.setCellWidget(row, 6, btn)
            
            # Auto-scroll to bottom
            self.traffic_table.scrollToBottom()
            
            # Update status
            self.traffic_status.showMessage(f"Captured {row + 1} packets")
        
        # Ensure UI updates happen on the main thread
        QMetaObject.invokeMethod(self, "_update_traffic_table_callback", 
                               Qt.QueuedConnection)
    
    @pyqtSlot()
    def _update_traffic_table_callback(self):
        """Callback for updating traffic table (runs on main thread)."""
        # This would be implemented to update the traffic table
        pass
    
    def filter_traffic(self, filter_text):
        """Filter the traffic table based on the selected filter."""
        try:
            for row in range(self.traffic_table.rowCount()):
                protocol_item = self.traffic_table.item(row, 3)
                if protocol_item:
                    protocol = protocol_item.text().upper()
                    show = (filter_text == "All Traffic") or (filter_text.upper() in protocol)
                    self.traffic_table.setRowHidden(row, not show)
                    
        except Exception as e:
            logger.error(f"Error filtering traffic: {e}")
    
    def clear_traffic_log(self):
        """Clear the traffic log."""
        try:
            self.traffic_table.setRowCount(0)
            self.traffic_packets = []
            self.traffic_status.showMessage("Log cleared")
            
        except Exception as e:
            logger.error(f"Error clearing traffic log: {e}")
    
    def save_traffic_log(self):
        """Save the traffic log to a file."""
        try:
            if self.traffic_table.rowCount() == 0:
                QMessageBox.information(self, "No Data", "No traffic data to save.")
                return
                
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Traffic Log",
                "",
                "PCAP Files (*.pcap);;CSV Files (*.csv);;All Files (*)"
            )
            
            if not file_path:
                return
                
            # This is a placeholder for actual file saving logic
            # In a real implementation, you would use a library like pcapng or scapy
            with open(file_path, 'w') as f:
                f.write("Time,Source,Destination,Protocol,Length,Info\n")
                for row in range(self.traffic_table.rowCount()):
                    row_data = []
                    for col in range(6):  # Skip the action column
                        item = self.traffic_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    f.write(",".join(f'"{x}"' for x in row_data) + "\n")
            
            self.log_message(f"Saved traffic log to {file_path}")
            QMessageBox.information(self, "Success", f"Traffic log saved to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save traffic log: {e}")
            logger.error(f"Error saving traffic log: {e}")
    
    def block_traffic(self, src, dst, protocol):
        """Block traffic matching the specified criteria."""
        try:
            # This is a placeholder for actual traffic blocking logic
            # In a real implementation, you would use a firewall or iptables
            rule = {
                'action': 'block',
                'enabled': True,
                'name': f'Block {protocol} from {src} to {dst}',
                'source': src,
                'destination': dst,
                'protocol': protocol.lower(),
                'description': f'Automatically created rule to block {protocol} traffic from {src} to {dst}'
            }
            
            # Add to rules
            rule_id = str(uuid.uuid4())
            self.rules[rule_id] = rule
            self.add_rule_to_table(rule)
            
            self.log_message(f"Added rule to block {protocol} traffic from {src} to {dst}")
            QMessageBox.information(self, "Rule Added", f"Added rule to block {protocol} traffic from {src} to {dst}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block traffic: {e}")
            logger.error(f"Error blocking traffic: {e}")
    
    def start_network_scan(self):
        """Start a network scan with the specified parameters."""
        try:
            target = self.scan_target.text().strip()
            if not target:
                QMessageBox.warning(self, "Error", "Please enter a target to scan.")
                return
                
            ports = self.scan_ports.text().strip() or "1-1024"
            scan_type = self.scan_type.currentText()
            
            # Update UI
            self.scan_btn.setEnabled(False)
            self.stop_scan_btn.setEnabled(True)
            self.scan_results.clear()
            self.scan_progress.setValue(0)
            self.scan_status.showMessage(f"Starting {scan_type} on {target}...")
            
            # Start scan in a separate thread
            self.scan_running = True
            self.scan_thread = threading.Thread(
                target=self._run_network_scan,
                args=(target, ports, scan_type),
                daemon=True
            )
            self.scan_thread.start()
            
            self.log_message(f"Started {scan_type} on {target} (ports: {ports})")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start network scan: {e}")
            logger.error(f"Error starting network scan: {e}")
    
    def stop_network_scan(self):
        """Stop the currently running network scan."""
        try:
            self.scan_running = False
            self.scan_status.showMessage("Stopping scan...")
            
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=2.0)
            
            self.scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            self.scan_status.showMessage("Scan stopped by user")
            
            self.log_message("Network scan stopped by user")
            
        except Exception as e:
            logger.error(f"Error stopping network scan: {e}")
    
    def _run_network_scan(self, target, ports, scan_type):
        """Background thread for running network scans."""
        try:
            # This is a placeholder for actual scanning logic
            # In a real implementation, you would use a library like python-nmap or scapy
            total_hosts = 1  # Simulate scanning one host
            
            for i in range(1, 101):  # Simulate progress
                if not self.scan_running:
                    break
                    
                # Simulate scanning progress
                time.sleep(0.1)
                
                # Update progress on the main thread
                QMetaObject.invokeMethod(self, "_update_scan_progress",
                                      Qt.QueuedConnection,
                                      Q_ARG(int, i))
                
                # Simulate finding a host and ports
                if i == 50:
                    self._add_scan_result("192.168.1.1", "up", [80, 443, 22, 21], "Linux", "Ubuntu 20.04")
                
            # Update status when done
            if self.scan_running:
                QMetaObject.invokeMethod(self, "_scan_complete",
                                      Qt.QueuedConnection)
                
        except Exception as e:
            logger.error(f"Error in network scan thread: {e}")
            QMetaObject.invokeMethod(self, "_scan_error",
                                  Qt.QueuedConnection,
                                  Q_ARG(str, str(e)))
    
    @pyqtSlot(int)
    def _update_scan_progress(self, value):
        """Update the scan progress bar (runs on main thread)."""
        self.scan_progress.setValue(value)
        self.scan_status.showMessage(f"Scanning... {value}% complete")
    
    @pyqtSlot()
    def _scan_complete(self):
        """Handle scan completion (runs on main thread)."""
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_status.showMessage("Scan completed successfully")
        self.log_message("Network scan completed")
    
    @pyqtSlot(str)
    def _scan_error(self, error):
        """Handle scan errors (runs on main thread)."""
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_status.showMessage("Scan failed")
        QMessageBox.critical(self, "Scan Error", f"Network scan failed: {error}")
        logger.error(f"Network scan error: {error}")
    
    def _add_scan_result(self, host, status, ports, os_info, details):
        """Add a scan result to the results tree (thread-safe)."""
        def add():
            # Create a top-level item for the host
            host_item = QTreeWidgetItem([host, status, str(len(ports)) if ports else "0", os_info, details])
            self.scan_results.addTopLevelItem(host_item)
            
            # Add ports as child items
            if ports:
                for port in sorted(ports):
                    port_item = QTreeWidgetItem(["", "", str(port), "tcp" if port < 1024 else "udp", "open"])
                    host_item.addChild(port_item)
            
            # Expand the host item
            host_item.setExpanded(True)
            
            # Auto-resize columns
            for i in range(self.scan_results.columnCount()):
                self.scan_results.resizeColumnToContents(i)
        
        # Ensure UI updates happen on the main thread
        QMetaObject.invokeMethod(self, "_add_scan_result_callback",
                              Qt.QueuedConnection,
                              Q_ARG(str, host),
                              Q_ARG(str, status),
                              Q_ARG(list, ports or []),
                              Q_ARG(str, os_info or ""),
                              Q_ARG(str, details or ""))
    
    @pyqtSlot(str, str, list, str, str)
    def _add_scan_result_callback(self, host, status, ports, os_info, details):
        """Callback for adding scan results (runs on main thread)."""
        # This would be implemented to update the scan results
        pass
    
    def show_scan_context_menu(self, position):
        """Show context menu for scan results."""
        try:
            item = self.scan_results.itemAt(position)
            if not item:
                return
                
            menu = QMenu()
            
            # Add actions based on the selected item
            if item.parent():  # This is a port item
                port = int(item.text(2))
                menu.addAction(f"Block port {port}", lambda: self.block_port(port))
                menu.addAction(f"Scan port {port}", lambda: self.scan_port(item.parent().text(0), port))
            else:  # This is a host item
                host = item.text(0)
                menu.addAction(f"Ping {host}", lambda: self.ping_host(host))
                menu.addAction(f"Traceroute to {host}", lambda: self.traceroute(host))
                menu.addSeparator()
                menu.addAction(f"Add to whitelist", lambda: self.whitelist_host(host))
                menu.addAction(f"Block {host}", lambda: self.block_host(host))
            
            menu.exec_(self.scan_results.viewport().mapToGlobal(position))
            
        except Exception as e:
            logger.error(f"Error showing scan context menu: {e}")
    
    # Placeholder methods for scan context menu actions
    def block_port(self, port):
        """Block the specified port."""
        QMessageBox.information(self, "Block Port", f"Blocking port {port} (not implemented)")
    
    def scan_port(self, host, port):
        """Scan the specified port on the host."""
        QMessageBox.information(self, "Scan Port", f"Scanning {host}:{port} (not implemented)")
    
    def ping_host(self, host):
        """Ping the specified host."""
        QMessageBox.information(self, "Ping", f"Pinging {host} (not implemented)")
    
    def traceroute(self, host):
        """Perform a traceroute to the specified host."""
        QMessageBox.information(self, "Traceroute", f"Traceroute to {host} (not implemented)")
    
    def whitelist_host(self, host):
        """Add the specified host to the whitelist."""
        QMessageBox.information(self, "Whitelist", f"Added {host} to whitelist (not implemented)")
    
    def block_host(self, host):
        """Block the specified host."""
        QMessageBox.information(self, "Block Host", f"Blocked {host} (not implemented)")
    
    def setup_logs_tab(self):
        """Set up the logs tab with filtering and search capabilities."""
        layout = QVBoxLayout()
        
        # Create a toolbar for log actions
        toolbar = QHBoxLayout()
        
        # Log level filter
        toolbar.addWidget(QLabel("Log Level:"))
        self.log_level = QComboBox()
        self.log_level.addItems(["All", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level.currentTextChanged.connect(self.filter_logs)
        toolbar.addWidget(self.log_level)
        
        # Search box
        toolbar.addWidget(QLabel("Search:"))
        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Search logs...")
        self.log_search.textChanged.connect(self.search_logs)
        toolbar.addWidget(self.log_search)
        
        # Buttons
        self.clear_logs_btn = QPushButton("Clear Logs")
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        toolbar.addWidget(self.clear_logs_btn)
        
        self.save_logs_btn = QPushButton("Save Logs")
        self.save_logs_btn.clicked.connect(self.save_logs)
        toolbar.addWidget(self.save_logs_btn)
        
        # Add stretch to push buttons to the left
        toolbar.addStretch()
        
        # Add toolbar to layout
        layout.addLayout(toolbar)
        
        # Log text area with monospace font
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier New", 10))
        
        # Set up syntax highlighting for logs
        self.log_highlighter = LogHighlighter(self.log_text.document())
        
        # Set up a custom context menu for the log area
        self.log_text.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_text.customContextMenuRequested.connect(self.show_log_context_menu)
        
        # Add log text area to layout with stretch
        layout.addWidget(self.log_text)
        
        # Status bar for log info
        self.log_status = QStatusBar()
        self.log_status.showMessage("Ready")
        layout.addWidget(self.log_status)
        
        # Create the tab and set the layout
        self.logs_tab = QWidget()
        self.logs_tab.setLayout(layout)
        self.tab_widget.addTab(self.logs_tab, "Logs")
        
        # Redirect stdout and stderr to the log window
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
        
        # Log buffer to store log messages
        self.log_buffer = []
        self.max_log_lines = 10000  # Maximum number of lines to keep in memory
        
        # Start with a welcome message
        self.log_message("NIPS Logging System Initialized", "INFO")
    
    def write(self, text):
        """Override write method to capture stdout/stderr."""
        if text.strip():
            self.log_message(text.rstrip(), "INFO" if sys.stdout == self else "ERROR")
    
    def flush(self):
        """Override flush method for file-like object compatibility."""
        pass
    
    def log_message(self, message, level="INFO"):
        """Add a message to the log with the specified level.
        
        Args:
            message (str): The log message
            level (str): The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log_entry = f"{timestamp} [{level}] {message}"
            
            # Add to buffer
            self.log_buffer.append((timestamp, level, message, log_entry))
            
            # Trim buffer if it gets too large
            if len(self.log_buffer) > self.max_log_lines:
                self.log_buffer = self.log_buffer[-self.max_log_lines:]
            
            # Update the log display if the tab is visible
            if self.tab_widget.currentWidget() == self.logs_tab:
                self.update_log_display()
                
            # Also log to file via the logger
            log_func = getattr(logger, level.lower(), logger.info)
            log_func(message)
            
        except Exception as e:
            # Fallback to stderr if logging fails
            print(f"Logging error: {e}", file=sys.__stderr__)
    
    def update_log_display(self):
        """Update the log display with current filter settings."""
        try:
            # Get current scroll position and whether we were at the bottom
            scrollbar = self.log_text.verticalScrollBar()
            was_at_bottom = scrollbar.value() == scrollbar.maximum()
            
            # Save cursor position and block signals while updating
            self.log_text.blockSignals(True)
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.End)
            
            # Clear and repopulate with filtered logs
            self.log_text.clear()
            
            for timestamp, level, message, log_entry in self.log_buffer:
                # Apply filters
                if self.log_level.currentText() != "All" and level != self.log_level.currentText():
                    continue
                    
                search_text = self.log_search.text().lower()
                if search_text and search_text not in message.lower():
                    continue
                
                # Format the log entry with appropriate color
                self.log_text.setTextColor(self.get_log_level_color(level))
                self.log_text.append(f"{timestamp} [{level}] {message}")
            
            # Restore cursor position and scroll to bottom if we were there
            self.log_text.moveCursor(cursor.position())
            if was_at_bottom:
                self.log_text.verticalScrollBar().setValue(
                    self.log_text.verticalScrollBar().maximum()
                )
                
            # Update status
            self.log_status.showMessage(f"Showing {len(self.log_buffer)} log entries")
            
        except Exception as e:
            print(f"Error updating log display: {e}", file=sys.__stderr__)
        finally:
            self.log_text.blockSignals(False)
    
    def get_log_level_color(self, level):
        """Get the color for a log level."""
        colors = {
            "DEBUG": QColor("gray"),
            "INFO": QColor("black"),
            "WARNING": QColor("orange"),
            "ERROR": QColor("red"),
            "CRITICAL": QColor("purple")
        }
        return colors.get(level, QColor("black"))
    
    def show_log_context_menu(self, position):
        """Show a context menu for the log area."""
        menu = QMenu()
        
        # Standard actions
        copy_action = QAction("Copy", self)
        copy_action.triggered.connect(self.copy_log_selection)
        
        select_all_action = QAction("Select All", self)
        select_all_action.triggered.connect(self.log_text.selectAll)
        
        clear_action = QAction("Clear Logs", self)
        clear_action.triggered.connect(self.clear_logs)
        
        # Add actions to menu
        menu.addAction(copy_action)
        menu.addAction(select_all_action)
        menu.addSeparator()
        menu.addAction(clear_action)
        
        # Show the menu
        menu.exec_(self.log_text.viewport().mapToGlobal(position))
    
    def copy_log_selection(self):
        """Copy the selected log text to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.log_text.textCursor().selectedText())
    
    def clear_logs(self):
        """Clear the log buffer and display."""
        try:
            # Clear the buffer
            self.log_buffer = []
            
            # Clear the display
            self.log_text.clear()
            
            # Update status
            self.log_status.showMessage("Logs cleared")
            
            # Log the clear action
            self.log_message("Logs cleared by user", "INFO")
            
        except Exception as e:
            error_msg = f"Error clearing logs: {e}"
            logger.error(error_msg)
            self.log_status.showMessage(error_msg)
    
    def save_logs(self):
        """Save the current logs to a file."""
        try:
            if not self.log_buffer:
                QMessageBox.information(self, "No Logs", "No log entries to save.")
                return
                
            # Open file dialog to choose save location
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Logs",
                f"nips_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
                "Log Files (*.log);;Text Files (*.txt);;All Files (*)"
            )
            
            if not file_path:
                return  # User cancelled
                
            # Write logs to file
            with open(file_path, 'w', encoding='utf-8') as f:
                for _, _, _, log_entry in self.log_buffer:
                    f.write(f"{log_entry}\n")
            
            # Show success message
            success_msg = f"Logs saved to {file_path}"
            self.log_status.showMessage(success_msg)
            self.log_message(f"Logs saved to {file_path}", "INFO")
            
        except Exception as e:
            error_msg = f"Error saving logs: {e}"
            logger.error(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def filter_logs(self, level):
        """Filter logs based on the selected log level."""
        try:
            self.update_log_display()
        except Exception as e:
            error_msg = f"Error filtering logs: {e}"
            logger.error(error_msg)
            self.log_status.showMessage(error_msg)
    
    def search_logs(self, text):
        """Search through the logs for the given text."""
        try:
            self.update_log_display()
        except Exception as e:
            error_msg = f"Error searching logs: {e}"
            logger.error(error_msg)
            self.log_status.showMessage(error_msg)
    
    def closeEvent(self, event):
        """Handle application close event."""
        try:
            # Restore original stdout/stderr
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr
            
            # Clean up any resources
            if hasattr(self, 'traffic_thread') and self.traffic_thread.is_alive():
                self.traffic_monitoring = False
                self.traffic_thread.join(timeout=2.0)
                
            if hasattr(self, 'scan_thread') and self.scan_thread.is_alive():
                self.scan_running = False
                self.scan_thread.join(timeout=2.0)
                
            # Save any unsaved data
            self.save_settings()
            
            # Accept the close event
            event.accept()
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            event.accept()  # Still allow the app to close
    
    def save_settings(self):
        """Save application settings."""
        try:
            settings = QSettings("SecurityOps", "NIPS")
            
            # Save window geometry and state
            settings.setValue("geometry", self.saveGeometry())
            settings.setValue("windowState", self.saveState())
            
            # Save splitter states
            if hasattr(self, 'main_splitter'):
                settings.setValue("mainSplitterState", self.main_splitter.saveState())
            
            # Save log level
            if hasattr(self, 'log_level'):
                settings.setValue("logLevel", self.log_level.currentText())
            
            logger.info("Settings saved")
            
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
    
    def load_settings(self):
        """Load application settings."""
        try:
            settings = QSettings("SecurityOps", "NIPS")
            
            # Restore window geometry and state
            if settings.contains("geometry"):
                self.restoreGeometry(settings.value("geometry"))
            if settings.contains("windowState"):
                self.restoreState(settings.value("windowState"))
            
            # Restore log level
            if hasattr(self, 'log_level') and settings.contains("logLevel"):
                level = settings.value("logLevel")
                index = self.log_level.findText(level)
                if index >= 0:
                    self.log_level.setCurrentIndex(index)
            
            logger.info("Settings loaded")
            
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
    
    # Add this class at the top level of the file, before the NIPSGUI class
class LogHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for log messages."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Format for different log levels
        debug_format = QTextCharFormat()
        debug_format.setForeground(QColor("gray"))
        self.highlighting_rules.append((QRegExp("\\[DEBUG\\].*"), debug_format))
        
        info_format = QTextCharFormat()
        info_format.setForeground(QColor("black"))
        self.highlighting_rules.append((QRegExp("\\[INFO\\].*"), info_format))
        
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor("orange"))
        self.highlighting_rules.append((QRegExp("\\[WARNING\\].*"), warning_format))
        
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("red"))
        self.highlighting_rules.append((QRegExp("\\[ERROR\\].*"), error_format))
        
        critical_format = QTextCharFormat()
        critical_format.setForeground(QColor("purple"))
        critical_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp("\\[CRITICAL\\].*"), critical_format))
        
        # Format for timestamps
        timestamp_format = QTextCharFormat()
        timestamp_format.setForeground(QColor("blue"))
        self.highlighting_rules.append((QRegExp("\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\.\\d{3}"), timestamp_format))
    
    def highlightBlock(self, text):
        """Apply syntax highlighting to the given text block."""
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
        
        self.setCurrentBlockState(0)
        clear_btn = QPushButton("Clear Logs")
        clear_btn.setToolTip("Clear all log messages")
        clear_btn.clicked.connect(self.clear_logs)
        toolbar.addWidget(clear_btn)
        
        save_btn = QPushButton("Save Logs")
        save_btn.setToolTip("Save logs to a file")
        save_btn.clicked.connect(self.save_logs)
        toolbar.addWidget(save_btn)
        
        # Add toolbar to main layout
        layout.addLayout(toolbar)
        
        # Log text area with monospace font
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        font = QFont("Courier New")
        font.setStyleHint(QFont.TypeWriter)
        self.log_text.setFont(font)
        self.log_text.setLineWrapMode(QTextEdit.NoWrap)
        
        # Add context menu for copy/select all
        self.log_text.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_text.customContextMenuRequested.connect(self.show_log_context_menu)
        
        # Add to layout with stretch to take remaining space
        layout.addWidget(self.log_text)
        
        # Status bar for log info
        self.log_status = QStatusBar()
        self.update_log_status()
        layout.addWidget(self.log_status)
        
        self.logs_tab.setLayout(layout)
    
    def show_log_context_menu(self, position):
        """Show context menu for log text area."""
        menu = self.log_text.createStandardContextMenu()
        menu.addSeparator()
        
        # Add custom actions
        clear_action = menu.addAction("Clear All")
        clear_action.triggered.connect(self.clear_logs)
        
        select_all_action = menu.addAction("Select All")
        select_all_action.triggered.connect(self.log_text.selectAll)
        
        menu.exec_(self.log_text.viewport().mapToGlobal(position))
    
    def update_log_status(self):
        """Update the log status bar with line count and size."""
        if not hasattr(self, 'log_text'):
            return
            
        line_count = len(self.log_text.toPlainText().split('\n'))
        char_count = len(self.log_text.toPlainText())
        size_kb = char_count / 1024.0
        
        self.log_status.showMessage(
            f"Lines: {line_count:,} | "
            f"Size: {size_kb:.2f} KB"
        )
        
        # Schedule next update
        QTimer.singleShot(5000, self.update_log_status)
    
    def new_ruleset(self):
        """Create a new rule set."""
        try:
            # Check for unsaved changes
            if hasattr(self, 'rules_modified') and self.rules_modified:
                reply = QMessageBox.question(
                    self, 'Unsaved Changes',
                    'You have unsaved changes. Create new rule set anyway?',
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return
            
            # Clear existing rules
            self.rules = {}
            self.rules_table.setRowCount(0)
            self.rules_modified = False
            self.current_ruleset_path = None
            self.setWindowTitle("Network Intrusion Prevention System (NIPS) - PyQt5 - New Ruleset")
            logger.info("Created new rule set")
            
        except Exception as e:
            logger.error(f"Error creating new rule set: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create new rule set: {e}")
    
    def open_ruleset(self):
        """Open a rule set from a file."""
        try:
            # Check for unsaved changes
            if hasattr(self, 'rules_modified') and self.rules_modified:
                reply = QMessageBox.question(
                    self, 'Unsaved Changes',
                    'You have unsaved changes. Open a different rule set anyway?',
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return
            
            # Show file dialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Open Rule Set",
                "",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'r') as f:
                    rules_data = json.load(f)
                
                # Clear existing rules
                self.rules = {}
                self.rules_table.setRowCount(0)
                
                # Load new rules
                for rule_data in rules_data:
                    rule_id = rule_data.get('id', str(uuid.uuid4()))
                    self.rules[rule_id] = rule_data
                    self.add_rule_to_table(rule_data)
                
                self.current_ruleset_path = file_path
                self.rules_modified = False
                self.setWindowTitle(f"Network Intrusion Prevention System (NIPS) - PyQt5 - {os.path.basename(file_path)}")
                logger.info(f"Loaded rule set from {file_path}")
                
        except Exception as e:
            logger.error(f"Error opening rule set: {e}")
            QMessageBox.critical(self, "Error", f"Failed to open rule set: {e}")
    
    def save_ruleset(self, file_path=None):
        """Save the current rule set to a file."""
        try:
            if not self.rules:
                QMessageBox.information(self, "No Rules", "No rules to save.")
                return
            
            # If no file path provided, show save dialog
            if not file_path:
                file_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Save Rule Set",
                    self.current_ruleset_path or "nips_rules.json",
                    "JSON Files (*.json);;All Files (*)"
                )
                
                if not file_path:  # User cancelled
                    return
            
            # Ensure file has .json extension
            if not file_path.lower().endswith('.json'):
                file_path += '.json'
            
            # Convert rules to list for JSON serialization
            rules_list = list(self.rules.values())
            
            # Save to file
            with open(file_path, 'w') as f:
                json.dump(rules_list, f, indent=2)
            
            self.current_ruleset_path = file_path
            self.rules_modified = False
            self.setWindowTitle(f"Network Intrusion Prevention System (NIPS) - PyQt5 - {os.path.basename(file_path)}")
            logger.info(f"Saved rule set to {file_path}")
            return True
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save ruleset: {e}")
            logger.error(f"Error in save_ruleset: {e}")
            return False
    
    def export_alerts(self):
        """Export alerts to a file."""
        try:
            if not hasattr(self, 'alerts') or not self.alerts:
                QMessageBox.information(self, "No Alerts", "No alerts to export.")
                return
                
            file_path, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Export Alerts",
                "",
                "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)"
            )
            
            if not file_path:
                return
                
            # Ensure the correct file extension
            if selected_filter == "CSV Files (*.csv)" and not file_path.endswith('.csv'):
                file_path += '.csv'
            elif selected_filter == "JSON Files (*.json)" and not file_path.endswith('.json'):
                file_path += '.json'
            
            if file_path.endswith('.json'):
                # Export to JSON
                with open(file_path, 'w') as f:
                    json.dump([alert.__dict__ for alert in self.alerts], f, indent=2)
            else:
                # Default to CSV
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if not self.alerts:
                        return
                        
                    # Get all possible fieldnames from all alerts
                    fieldnames = set()
                    for alert in self.alerts:
                        fieldnames.update(alert.__dict__.keys())
                    
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    
                    for alert in self.alerts:
                        writer.writerow(alert.__dict__)
                with open(file_path, 'w') as f:
                    json.dump(alerts_data, f, indent=2)
            
            logger.info(f"Exported {len(alerts_data)} alerts to {file_path}")
            QMessageBox.information(self, "Export Complete", f"Successfully exported {len(alerts_data)} alerts to {file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export alerts: {e}")
    
    def start_alert_processor(self):
        """Start the alert processing thread."""
        if not self.alert_processor.isRunning():
            self.alert_processor.start()
            logger.info("Alert processor started")
    
    def stop_alert_processor(self):
        """Stop the alert processing thread."""
        if hasattr(self, 'alert_processor') and self.alert_processor.isRunning():
            self.alert_processor.stop()
            self.alert_processor.wait()
            logger.info("Alert processor stopped")
    
    def handle_alert(self, alert):
        """Handle a new alert from the alert processor.
        
        Args:
            alert (dict): The alert data
        """
        try:
            # Ensure alert has required fields
            if not isinstance(alert, dict):
                logger.warning(f"Received invalid alert format: {alert}")
                return
                
            # Add timestamp if not provided
            if 'timestamp' not in alert:
                alert['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
            # Set default status if not provided
            if 'status' not in alert:
                alert['status'] = 'new'
                
            # Add alert to the list
            self.alerts.append(alert)
            
            # Update the alerts table
            self.update_alert_display(alert)
            
            # Update alert statistics
            self.update_alert_stats()
            
            # Update the export button state
            if hasattr(self, 'export_btn'):
                self.export_btn.setEnabled(True)
            
            # Show notification if enabled
            if self.settings.value("alerts/notifications", True, type=bool):
                self.show_alert_notification(alert)
                
            logger.debug(f"Handled alert: {alert.get('id')} - {alert.get('description', 'No description')}")
                
        except Exception as e:
            logger.error(f"Error handling alert: {e}", exc_info=True)
    
    def update_alert_stats(self):
        """Update alert statistics from the alert processor."""
        if hasattr(self, 'alert_processor'):
            self.alert_stats = self.alert_processor.get_alert_stats()
            self.update_status_bar()
    
    def update_alert_display(self, alert):
        """Update the alerts table with a new alert.
        
        Args:
            alert (dict): The alert data to display
        """
        if not hasattr(self, 'alerts_table'):
            return
            
        try:
            # Check if the alert passes the current filters
            if not self._alert_passes_filters(alert):
                return
                
            # Get the current row count
            row = self.alerts_table.rowCount()
            
            # Insert a new row at the end
            self.alerts_table.insertRow(row)
            
            # Add alert data to the table
            self.alerts_table.setItem(row, 0, QTableWidgetItem(str(alert.get('id', ''))))  # Hidden ID column
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.get('timestamp', '')))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.get('severity', 'Unknown').capitalize()))
            self.alerts_table.setItem(row, 3, QTableWidgetItem(alert.get('source_ip', '')))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.get('destination_ip', '')))
            self.alerts_table.setItem(row, 5, QTableWidgetItem(alert.get('protocol', '').upper()))
            self.alerts_table.setItem(row, 6, QTableWidgetItem(alert.get('description', '')))
            
            # Set the status column
            status = alert.get('status', 'new').capitalize()
            self.alerts_table.setItem(row, 7, QTableWidgetItem(status))
            
            # Color code the row based on severity
            self.color_code_alert_row(row, alert.get('severity', 'low').lower())
            
            # Auto-scroll to the new row if at the bottom
            if self.alerts_table.verticalScrollBar().value() == self.alerts_table.verticalScrollBar().maximum():
                self.alerts_table.scrollToBottom()
                
        except Exception as e:
            logger.error(f"Error updating alert display: {e}", exc_info=True)
            
    def filter_alerts(self):
        """Filter the alerts table based on the current filter settings."""
        try:
            # Store the current scroll position
            scroll_pos = self.alerts_table.verticalScrollBar().value()
            
            # Clear the current table
            self.alerts_table.setRowCount(0)
            
            # Get the current filter values
            severity_filter = self.severity_filter.currentText().lower()
            search_text = self.alert_search.text().lower()
            time_filter = self.time_filter.currentText()
            
            # Apply filters to all alerts
            for alert in self.alerts:
                if self._alert_passes_filters(alert, severity_filter, search_text, time_filter):
                    # Add the alert to the table
                    row = self.alerts_table.rowCount()
                    self.alerts_table.insertRow(row)
                    
                    # Add alert data to the table
                    self.alerts_table.setItem(row, 0, QTableWidgetItem(str(alert.get('id', ''))))
                    self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.get('timestamp', '')))
                    self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.get('severity', 'Unknown').capitalize()))
                    self.alerts_table.setItem(row, 3, QTableWidgetItem(alert.get('source_ip', '')))
                    self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.get('destination_ip', '')))
                    self.alerts_table.setItem(row, 5, QTableWidgetItem(alert.get('protocol', '').upper()))
                    self.alerts_table.setItem(row, 6, QTableWidgetItem(alert.get('description', '')))
                    
                    # Set the status column
                    status = alert.get('status', 'new').capitalize()
                    self.alerts_table.setItem(row, 7, QTableWidgetItem(status))
                    
                    # Color code the row based on severity
                    self.color_code_alert_row(row, alert.get('severity', 'low').lower())
            
            # Restore the scroll position
            self.alerts_table.verticalScrollBar().setValue(scroll_pos)
            
            # Update the status bar
            visible_count = self.alerts_table.rowCount()
            total_count = len(self.alerts)
            self.statusBar().showMessage(f"Showing {visible_count} of {total_count} alerts", 3000)
            
        except Exception as e:
            logger.error(f"Error filtering alerts: {e}", exc_info=True)
            
    def _alert_passes_filters(self, alert, severity_filter=None, search_text=None, time_filter=None):
        """Check if an alert passes all the current filters.
        
        Args:
            alert (dict): The alert to check
            severity_filter (str, optional): Severity filter value. If None, uses the current UI value.
            search_text (str, optional): Search text. If None, uses the current UI value.
            time_filter (str, optional): Time filter value. If None, uses the current UI value.
            
        Returns:
            bool: True if the alert passes all filters, False otherwise
        """
        try:
            # Get current filter values if not provided
            if severity_filter is None:
                severity_filter = self.severity_filter.currentText().lower()
            if search_text is None:
                search_text = self.alert_search.text().lower()
            if time_filter is None:
                time_filter = self.time_filter.currentText()
            
            # Apply severity filter
            if severity_filter != 'all':
                alert_severity = alert.get('severity', '').lower()
                if alert_severity != severity_filter:
                    return False
            
            # Apply search text filter
            if search_text:
                search_fields = [
                    str(alert.get('source_ip', '')),
                    str(alert.get('destination_ip', '')),
                    str(alert.get('protocol', '')),
                    str(alert.get('description', '')),
                    str(alert.get('id', ''))
                ]
                
                # Check if any field contains the search text
                if not any(search_text.lower() in field.lower() for field in search_fields):
                    return False
            
            # Apply time filter
            if time_filter != 'All Time' and 'timestamp' in alert:
                try:
                    alert_time = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')
                    now = datetime.now()
                    
                    if time_filter == 'Last 24 Hours':
                        if (now - alert_time).total_seconds() > 24 * 3600:
                            return False
                    elif time_filter == 'Last 7 Days':
                        if (now - alert_time).total_seconds() > 7 * 24 * 3600:
                            return False
                    elif time_filter == 'Last 30 Days':
                        if (now - alert_time).total_seconds() > 30 * 24 * 3600:
                            return False
                    # Add custom time range handling here if needed
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error parsing alert timestamp: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error in alert filter: {e}", exc_info=True)
            return False
    
    def color_code_alert_row(self, row, severity):
        """Color code an alert row based on severity.
        
        Args:
            row (int): The row number to color
            severity (str): The severity level (low, medium, high, critical)
        """
        colors = {
            'low': QColor(255, 255, 200),      # Light yellow
            'medium': QColor(255, 220, 150),    # Light orange
            'high': QColor(255, 180, 150),      # Light red
            'critical': QColor(255, 150, 150)   # Red
        }
        
        color = colors.get(severity.lower(), QColor(255, 255, 255))
        
        for col in range(self.alerts_table.columnCount()):
            item = self.alerts_table.item(row, col)
            if item:
                item.setBackground(color)
    
    def show_alert_notification(self, alert):
        """Show a system notification for a new alert.
        
        Args:
            alert (dict): The alert data
        """
        try:
            title = f"NIPS Alert: {alert.get('severity', 'Alert').capitalize()}"
            message = alert.get('description', 'New security alert')
            
            # Use QSystemTrayIcon if available, otherwise use QMessageBox
            if hasattr(self, 'tray_icon') and self.tray_icon.isSystemTrayAvailable():
                self.tray_icon.showMessage(title, message, QSystemTrayIcon.Warning, 5000)
            else:
                QMessageBox.warning(self, title, message)
                
        except Exception as e:
            logger.error(f"Error showing alert notification: {e}")
    
    def acknowledge_alert(self, alert_id=None):
        """Mark an alert as acknowledged.
        
        Args:
            alert_id (str, optional): The ID of the alert to acknowledge. If None, uses the selected alert(s).
        """
        try:
            # Get selected alert IDs if none provided
            if alert_id is None:
                selected_rows = set(index.row() for index in self.alerts_table.selectedIndexes())
                if not selected_rows:
                    QMessageBox.information(self, "No Selection", "Please select one or more alerts to acknowledge.")
                    return
                
                # Process each selected alert
                for row in selected_rows:
                    alert_id_item = self.alerts_table.item(row, 0)  # ID is in the first (hidden) column
                    if alert_id_item:
                        self.acknowledge_alert(alert_id_item.text())
                return
            
            # Find and update the alert in the alerts list
            for alert in self.alerts:
                if alert.get('id') == alert_id:
                    alert['status'] = 'acknowledged'
                    alert['acknowledged_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    alert['acknowledged_by'] = os.getlogin()  # Get current username
                    
                    # Update the UI
                    row = self._find_alert_row(alert_id)
                    if row is not None:
                        # Update the status in the table
                        status_item = QTableWidgetItem("Acknowledged")
                        self.alerts_table.setItem(row, 7, status_item)  # Status is column 7
                        
                        # Change row color to indicate acknowledged status
                        for col in range(self.alerts_table.columnCount()):
                            item = self.alerts_table.item(row, col)
                            if item:
                                item.setBackground(QColor(230, 230, 250))  # Light lavender
                    
                    logger.info(f"Acknowledged alert: {alert_id}")
                    self.statusBar().showMessage(f"Alert {alert_id} acknowledged", 3000)
                    break
            else:
                logger.warning(f"Alert not found: {alert_id}")
                QMessageBox.warning(self, "Alert Not Found", f"Could not find alert with ID: {alert_id}")
                
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to acknowledge alert: {e}")
            
    def escalate_alert(self, alert_id=None):
        """Mark an alert as escalated.
        
        Args:
            alert_id (str, optional): The ID of the alert to escalate. If None, uses the selected alert(s).
        """
        try:
            # Get selected alert IDs if none provided
            if alert_id is None:
                selected_rows = set(index.row() for index in self.alerts_table.selectedIndexes())
                if not selected_rows:
                    QMessageBox.information(self, "No Selection", "Please select one or more alerts to escalate.")
                    return
                
                # Process each selected alert
                for row in selected_rows:
                    alert_id_item = self.alerts_table.item(row, 0)  # ID is in the first (hidden) column
                    if alert_id_item:
                        self.escalate_alert(alert_id_item.text())
                return
            
            # Find and update the alert in the alerts list
            for alert in self.alerts:
                if alert.get('id') == alert_id:
                    alert['status'] = 'escalated'
                    alert['escalated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    alert['escalated_by'] = os.getlogin()  # Get current username
                    
                    # If previously acknowledged, keep that info but mark as escalated
                    if 'acknowledged_at' not in alert:
                        alert['acknowledged_at'] = alert['escalated_at']
                    if 'acknowledged_by' not in alert:
                        alert['acknowledged_by'] = alert['escalated_by']
                    
                    # Update the UI
                    row = self._find_alert_row(alert_id)
                    if row is not None:
                        # Update the status in the table
                        status_item = QTableWidgetItem("Escalated")
                        self.alerts_table.setItem(row, 7, status_item)  # Status is column 7
                        
                        # Change row color to indicate escalated status (light red)
                        for col in range(self.alerts_table.columnCount()):
                            item = self.alerts_table.item(row, col)
                            if item:
                                item.setBackground(QColor(255, 220, 220))  # Light red
                    
                    logger.info(f"Escalated alert: {alert_id}")
                    self.statusBar().showMessage(f"Alert {alert_id} escalated", 3000)
                    
                    # Show a confirmation dialog
                    QMessageBox.information(
                        self, 
                        "Alert Escalated", 
                        f"Alert {alert_id} has been escalated to the security team."
                    )
                    break
            else:
                logger.warning(f"Alert not found: {alert_id}")
                QMessageBox.warning(self, "Alert Not Found", f"Could not find alert with ID: {alert_id}")
                
        except Exception as e:
            logger.error(f"Error escalating alert: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to escalate alert: {e}")
            
    def _find_alert_row(self, alert_id):
        """Find the row number of an alert in the table by its ID.
        
        Args:
            alert_id (str): The ID of the alert to find
            
        Returns:
            int or None: The row number if found, None otherwise
        """
        for row in range(self.alerts_table.rowCount()):
            item = self.alerts_table.item(row, 0)  # ID is in the first (hidden) column
            if item and item.text() == alert_id:
                return row
        return None
        
    def _setup_alerts_context_menu(self):
        """Set up the context menu for the alerts table."""
        self.alerts_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.alerts_table.customContextMenuRequested.connect(self._show_alerts_context_menu)
        
    def _show_alerts_context_menu(self, position):
        """Show the context menu for the alerts table.
        
        Args:
            position (QPoint): The position where the context menu was requested
        """
        try:
            # Get the selected rows
            selected_rows = set(index.row() for index in self.alerts_table.selectedIndexes())
            if not selected_rows:
                return
                
            # Create the context menu
            menu = QMenu()
            
            # Add actions
            ack_action = menu.addAction("Acknowledge")
            view_action = menu.addAction("View Details")
            copy_action = menu.addAction("Copy to Clipboard")
            menu.addSeparator()
            delete_action = menu.addAction("Delete")
            
            # Show the menu and get the selected action
            action = menu.exec_(self.alerts_table.viewport().mapToGlobal(position))
            
            # Handle the selected action
            if action == ack_action:
                self.acknowledge_alert()
            elif action == view_action:
                self._view_alert_details()
            elif action == copy_action:
                self._copy_alert_to_clipboard()
            elif action == delete_action:
                self._delete_selected_alerts()
                
        except Exception as e:
            logger.error(f"Error showing context menu: {e}", exc_info=True)
            
    def _view_alert_details(self):
        """Show details for the selected alert."""
        try:
            selected_items = self.alerts_table.selectedItems()
            if not selected_items:
                return
                
            # Get the alert ID from the first column (hidden)
            row = selected_items[0].row()
            alert_id_item = self.alerts_table.item(row, 0)
            if not alert_id_item:
                return
                
            alert_id = alert_id_item.text()
            
            # Find the alert in the alerts list
            for alert in self.alerts:
                if alert.get('id') == alert_id:
                    # Create a dialog to show alert details
                    dialog = QDialog(self)
                    dialog.setWindowTitle("Alert Details")
                    dialog.setMinimumWidth(500)
                    
                    layout = QVBoxLayout()
                    
                    # Create a text edit to display the alert details
                    text_edit = QTextEdit()
                    text_edit.setReadOnly(True)
                    text_edit.setFont(QFont("Monospace"))
                    
                    # Format the alert details as JSON for display
                    alert_copy = dict(alert)  # Create a copy to avoid modifying the original
                    alert_copy.pop('id', None)  # Remove the ID from the display
                    
                    try:
                        # Pretty-print the alert details as JSON
                        alert_json = json.dumps(alert_copy, indent=2, default=str)
                        text_edit.setPlainText(alert_json)
                    except Exception as e:
                        logger.warning(f"Error formatting alert details: {e}")
                        text_edit.setPlainText(str(alert_copy))
                    
                    # Add a close button
                    button_box = QDialogButtonBox(QDialogButtonBox.Close)
                    button_box.rejected.connect(dialog.reject)
                    
                    # Add widgets to layout
                    layout.addWidget(text_edit)
                    layout.addWidget(button_box)
                    
                    dialog.setLayout(layout)
                    dialog.exec_()
                    break
                    
        except Exception as e:
            logger.error(f"Error viewing alert details: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to view alert details: {e}")
            
    def _copy_alert_to_clipboard(self):
        """Copy the selected alert to the clipboard."""
        try:
            selected_items = self.alerts_table.selectedItems()
            if not selected_items:
                return
                
            # Get the alert ID from the first column (hidden)
            row = selected_items[0].row()
            alert_id_item = self.alerts_table.item(row, 0)
            if not alert_id_item:
                return
                
            alert_id = alert_id_item.text()
            
            # Find the alert in the alerts list
            for alert in self.alerts:
                if alert.get('id') == alert_id:
                    # Format the alert as a string
                    alert_text = ""
                    for key, value in alert.items():
                        if key != 'id':  # Skip the ID
                            alert_text += f"{key}: {value}\n"
                    
                    # Copy to clipboard
                    QApplication.clipboard().setText(alert_text.strip())
                    self.statusBar().showMessage("Alert copied to clipboard", 2000)
                    break
                    
        except Exception as e:
            logger.error(f"Error copying alert to clipboard: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to copy alert: {e}")
            
    def _delete_selected_alerts(self):
        """Delete the selected alerts."""
        try:
            selected_rows = set(index.row() for index in self.alerts_table.selectedIndexes())
            if not selected_rows:
                return
                
            # Get confirmation
            reply = QMessageBox.question(
                self,
                "Confirm Deletion",
                f"Are you sure you want to delete {len(selected_rows)} selected alert(s)?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Get the alert IDs to delete
                alert_ids = []
                for row in selected_rows:
                    alert_id_item = self.alerts_table.item(row, 0)  # ID is in the first column
                    if alert_id_item:
                        alert_ids.append(alert_id_item.text())
                
                # Remove from the alerts list
                self.alerts = [alert for alert in self.alerts if alert.get('id') not in alert_ids]
                
                # Remove from the table
                for row in sorted(selected_rows, reverse=True):
                    self.alerts_table.removeRow(row)
                
                self.statusBar().showMessage(f"Deleted {len(alert_ids)} alert(s)", 3000)
                
        except Exception as e:
            logger.error(f"Error deleting alerts: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to delete alerts: {e}")
            
    def clear_alerts(self):
        """Clear all alerts from the table after confirmation."""
        try:
            if self.alerts_table.rowCount() == 0:
                return
                
            # Get confirmation
            reply = QMessageBox.question(
                self,
                "Confirm Clear All",
                "Are you sure you want to clear all alerts? This action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Clear the alerts list
                self.alerts = []
                
                # Clear the table
                self.alerts_table.setRowCount(0)
                
                # Clear the details panel
                self.alert_details.clear()
                
                # Update status bar
                self.statusBar().showMessage("All alerts cleared", 3000)
                logger.info("All alerts cleared")
                
        except Exception as e:
            logger.error(f"Error clearing alerts: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to clear alerts: {e}")
            
    def export_alerts(self):
        """Export alerts to a file in various formats."""
        try:
            if not self.alerts:
                QMessageBox.information(self, "No Alerts", "There are no alerts to export.")
                return
                
            # Let user choose file location and format
            file_path, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Export Alerts",
                "",
                "CSV Files (*.csv);;JSON Files (*.json);;Text Files (*.txt);;All Files (*)",
                "CSV Files (*.csv)"
            )
            
            if not file_path:
                return  # User cancelled
                
            # Determine format from file extension if not specified by filter
            if selected_filter == "JSON Files (*.json)" or file_path.lower().endswith('.json'):
                self._export_alerts_to_json(file_path)
            elif selected_filter == "Text Files (*.txt)" or file_path.lower().endswith('.txt'):
                self._export_alerts_to_text(file_path)
            else:  # Default to CSV
                if not file_path.lower().endswith('.csv'):
                    file_path += '.csv'
                self._export_alerts_to_csv(file_path)
                
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}", exc_info=True)
            QMessageBox.critical(self, "Export Error", f"Failed to export alerts: {e}")
    
    def _export_alerts_to_csv(self, file_path):
        """Export alerts to a CSV file.
        
        Args:
            file_path (str): Path to save the CSV file
        """
        try:
            # Define the field names in the desired order
            fieldnames = [
                'id', 'timestamp', 'severity', 'source_ip', 'destination_ip',
                'protocol', 'description', 'status', 'acknowledged_at',
                'acknowledged_by', 'escalated_at', 'escalated_by'
            ]
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for alert in self.alerts:
                    # Create a copy of the alert with all fields
                    row = {field: '' for field in fieldnames}
                    row.update({k: v for k, v in alert.items() if k in fieldnames})
                    writer.writerow(row)
            
            self.statusBar().showMessage(f"Exported {len(self.alerts)} alerts to {file_path}", 5000)
            logger.info(f"Exported {len(self.alerts)} alerts to {file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting alerts to CSV: {e}", exc_info=True)
            raise
    
    def _export_alerts_to_json(self, file_path):
        """Export alerts to a JSON file.
        
        Args:
            file_path (str): Path to save the JSON file
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.alerts, f, indent=2, default=str)
            
            self.statusBar().showMessage(f"Exported {len(self.alerts)} alerts to {file_path}", 5000)
            logger.info(f"Exported {len(self.alerts)} alerts to {file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting alerts to JSON: {e}", exc_info=True)
            raise
    
    def _export_alerts_to_text(self, file_path):
        """Export alerts to a formatted text file.
        
        Args:
            file_path (str): Path to save the text file
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"NIPS Alert Export - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, alert in enumerate(self.alerts, 1):
                    f.write(f"Alert #{i}\n")
                    f.write("-" * 40 + "\n")
                    
                    # Format each field on its own line
                    for key, value in alert.items():
                        if isinstance(value, dict):
                            # Handle nested dictionaries
                            f.write(f"{key}:\n")
                            for k, v in value.items():
                                f.write(f"  {k}: {v}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                    
                    f.write("\n")  # Add space between alerts
                
                f.write(f"\nTotal alerts: {len(self.alerts)}\n")
            
            self.statusBar().showMessage(f"Exported {len(self.alerts)} alerts to {file_path}", 5000)
            logger.info(f"Exported {len(self.alerts)} alerts to {file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting alerts to text: {e}", exc_info=True)
            raise
            
    def _sort_alerts_table(self, column):
        """Handle sorting of the alerts table when a column header is clicked.
        
        Args:
            column (int): The column index that was clicked
        """
        try:
            # Skip the ID column (hidden)
            if column == 0:
                return
                
            # Get the current sort order
            current_order = self.alerts_table.horizontalHeader().sortIndicatorOrder()
            
            # Toggle sort order for the column
            if self.alerts_table.horizontalHeader().sortIndicatorSection() == column:
                new_order = Qt.DescendingOrder if current_order == Qt.AscendingOrder else Qt.AscendingOrder
            else:
                new_order = Qt.AscendingOrder
                
            # Apply the sort
            self.alerts_table.sortByColumn(column, new_order)
            
        except Exception as e:
            logger.error(f"Error sorting alerts table: {e}", exc_info=True)
    
    def start_alert_processor(self):
        """Start the alert processing thread."""
        self.alert_worker = AlertWorker(self.alert_queue)
        self.alert_worker_thread = QThread()
        self.alert_worker.moveToThread(self.alert_worker_thread)
        
        # Connect signals and slots
        self.alert_worker.alert_received.connect(self.handle_alert)
        self.alert_worker_thread.started.connect(self.alert_worker.process_alerts)
        
        # Start the thread
        self.alert_worker_thread.start()
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if self.monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def clear_logs(self):
        """Clear the logs text widget."""
        try:
            self.log_text.clear()
            logger.info("Logs cleared")
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            QMessageBox.critical(self, "Error", f"Failed to clear logs: {e}")
    
    def save_logs(self):
        """Save the current logs to a file."""
        try:
            if not self.log_text.toPlainText().strip():
                QMessageBox.information(self, "No Logs", "No logs available to save.")
                return
                
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Logs",
                "nips_logs.txt",
                "Text Files (*.txt);;Log Files (*.log);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.toPlainText())
                logger.info(f"Logs saved to {file_path}")
                QMessageBox.information(self, "Success", f"Logs saved to {file_path}")
                
        except Exception as e:
            logger.error(f"Error saving logs: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save logs: {e}")
    
    def filter_logs(self, level):
        """Filter logs based on the selected log level."""
        if not hasattr(self, 'log_text') or not hasattr(self, 'log_level'):
            return
            
        try:
            # Get all log entries
            all_logs = self.log_text.toPlainText().split('\n')
            
            # Clear and repopulate with filtered logs
            self.log_text.clear()
            
            for log_entry in all_logs:
                if not log_entry.strip():
                    continue
                    
                # Check if log entry matches the selected level
                if level == "ALL" or f" - {level} - " in log_entry:
                    self.log_text.append(log_entry)
                    
        except Exception as e:
            logger.error(f"Error filtering logs: {e}")
    
    def search_logs(self):
        """Search through the logs for the given text."""
        if not hasattr(self, 'log_text') or not hasattr(self, 'log_search'):
            return
            
        try:
            search_text = self.log_search.text().lower()
            if not search_text:
                return
                
            # Get all log entries
            all_logs = self.log_text.toPlainText().split('\n')
            
            # Clear and repopulate with matching logs
            self.log_text.clear()
            
            for log_entry in all_logs:
                if search_text in log_entry.lower():
                    self.log_text.append(log_entry)
                    
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
    
    def start_monitoring(self):
        """Start monitoring network traffic."""
        try:
            self.monitoring = True
            self.start_action.setEnabled(False)
            self.stop_action.setEnabled(True)
            self.dashboard_start_btn.setText("Stop Monitoring")
            self.status_indicator.setText("Status: Running")
            self.status_bar.showMessage("Monitoring started")
            
            # Start the timer for updating UI
            self.start_time = datetime.now()
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.update_ui)
            self.timer.start(1000)  # Update every second
            
            logger.info("Monitoring started")
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring network traffic."""
        try:
            self.monitoring = False
            self.start_action.setEnabled(True)
            self.stop_action.setEnabled(False)
            self.dashboard_start_btn.setText("Start Monitoring")
            self.status_indicator.setText("Status: Stopped")
            
            # Stop the timer
            if hasattr(self, 'timer') and self.timer.isActive():
                self.timer.stop()
            
            self.status_bar.showMessage("Monitoring stopped")
            logger.info("Monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            QMessageBox.critical(self, "Error", f"Failed to stop monitoring: {e}")
    
    def update_status_bar(self):
        """Update the status bar with current statistics."""
        try:
            # Get alert statistics
            alert_stats = getattr(self, 'alert_stats', {})
            severity_counts = alert_stats.get('severity', {})
            
            # Format alert summary
            alert_summary = (
                f"Alerts: {alert_stats.get('total', 0)} "
                f"(L:{severity_counts.get('low', 0)} "
                f"M:{severity_counts.get('medium', 0)} "
                f"H:{severity_counts.get('high', 0)} "
                f"C:{severity_counts.get('critical', 0)})"
            )
            
            # Update status bar text
            status_text = (
                f"{alert_summary} | "
                f"Threats blocked: {getattr(self, 'threats_blocked', 0)} | "
                f"Packets analyzed: {getattr(self, 'packets_analyzed', 0)} | "
                f"Uptime: {getattr(self, 'get_uptime', lambda: 'N/A')()}"
            )
            
            self.statusBar().showMessage(status_text)
            
        except Exception as e:
            logger.error(f"Error updating status bar: {e}", exc_info=True)
            # Fallback to basic status if there's an error
            self.statusBar().showMessage("Status: Ready")
            
    def get_uptime(self):
        """Get formatted uptime string."""
        if not hasattr(self, 'start_time'):
            return "N/A"
            
        uptime = datetime.now() - self.start_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        else:
            return f"{minutes}m {seconds}s"
    
    def update_ui(self):
        """Update the UI with current status."""
        try:
            # Update uptime
            uptime = datetime.now() - self.start_time
            uptime_str = str(uptime).split('.')[0]  # Remove microseconds
            
            # Update status bar
            self.update_status_bar()
            
            # Update dashboard
            self.uptime_label.setText(f"Uptime: {uptime_str}")
            self.dashboard_uptime.setText(f"Uptime: {uptime_str}")
            self.packets_label.setText(f"Packets Analyzed: {self.packets_analyzed}")
            self.dashboard_packets.setText(f"Packets Analyzed: {self.packets_analyzed}")
            self.threats_label.setText(f"Threats Blocked: {self.threats_blocked}")
            self.dashboard_threats.setText(f"Threats Blocked: {self.threats_blocked}")
            self.connections_label.setText(f"Active Connections: {self.connections_active}")
            self.dashboard_connections.setText(f"Active Connections: {self.connections_active}")
            
        except Exception as e:
            logger.error(f"Error updating UI: {e}")
    
    def handle_alert(self, alert):
        """Handle a new alert."""
        try:
            # Add alert to the list
            self.alerts.append(alert)
            
            # Update the alerts table
            row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row)
            
            # Set the data for each column
            self.alerts_table.setItem(row, 0, QTableWidgetItem(alert.timestamp))
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.severity))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.source_ip))
            self.alerts_table.setItem(row, 3, QTableWidgetItem(alert.destination_ip))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.protocol))
            self.alerts_table.setItem(row, 5, QTableWidgetItem(alert.description))
            
            # Set row color based on severity
            if alert.severity.lower() == "high":
                color = QColor(255, 200, 200)  # Light red for high severity
            elif alert.severity.lower() == "medium":
                color = QColor(255, 255, 200)  # Light yellow for medium severity
            else:
                color = QColor(200, 255, 200)  # Light green for low severity
            
            for col in range(self.alerts_table.columnCount()):
                item = self.alerts_table.item(row, col)
                if item:
                    item.setBackground(color)
            
            # Auto-scroll to the bottom
            self.alerts_table.scrollToBottom()
            
            # Log the alert
            log_msg = f"[{alert.timestamp}] {alert.severity}: {alert.description} (From: {alert.source_ip}, To: {alert.destination_ip}, Protocol: {alert.protocol})"
            self.log_message(log_msg)
            
            # Show a message box for high severity alerts
            if alert.severity.lower() == "high":
                QMessageBox.warning(self, "High Severity Alert", 
                                  f"{alert.description}\n\n"
                                  f"Source: {alert.source_ip}\n"
                                  f"Destination: {alert.destination_ip}\n"
                                  f"Protocol: {alert.protocol}")
            
            # Update threats blocked counter if the alert was blocked
            if "blocked" in alert.action.lower():
                self.threats_blocked += 1
            
            # Update packets analyzed counter
            self.packets_analyzed += 1
            
        except Exception as e:
            logger.error(f"Error handling alert: {e}")
    
    def show_alert_details(self, index):
        """Show details for the selected alert."""
        try:
            row = index.row()
            if 0 <= row < len(self.alerts):
                alert = self.alerts[row]
                
                # Format the alert details
                details = f"""
                <h2>Alert Details</h2>
                <table border="1" cellspacing="0" cellpadding="5">
                    <tr><td><b>Timestamp:</b></td><td>{alert.timestamp}</td></tr>
                    <tr><td><b>Severity:</b></td><td>{alert.severity}</td></tr>
                    <tr><td><b>Source IP:</b></td><td>{alert.source_ip}</td></tr>
                    <tr><td><b>Destination IP:</b></td><td>{alert.destination_ip}</td></tr>
                    <tr><td><b>Protocol:</b></td><td>{alert.protocol}</td></tr>
                    <tr><td><b>Action:</b></td><td>{alert.action}</td></tr>
                    <tr><td><b>Rule ID:</b></td><td>{alert.rule_id if alert.rule_id else 'N/A'}</td></tr>
                    <tr><td><b>Description:</b></td><td>{alert.description}</td></tr>
                </table>
                """
                
                if alert.details:
                    details += f"<h3>Additional Details</h3><pre>{alert.details}</pre>"
                
                self.alert_details.setHtml(details)
        
        except Exception as e:
            logger.error(f"Error showing alert details: {e}")
            QMessageBox.critical(self, "Error", f"Failed to show alert details: {e}")
    
    def clear_alerts(self):
        """Clear all alerts."""
        try:
            self.alerts_table.setRowCount(0)
            self.alerts = []
            self.alert_details.clear()
            logger.info("Alerts cleared")
            
        except Exception as e:
            logger.error(f"Error clearing alerts: {e}")
            QMessageBox.critical(self, "Error", f"Failed to clear alerts: {e}")
    
    def export_alerts(self):
        """Export alerts to a file."""
        try:
            if not self.alerts:
                QMessageBox.information(self, "No Alerts", "There are no alerts to export.")
                return
            
            # Get the file path to save
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Alerts", "", "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
            )
            
            if not file_path:
                return  # User cancelled
            
            # Convert alerts to a list of dictionaries
            alerts_data = []
            for alert in self.alerts:
                alert_dict = {
                    'id': alert.id,
                    'timestamp': alert.timestamp,
                    'severity': alert.severity,
                    'source_ip': alert.source_ip,
                    'destination_ip': alert.destination_ip,
                    'protocol': alert.protocol,
                    'description': alert.description,
                    'rule_id': alert.rule_id,
                    'action': alert.action,
                    'details': alert.details
                }
                alerts_data.append(alert_dict)
            
            # Save to file based on extension
            if file_path.lower().endswith('.csv'):
                import csv
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=alerts_data[0].keys())
                    writer.writeheader()
                    writer.writerows(alerts_data)
            else:  # Default to JSON
                with open(file_path, 'w') as f:
                    json.dump(alerts_data, f, indent=2)
            
            QMessageBox.information(self, "Export Successful", f"Alerts exported to {file_path}")
            logger.info(f"Alerts exported to {file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export alerts: {e}")
    
    def clear_logs(self):
        """Clear the logs."""
        try:
            self.logs_text.clear()
            logger.info("Logs cleared")
            
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            QMessageBox.critical(self, "Error", f"Failed to clear logs: {e}")
    
    def save_logs(self):
        """Save the logs to a file."""
        try:
            if not self.logs_text.toPlainText():
                QMessageBox.information(self, "No Logs", "There are no logs to save.")
                return
            
            # Get the file path to save
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Logs", "", "Log Files (*.log);;Text Files (*.txt);;All Files (*)"
            )
            
            if not file_path:
                return  # User cancelled
            
            # Save the logs
            with open(file_path, 'w') as f:
                f.write(self.logs_text.toPlainText())
            
            QMessageBox.information(self, "Save Successful", f"Logs saved to {file_path}")
            logger.info(f"Logs saved to {file_path}")
            
        except Exception as e:
            logger.error(f"Error saving logs: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save logs: {e}")
    
    def log_message(self, message):
        """Add a message to the logs."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {message}"
            
            # Add to the logs text area
            self.logs_text.append(log_entry)
            
            # Auto-scroll to the bottom
            scrollbar = self.logs_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            
            # Also log to the console
            logger.info(message)
            
        except Exception as e:
            logger.error(f"Error logging message: {e}")
    
    def show_about(self):
        """Show the about dialog."""
        about_text = """
        <h2>Network Intrusion Prevention System (NIPS)</h2>
        <p>Version: 1.0.0</p>
        <p>© 2025 Security Ops Center</p>
        <p>This is a PyQt5-based GUI for the Network Intrusion Prevention System.</p>
        <p>Developed by: Security Team</p>
        """
        
        QMessageBox.about(self, "About NIPS", about_text)
    
    def closeEvent(self, event):
        """Handle the window close event."""
        try:
            # Save settings before closing
            self.save_settings()
            
            # Stop any running monitoring
            if hasattr(self, 'monitoring') and self.monitoring:
                self.stop_monitoring()
                
            # Stop the alert processor
            if hasattr(self, 'alert_processor') and self.alert_processor.isRunning():
                self.alert_processor.stop()
                self.alert_processor.wait(2000)  # Wait up to 2 seconds
                
            # Stop the alert worker thread if it exists
            if hasattr(self, 'alert_worker_thread') and self.alert_worker_thread.isRunning():
                self.alert_worker.stop()
                self.alert_worker_thread.quit()
                self.alert_worker_thread.wait(2000)  # Wait up to 2 seconds
                
            # Save any unsaved rules
            if hasattr(self, 'rules_modified') and self.rules_modified:
                reply = QMessageBox.question(
                    self, 'Save Changes',
                    'You have unsaved changes to your rules. Would you like to save them before exiting?',
                    QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                    QMessageBox.Save
                )
                
                if reply == QMessageBox.Save:
                    if not self.save_ruleset():
                        # User canceled save
                        event.ignore()
                        return
                elif reply == QMessageBox.Cancel:
                    event.ignore()
                    return
                    
            # Clean up any other resources
            if hasattr(self, 'tray_icon'):
                self.tray_icon.hide()
                
            # Stop any other running threads
            if hasattr(self, 'traffic_monitor_thread') and self.traffic_monitor_thread.isRunning():
                self.traffic_monitor_thread.quit()
                self.traffic_monitor_thread.wait(1000)
                
            if hasattr(self, 'network_scanner_thread') and self.network_scanner_thread.isRunning():
                self.network_scanner_thread.quit()
                self.network_scanner_thread.wait(1000)
                
            logger.info("NIPS GUI shutdown complete")
            event.accept()
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)
            # Still allow the application to close
            event.accept()
    
    def main():
        """Main entry point for the NIPS GUI application."""
        try:
            # Create the application
            app = QApplication(sys.argv)
            
            # Set application style
            app.setStyle('Fusion')
            
            # Create and show the main window
            window = NIPSGUI()
            window.show()
            
            # Start the application event loop
            sys.exit(app.exec_())
            
        except Exception as e:
            logger.critical(f"Fatal error: {e}", exc_info=True)
            QMessageBox.critical(None, "Fatal Error", f"A fatal error occurred: {e}\n\nPlease check the logs for more details.")
            sys.exit(1)

if __name__ == "__main__":
    main()
