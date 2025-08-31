"""
EDR GUI Module (PyQt5 Version)

Provides a PyQt5-based graphical interface for the Endpoint Detection and Response system.
"""
import sys
import os
import logging
import queue
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QTabWidget, QLabel, QPushButton, QFileDialog, QMessageBox,
                           QTreeWidget, QTreeWidgetItem, QHeaderView, QSplitter, 
                           QTextEdit, QFormLayout, QLineEdit, QGroupBox, QComboBox,
                           QStatusBar, QAction, QMenu, QToolBar, QStyle, QProgressBar,
                           QTableWidget, QTableWidgetItem, QCheckBox, QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject, QSize
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette, QTextCursor

# Local imports from edr package
from . import __version__
from .core import ThreatDetector
from .rule_manager import RuleManager
from .threat_detection import ThreatDetectionEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('edr.gui.qt')

class EDRWindow(QMainWindow):
    """Main EDR application window."""
    
    def __init__(self):
        """Initialize the EDR GUI."""
        super().__init__()
        
        # Initialize logging
        self.logger = logging.getLogger('edr.gui')
        self.logger.info("Initializing EDR GUI")
        
        # Data storage
        self.alerts = []
        self.events_queue = queue.Queue()
        self.running = False
        
        try:
            # Initialize EDR components with error handling
            self.logger.info("Initializing ThreatDetector...")
            self.detector = ThreatDetector()
            
            self.logger.info("Initializing RuleManager...")
            self.rule_manager = RuleManager()
            
            self.logger.info("Initializing ThreatDetectionEngine...")
            self.detection_engine = ThreatDetectionEngine()
            
            # Setup UI
            self.setup_ui()
            
            # Set window properties
            self.setWindowTitle(f"Endpoint Detection and Response v{__version__}")
            self.setGeometry(100, 100, 1200, 800)
            
            # Setup status bar
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.status_bar.showMessage("Ready")
            
            self.logger.info("EDR GUI initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize EDR GUI: {str(e)}", exc_info=True)
            QMessageBox.critical(
                None,
                "Initialization Error",
                f"Failed to initialize EDR GUI: {str(e)}\n\nCheck the logs for more details."
            )
            sys.exit(1)
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_alerts_tab()
        self.setup_rules_tab()
        self.setup_logs_tab()
        
        # Setup menu bar and toolbar
        self.setup_menu_bar()
        self.setup_toolbar()
    
    def setup_menu_bar(self):
        """Set up the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        # Actions
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        # Add view actions here
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        # Add tools actions here
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
    
    def setup_toolbar(self):
        """Set up the toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)
        
        # Add toolbar actions
        start_scan_action = QAction("Start Scan", self)
        start_scan_action.triggered.connect(self.start_scan)
        toolbar.addAction(start_scan_action)
        
        stop_scan_action = QAction("Stop Scan", self)
        stop_scan_action.triggered.connect(self.stop_scan)
        toolbar.addAction(stop_scan_action)
        
        toolbar.addSeparator()
        
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_ui)
        toolbar.addAction(refresh_action)
    
    def setup_dashboard_tab(self):
        """Set up the dashboard tab."""
        self.dashboard_tab = QWidget()
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Stats group
        stats_group = QGroupBox("System Status")
        stats_layout = QHBoxLayout()
        
        # Stats widgets
        self.threats_count = QLabel("0")
        self.rules_count = QLabel(str(len(self.rule_manager.rules)))
        self.status_label = QLabel("Stopped")
        
        # Add stats to layout
        stats_layout.addWidget(QLabel("Threats Detected:"))
        stats_layout.addWidget(self.threats_count)
        stats_layout.addStretch()
        
        stats_layout.addWidget(QLabel("Active Rules:"))
        stats_layout.addWidget(self.rules_count)
        stats_layout.addStretch()
        
        stats_layout.addWidget(QLabel("Status:"))
        stats_layout.addWidget(self.status_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Add dashboard content here
        
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")
    
    def setup_alerts_tab(self):
        """Set up the alerts tab."""
        self.alerts_tab = QWidget()
        layout = QVBoxLayout(self.alerts_tab)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Severity", "Source", "Type", "Description"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.alerts_table)
        self.tab_widget.addTab(self.alerts_tab, "Alerts")
    
    def setup_rules_tab(self):
        """Set up the rules tab."""
        self.rules_tab = QWidget()
        layout = QVBoxLayout(self.rules_tab)
        
        # Rules list
        self.rules_list = QListWidget()
        self.load_rules()
        
        # Buttons
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        edit_btn = QPushButton("Edit Rule")
        delete_btn = QPushButton("Delete Rule")
        
        button_layout.addWidget(add_btn)
        button_layout.addWidget(edit_btn)
        button_layout.addWidget(delete_btn)
        
        layout.addWidget(self.rules_list)
        layout.addLayout(button_layout)
        
        self.tab_widget.addTab(self.rules_tab, "Rules")
    
    def setup_logs_tab(self):
        """Set up the logs tab."""
        self.logs_tab = QWidget()
        layout = QVBoxLayout(self.logs_tab)
        
        # Logs text area
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Monospace", 10))
        
        # Buttons
        refresh_btn = QPushButton("Refresh Logs")
        clear_btn = QPushButton("Clear Logs")
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(refresh_btn)
        button_layout.addWidget(clear_btn)
        
        layout.addWidget(self.logs_text)
        layout.addLayout(button_layout)
        
        self.tab_widget.addTab(self.logs_tab, "Logs")
    
    def load_rules(self):
        """Load rules into the rules list."""
        self.rules_list.clear()
        for rule in self.rule_manager.rules:
            self.rules_list.addItem(rule.get('name', 'Unnamed Rule'))
    
    def start_scan(self):
        """Start a new scan."""
        self.status_bar.showMessage("Scanning...")
        self.running = True
        self.status_label.setText("Scanning")
        # TODO: Implement scan logic
    
    def stop_scan(self):
        """Stop the current scan."""
        self.running = False
        self.status_bar.showMessage("Scan stopped")
        self.status_label.setText("Stopped")
    
    def refresh_ui(self):
        """Refresh the UI components."""
        self.load_rules()
        self.threats_count.setText(str(len(self.alerts)))
        self.rules_count.setText(str(len(self.rule_manager.rules)))
    
    def show_about_dialog(self):
        """Show the about dialog."""
        QMessageBox.about(self, "About EDR",
                         f"<h2>Endpoint Detection and Response</h2>"
                         f"<p>Version: {__version__}</p>"
                         f"<p>Copyright © 2025 Security Ops Center</p>")
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop any running scans
        self.stop_scan()
        
        # Ask for confirmation
        reply = QMessageBox.question(
            self, 'Confirm Exit',
            'Are you sure you want to exit?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

def main():
    """Main entry point for the EDR GUI application."""
    try:
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("edr_gui.log")
            ]
        )
        
        logger = logging.getLogger('edr')
        logger.info("Starting EDR GUI application")
        
        # Create the application
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Create and show the main window
        window = EDRWindow()
        window.show()
        
        logger.info("EDR GUI started successfully")
        
        # Run the application
        sys.exit(app.exec_())
        
    except Exception as e:
        logger = logging.getLogger('edr')
        logger.critical(f"Fatal error in EDR GUI: {str(e)}", exc_info=True)
        
        # Show error message if possible
        try:
            app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(
                None,
                "Fatal Error",
                f"A fatal error occurred: {str(e)}\n\nCheck the logs for more details."
            )
            sys.exit(1)
        except:
            sys.exit(1)

if __name__ == "__main__":
    main()
