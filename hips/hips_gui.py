"""
HIPS GUI Module - PyQt5 Version

Provides a PyQt5-based graphical interface for the Host Intrusion Prevention System.
"""
import sys
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import os
import json
import queue
import threading

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView, 
    QStatusBar, QMenu, QAction, QFileDialog, QMessageBox, QFrame, QSplitter
)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QIcon, QFont

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('hips.gui.qt5')

class HIPSGUI(QMainWindow):
    """Main HIPS GUI application using PyQt5."""
    
    def __init__(self):
        """Initialize the HIPS GUI."""
        super().__init__()
        
        # Initialize HIPS components
        self.monitoring = False
        self.events = []
        self.event_queue = queue.Queue()
        self.rules = {}
        
        # Setup UI
        self.setup_ui()
        
        # Start event processing timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_events)
        self.timer.start(100)  # Process events every 100ms
        
        # Load sample data
        self.load_sample_rules()
        
    def setup_ui(self):
        """Initialize the main UI components."""
        self.setWindowTitle("Host Intrusion Prevention System")
        self.setMinimumSize(1000, 600)
        self.resize(1200, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_process_monitor_tab()
        self.setup_network_firewall_tab()
        self.setup_rules_tab()
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply styles
        self.apply_styles()
    
    def apply_styles(self):
        """Apply custom styles to the application."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QTabWidget::pane {
                border: 1px solid #c4c4c4;
                border-radius: 4px;
                margin: 2px;
                background: white;
            }
            QTabBar::tab {
                background: #e0e0e0;
                padding: 8px 12px;
                border: 1px solid #c4c4c4;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom: 1px solid white;
                margin-bottom: -1px;
            }
            QTreeWidget {
                border: 1px solid #c4c4c4;
                border-radius: 4px;
                background: white;
                alternate-background-color: #f9f9f9;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QPushButton {
                padding: 5px 10px;
                border: 1px solid #c4c4c4;
                border-radius: 4px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 #f6f7fa, stop:1 #dadbde);
                min-width: 80px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 #e7e7e7, stop:1 #d3d3d3);
            }
            QPushButton:pressed {
                background: #d0d0d0;
            }
            QPushButton:disabled {
                background: #e0e0e0;
                color: #a0a0a0;
            }
            QLabel[title="true"] {
                font-weight: bold;
                font-size: 11pt;
                color: #333333;
            }
        """)
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab."""
        tab = QWidget()
        self.tab_widget.addTab(tab, "Dashboard")
        layout = QVBoxLayout(tab)
        
        # Stats frame
        stats_frame = QFrame()
        stats_frame.setFrameShape(QFrame.StyledPanel)
        stats_frame.setMaximumHeight(120)
        stats_layout = QHBoxLayout(stats_frame)
        
        # Stats widgets
        stats = [
            ("Process Monitoring", "Stopped"),
            ("Network Firewall", "Inactive"),
            ("Exploit Prevention", "Inactive"),
            ("Active Rules", "0")
        ]
        
        for label, value in stats:
            frame = QFrame()
            frame_layout = QVBoxLayout(frame)
            
            lbl = QLabel(label)
            lbl.setProperty('title', True)
            frame_layout.addWidget(lbl)
            
            var = QLabel(value)
            var.setAlignment(Qt.AlignCenter)
            font = var.font()
            font.setPointSize(12)
            var.setFont(font)
            frame_layout.addWidget(var)
            
            # Store variables for updates
            setattr(self, f"stat_{label.lower().replace(' ', '_')}", var)
            
            stats_layout.addWidget(frame)
        
        layout.addWidget(stats_frame)
        
        # Recent events
        events_frame = QFrame()
        events_frame.setFrameShape(QFrame.StyledPanel)
        events_layout = QVBoxLayout(events_frame)
        
        events_label = QLabel("Recent Security Events")
        events_label.setProperty('title', True)
        events_layout.addWidget(events_label)
        
        # Events table
        columns = ["Time", "Type", "Process", "Action", "Details"]
        self.events_tree = QTreeWidget()
        self.events_tree.setHeaderLabels(columns)
        self.events_tree.setColumnCount(len(columns))
        self.events_tree.setSortingEnabled(True)
        self.events_tree.sortByColumn(0, Qt.DescendingOrder)
        
        # Set column widths
        col_widths = {"Time": 150, "Type": 100, "Process": 150, "Action": 100, "Details": 300}
        for i, col in enumerate(columns):
            self.events_tree.header().setSectionResizeMode(i, QHeaderView.Interactive)
            self.events_tree.setColumnWidth(i, col_widths.get(col, 100))
        
        # Enable context menu
        self.events_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.events_tree.customContextMenuRequested.connect(self.show_event_menu)
        
        events_layout.addWidget(self.events_tree)
        layout.addWidget(events_frame, 1)
    
    def setup_process_monitor_tab(self):
        """Setup the process monitor tab."""
        tab = QWidget()
        self.tab_widget.addTab(tab, "Process Monitor")
        layout = QVBoxLayout(tab)
        
        # Controls
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        
        self.start_monitor_btn = QPushButton("Start Monitoring")
        self.start_monitor_btn.clicked.connect(self.toggle_monitoring)
        
        add_rule_btn = QPushButton("Add Rule")
        add_rule_btn.clicked.connect(self.add_process_rule)
        
        control_layout.addWidget(self.start_monitor_btn)
        control_layout.addWidget(add_rule_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Process list
        process_frame = QFrame()
        process_frame.setFrameShape(QFrame.StyledPanel)
        process_layout = QVBoxLayout(process_frame)
        
        process_label = QLabel("Running Processes")
        process_label.setProperty('title', True)
        process_layout.addWidget(process_label)
        
        # Process table
        columns = ["PID", "Name", "User", "CPU %", "Memory %", "Status"]
        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(columns)
        self.process_tree.setColumnCount(len(columns))
        self.process_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        
        # Set column widths
        col_widths = {"PID": 80, "Name": 200, "User": 150, "CPU %": 80, "Memory %": 80, "Status": 100}
        for i, col in enumerate(columns):
            self.process_tree.header().setSectionResizeMode(i, QHeaderView.Interactive)
            self.process_tree.setColumnWidth(i, col_widths.get(col, 100))
        
        # Enable context menu
        self.process_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_tree.customContextMenuRequested.connect(self.show_process_menu)
        
        process_layout.addWidget(self.process_tree)
        layout.addWidget(process_frame, 1)
    
    def setup_network_firewall_tab(self):
        """Setup the network firewall tab."""
        tab = QWidget()
        self.tab_widget.addTab(tab, "Network Firewall")
        layout = QVBoxLayout(tab)
        
        # Controls
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        
        add_rule_btn = QPushButton("Add Rule")
        add_rule_btn.clicked.connect(self.add_firewall_rule)
        
        control_layout.addWidget(add_rule_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Rules list
        rules_frame = QFrame()
        rules_frame.setFrameShape(QFrame.StyledPanel)
        rules_layout = QVBoxLayout(rules_frame)
        
        rules_label = QLabel("Firewall Rules")
        rules_label.setProperty('title', True)
        rules_layout.addWidget(rules_label)
        
        # Rules table
        columns = ["Enabled", "Name", "Direction", "Protocol", "Source", "Destination", "Ports", "Action"]
        self.firewall_tree = QTreeWidget()
        self.firewall_tree.setHeaderLabels(columns)
        self.firewall_tree.setColumnCount(len(columns))
        self.firewall_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        
        # Set column widths
        col_widths = {
            "Enabled": 60, "Name": 150, "Direction": 80, "Protocol": 80,
            "Source": 120, "Destination": 120, "Ports": 100, "Action": 80
        }
        for i, col in enumerate(columns):
            self.firewall_tree.header().setSectionResizeMode(i, QHeaderView.Interactive)
            self.firewall_tree.setColumnWidth(i, col_widths.get(col, 100))
        
        # Enable context menu
        self.firewall_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.firewall_tree.customContextMenuRequested.connect(self.show_rule_menu)
        
        rules_layout.addWidget(self.firewall_tree)
        layout.addWidget(rules_frame, 1)
    
    def setup_rules_tab(self):
        """Setup the rules management tab."""
        tab = QWidget()
        self.tab_widget.addTab(tab, "Rules")
        layout = QVBoxLayout(tab)
        
        # Rules list
        rules_frame = QFrame()
        rules_frame.setFrameShape(QFrame.StyledPanel)
        rules_layout = QVBoxLayout(rules_frame)
        
        rules_label = QLabel("HIPS Rules")
        rules_label.setProperty('title', True)
        rules_layout.addWidget(rules_label)
        
        # Rules table
        columns = ["Enabled", "Name", "Type", "Target", "Action", "Description"]
        self.rules_tree = QTreeWidget()
        self.rules_tree.setHeaderLabels(columns)
        self.rules_tree.setColumnCount(len(columns))
        self.rules_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        
        # Set column widths
        col_widths = {
            "Enabled": 60, "Name": 150, "Type": 100,
            "Target": 200, "Action": 80, "Description": 300
        }
        for i, col in enumerate(columns):
            self.rules_tree.header().setSectionResizeMode(i, QHeaderView.Interactive)
            self.rules_tree.setColumnWidth(i, col_widths.get(col, 100))
        
        rules_layout.addWidget(self.rules_tree)
        layout.addWidget(rules_frame, 1)
        
        # Buttons
        btn_frame = QFrame()
        btn_layout = QHBoxLayout(btn_frame)
        
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        
        edit_btn = QPushButton("Edit Rule")
        edit_btn.clicked.connect(self.edit_rule)
        
        delete_btn = QPushButton("Delete Rule")
        delete_btn.clicked.connect(self.delete_rule)
        
        import_btn = QPushButton("Import Rules")
        import_btn.clicked.connect(self.import_rules)
        
        export_btn = QPushButton("Export Rules")
        export_btn.clicked.connect(self.export_rules)
        
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(edit_btn)
        btn_layout.addWidget(delete_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(import_btn)
        btn_layout.addWidget(export_btn)
        
        layout.addWidget(btn_frame)
    
    # ===== Event Handlers =====
    
    def toggle_monitoring(self):
        """Toggle process monitoring."""
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.start_monitor_btn.setText("Stop Monitoring")
            self.status_bar.showMessage("Process monitoring started")
            self.stat_process_monitoring.setText("Running")
        else:
            self.start_monitor_btn.setText("Start Monitoring")
            self.status_bar.showMessage("Process monitoring stopped")
            self.stat_process_monitoring.setText("Stopped")
    
    def add_process_rule(self):
        """Add a new process rule."""
        self.show_rule_editor("process")
    
    def add_firewall_rule(self):
        """Add a new firewall rule."""
        self.show_rule_editor("firewall")
    
    def edit_firewall_rule(self):
        """Edit the selected firewall rule."""
        selected = self.firewall_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a rule to edit")
            return
        
        # In a real implementation, this would open an editor with the rule details
        item = selected[0]
        values = [item.text(i) for i in range(self.firewall_tree.columnCount())]
        self.show_rule_editor("firewall", values)
    
    def delete_firewall_rule(self):
        """Delete the selected firewall rule."""
        selected = self.firewall_tree.selectedItems()
        if not selected:
            return
        
        reply = QMessageBox.question(
            self, 'Confirm', 
            f'Delete {len(selected)} selected rule(s)?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for item in selected:
                self.firewall_tree.takeTopLevelItem(
                    self.firewall_tree.indexOfTopLevelItem(item)
                )
            self.status_bar.showMessage(f"Deleted {len(selected)} firewall rule(s)")
    
    def toggle_firewall_rule(self):
        """Toggle the selected firewall rule."""
        selected = self.firewall_tree.selectedItems()
        if not selected:
            return
        
        for item in selected:
            # Toggle enabled state
            enabled = item.text(0) == "Yes"
            item.setText(0, "No" if enabled else "Yes")
    
    def add_rule(self):
        """Add a new HIPS rule."""
        self.show_rule_editor("hips")
    
    def edit_rule(self):
        """Edit the selected HIPS rule."""
        selected = self.rules_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a rule to edit")
            return
        
        # In a real implementation, this would open an editor with the rule details
        item = selected[0]
        values = [item.text(i) for i in range(self.rules_tree.columnCount())]
        self.show_rule_editor("hips", values)
    
    def delete_rule(self):
        """Delete the selected HIPS rule."""
        selected = self.rules_tree.selectedItems()
        if not selected:
            return
        
        reply = QMessageBox.question(
            self, 'Confirm', 
            f'Delete {len(selected)} selected rule(s)?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for item in selected:
                self.rules_tree.takeTopLevelItem(
                    self.rules_tree.indexOfTopLevelItem(item)
                )
            self.status_bar.showMessage(f"Deleted {len(selected)} rule(s)")
    
    def import_rules(self):
        """Import rules from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Rules",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                rules = json.load(f)
                # Process imported rules here
                self.status_bar.showMessage(f"Successfully imported rules from {os.path.basename(file_path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import rules: {str(e)}")
    
    def export_rules(self):
        """Export rules to a file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Rules",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Prepare rules data
            rules = []
            for i in range(self.rules_tree.topLevelItemCount()):
                item = self.rules_tree.topLevelItem(i)
                rule = {
                    "enabled": item.text(0) == "Yes",
                    "name": item.text(1),
                    "type": item.text(2),
                    "target": item.text(3),
                    "action": item.text(4),
                    "description": item.text(5)
                }
                rules.append(rule)
            
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=2)
                
            self.status_bar.showMessage(f"Successfully exported {len(rules)} rules to {os.path.basename(file_path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export rules: {str(e)}")
    
    def show_rule_editor(self, rule_type, values=None):
        """Show the rule editor dialog."""
        # This would be implemented to show a dialog for editing rules
        QMessageBox.information(
            self,
            "Rule Editor",
            f"{rule_type.capitalize()} rule editor would open here"
        )
    
    def show_event_menu(self, position):
        """Show context menu for events."""
        menu = QMenu()
        
        view_action = QAction("View Details", self)
        view_action.triggered.connect(self.view_event_details)
        
        add_rule_action = QAction("Add to Rules", self)
        add_rule_action.triggered.connect(self.add_to_rules)
        
        menu.addAction(view_action)
        menu.addAction(add_rule_action)
        
        menu.exec_(self.events_tree.viewport().mapToGlobal(position))
    
    def show_process_menu(self, position):
        """Show context menu for processes."""
        menu = QMenu()
        
        end_action = QAction("End Process", self)
        end_action.triggered.connect(self.end_process)
        
        block_action = QAction("Add to Blocklist", self)
        block_action.triggered.connect(self.add_to_blocklist)
        
        props_action = QAction("Properties", self)
        props_action.triggered.connect(self.show_process_properties)
        
        menu.addAction(end_action)
        menu.addAction(block_action)
        menu.addSeparator()
        menu.addAction(props_action)
        
        menu.exec_(self.process_tree.viewport().mapToGlobal(position))
    
    def show_rule_menu(self, position):
        """Show context menu for firewall rules."""
        menu = QMenu()
        
        edit_action = QAction("Edit Rule", self)
        edit_action.triggered.connect(self.edit_firewall_rule)
        
        delete_action = QAction("Delete Rule", self)
        delete_action.triggered.connect(self.delete_firewall_rule)
        
        toggle_action = QAction("Enable/Disable", self)
        toggle_action.triggered.connect(self.toggle_firewall_rule)
        
        menu.addAction(edit_action)
        menu.addAction(delete_action)
        menu.addSeparator()
        menu.addAction(toggle_action)
        
        menu.exec_(self.firewall_tree.viewport().mapToGlobal(position))
    
    def view_event_details(self):
        """View details of the selected event."""
        selected = self.events_tree.selectedItems()
        if not selected:
            return
        
        # Show event details in a dialog
        item = selected[0]
        details = "\n".join([
            f"{self.events_tree.headerItem().text(i)}: {item.text(i)}" 
            for i in range(self.events_tree.columnCount())
        ])
        
        QMessageBox.information(
            self,
            "Event Details",
            details
        )
    
    def add_to_rules(self):
        """Add selected event to rules."""
        selected = self.events_tree.selectedItems()
        if not selected:
            return
        
        # This would open the rule editor with pre-filled values from the event
        self.show_rule_editor("hips")
    
    def end_process(self):
        """End the selected process."""
        selected = self.process_tree.selectedItems()
        if not selected:
            return
        
        reply = QMessageBox.question(
            self, 'Confirm', 
            f'End {len(selected)} selected process(es)?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # In a real implementation, this would terminate the processes
            for item in selected:
                self.process_tree.takeTopLevelItem(
                    self.process_tree.indexOfTopLevelItem(item)
                )
            self.status_bar.showMessage(f"Terminated {len(selected)} process(es)")
    
    def add_to_blocklist(self):
        """Add selected process to blocklist."""
        selected = self.process_tree.selectedItems()
        if not selected:
            return
        
        # This would add the process to the blocklist
        process_names = [item.text(1) for item in selected]
        self.status_bar.showMessage(f"Added {len(process_names)} process(es) to blocklist")
    
    def show_process_properties(self):
        """Show properties of the selected process."""
        selected = self.process_tree.selectedItems()
        if not selected:
            return
        
        # Show process properties in a dialog
        item = selected[0]
        details = "\n".join([
            f"{self.process_tree.headerItem().text(i)}: {item.text(i)}" 
            for i in range(self.process_tree.columnCount())
        ])
        
        QMessageBox.information(
            self,
            "Process Properties",
            details
        )
    
    def load_sample_rules(self):
        """Load sample rules into the UI."""
        sample_rules = [
            ("Yes", "Block CMD", "Process", "cmd.exe", "Block", "Prevent command prompt execution"),
            ("Yes", "Block PowerShell", "Process", "powershell.exe", "Block", "Prevent PowerShell execution"),
            ("Yes", "Block Registry Edits", "Registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Block", "Prevent auto-run registry changes")
        ]
        
        for rule in sample_rules:
            item = QTreeWidgetItem(self.rules_tree, rule)
            self.rules_tree.addTopLevelItem(item)
    
    def process_events(self):
        """Process pending events from the queue."""
        try:
            while True:
                event = self.event_queue.get_nowait()
                self.handle_event(event)
        except queue.Empty:
            pass
    
    def handle_event(self, event):
        """Handle a single event."""
        # Add event to the tree
        item = QTreeWidgetItem([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event.get("type", "Unknown"),
            event.get("process", ""),
            event.get("action", ""),
            event.get("details", "")
        ])
        self.events_tree.insertTopLevelItem(0, item)
        
        # Keep only the last 1000 events
        while self.events_tree.topLevelItemCount() > 1000:
            self.events_tree.takeTopLevelItem(self.events_tree.topLevelItemCount() - 1)

def main():
    """Main entry point for the HIPS GUI application."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = HIPSGUI()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
