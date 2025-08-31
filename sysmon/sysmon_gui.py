import sys
import win32evtlog
import win32evtlogutil
import win32con
import win32api
import win32security
import datetime
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, 
                            QTableWidgetItem, QPushButton, QComboBox, QLabel, QHBoxLayout,
                            QLineEdit, QHeaderView, QMessageBox, QTabWidget, QSplitter,
                            QGroupBox, QFormLayout, QTextEdit, QFileDialog, QStatusBar, QDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal as Signal
from PyQt5.QtGui import QFont, QTextCursor

class SysmonEventFetcher(QThread):
    update_signal = Signal(dict)
    finished_signal = Signal()
    
    def __init__(self, event_types=None, limit=1000):
        super().__init__()
        self.event_types = event_types or ["all"]
        self.limit = limit
        self.running = True
        
    def run(self):
        try:
            server = 'localhost'
            logtype = 'Microsoft-Windows-Sysmon/Operational'
            
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            
            count = 0
            while self.running and count < self.limit:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    if not self.running or count >= self.limit:
                        break
                        
                    event_id = event.EventID
                    if self.event_types != ["all"] and str(event_id) not in self.event_types:
                        continue
                        
                    event_data = {
                        'EventID': event_id,
                        'TimeCreated': event.TimeGenerated.Format(),
                        'Computer': event.ComputerName,
                        'Source': event.SourceName,
                        'Level': self._get_event_level(event.EventType),
                        'Message': self._get_event_message(event)
                    }
                    
                    self.update_signal.emit(event_data)
                    count += 1
                    
        except Exception as e:
            print(f"Error: {str(e)}")
        finally:
            if 'hand' in locals():
                win32evtlog.CloseEventLog(hand)
            self.finished_signal.emit()
    
    def stop(self):
        self.running = False
        
    def _get_event_level(self, event_type):
        levels = {
            win32con.EVENTLOG_ERROR_TYPE: "Error",
            win32con.EVENTLOG_WARNING_TYPE: "Warning",
            win32con.EVENTLOG_INFORMATION_TYPE: "Information",
            win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
            win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure"
        }
        return levels.get(event_type, "Unknown")
    
    def _get_event_message(self, event):
        try:
            return win32evtlogutil.SafeFormatMessage(event, "Microsoft-Windows-Sysmon")
        except:
            return ""

class SysmonGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sysmon Viewer")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #d0d0d0;
                gridline-color: #e0e0e0;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                padding: 4px;
                border: 1px solid #d0d0d0;
                font-weight: bold;
            }
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #3a76d8;
            }
            QPushButton:pressed {
                background-color: #2a66c8;
            }
            QComboBox, QLineEdit {
                padding: 5px;
                border: 1px solid #d0d0d0;
                border-radius: 4px;
                min-width: 120px;
            }
            QGroupBox {
                border: 1px solid #d0d0d0;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        self.init_ui()
        self.statusBar().showMessage("Ready")
        
        # Initialize worker thread
        self.worker = None
        
    def init_ui(self):
        # Create toolbar
        self.create_toolbar()
        
        # Create main splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Create filter panel
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout()
        
        # Event Type Filter
        type_label = QLabel("Event Type:")
        self.event_type_combo = QComboBox()
        self.event_type_combo.addItems(["All Events", "Process Create (1)", "File creation (11)", 
                                      "Network connection (3)", "Process Terminate (5)"])
        
        # Time Filter
        time_label = QLabel("Time Range:")
        self.time_combo = QComboBox()
        self.time_combo.addItems(["Last hour", "Last 12 hours", "Last 24 hours", "Last 7 days", "Custom"])
        
        # Search Box
        search_label = QLabel("Search:")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search in events...")
        self.search_box.returnPressed.connect(self.apply_filters)
        
        # Apply Button
        apply_btn = QPushButton("Apply Filters")
        apply_btn.clicked.connect(self.apply_filters)
        
        # Add widgets to filter layout
        filter_layout.addWidget(type_label)
        filter_layout.addWidget(self.event_type_combo)
        filter_layout.addWidget(time_label)
        filter_layout.addWidget(self.time_combo)
        filter_layout.addWidget(search_label)
        filter_layout.addWidget(self.search_box)
        filter_layout.addWidget(apply_btn)
        filter_layout.addStretch()
        
        filter_group.setLayout(filter_layout)
        
        # Create main tab widget
        self.tabs = QTabWidget()
        
        # Events Tab
        self.events_tab = QWidget()
        self.setup_events_tab()
        self.tabs.addTab(self.events_tab, "Events")
        
        # Dashboard Tab
        self.dashboard_tab = QWidget()
        self.setup_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        
        # Add widgets to splitter
        splitter.addWidget(filter_group)
        splitter.addWidget(self.tabs)
        
        # Set stretch factors
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 10)
        
        # Add splitter to main layout
        self.layout.addWidget(splitter)
        
        # Connect signals
        self.tabs.currentChanged.connect(self.tab_changed)
        
    def create_toolbar(self):
        toolbar = self.addToolBar("Main Toolbar")
        
        # Refresh Button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_events)
        toolbar.addWidget(refresh_btn)
        
        # Export Button
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_events)
        toolbar.addWidget(export_btn)
        
        # Add separator
        toolbar.addSeparator()
        
        # Sysmon Config Button
        config_btn = QPushButton("Sysmon Config")
        config_btn.clicked.connect(self.show_config_dialog)
        toolbar.addWidget(config_btn)
        
    def setup_events_tab(self):
        layout = QVBoxLayout(self.events_tab)
        
        # Create table for events
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["Time", "Event ID", "Level", "Source", "Computer", "Message"])
        self.events_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        # In PyQt5, we need to set the resize mode for each column individually
        for i in range(6):
            if i != 5:  # Don't override the stretch for the message column
                self.events_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.events_table.verticalHeader().setVisible(False)
        self.events_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.events_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.events_table.setSortingEnabled(True)
        self.events_table.doubleClicked.connect(self.show_event_details)
        
        # Set column widths
        self.events_table.setColumnWidth(0, 150)  # Time
        self.events_table.setColumnWidth(1, 70)   # Event ID
        self.events_table.setColumnWidth(2, 80)   # Level
        self.events_table.setColumnWidth(3, 150)  # Source
        self.events_table.setColumnWidth(4, 150)  # Computer
        
        layout.addWidget(self.events_table)
        
    def setup_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Add some sample dashboard widgets
        # In a real application, you would add charts and statistics here
        
        # Summary Group
        summary_group = QGroupBox("Summary")
        summary_layout = QHBoxLayout()
        
        # Add summary items
        summary_items = [
            ("Total Events", "0"),
            ("Process Creations", "0"),
            ("Network Connections", "0"),
            ("File Creations", "0")
        ]
        
        for label, value in summary_items:
            item_layout = QVBoxLayout()
            value_label = QLabel(value)
            value_label.setFont(QFont("Arial", 16, QFont.Bold))
            item_layout.addWidget(value_label, 0, Qt.AlignCenter)
            
            label_widget = QLabel(label)
            label_widget.setStyleSheet("color: #666;")
            item_layout.addWidget(label_widget, 0, Qt.AlignCenter)
            
            summary_layout.addLayout(item_layout)
        
        summary_group.setLayout(summary_layout)
        
        # Add to main layout
        layout.addWidget(summary_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
    def refresh_events(self):
        self.statusBar().showMessage("Loading events...")
        
        # Stop any existing worker
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        
        # Clear existing data
        self.events_table.setRowCount(0)
        
        # Determine event types to fetch
        event_type_text = self.event_type_combo.currentText()
        event_types = []
        
        if "All" not in event_type_text:
            # Extract event ID from text, e.g., "Process Create (1)" -> "1"
            if "(" in event_type_text and ")" in event_type_text:
                event_id = event_type_text.split("(")[1].split(")")[0]
                event_types = [event_id]
        
        # Create and start worker thread
        self.worker = SysmonEventFetcher(event_types=event_types, limit=1000)
        self.worker.update_signal.connect(self.update_events_table)
        self.worker.finished_signal.connect(self.on_fetch_complete)
        self.worker.start()
    
    def update_events_table(self, event_data):
        row_position = self.events_table.rowCount()
        self.events_table.insertRow(row_position)
        
        # Add data to table
        self.events_table.setItem(row_position, 0, QTableWidgetItem(event_data['TimeCreated']))
        self.events_table.setItem(row_position, 1, QTableWidgetItem(str(event_data['EventID'])))
        self.events_table.setItem(row_position, 2, QTableWidgetItem(event_data['Level']))
        self.events_table.setItem(row_position, 3, QTableWidgetItem(event_data['Source']))
        self.events_table.setItem(row_position, 4, QTableWidgetItem(event_data['Computer']))
        
        # Truncate long messages for the table view
        message = event_data['Message']
        if len(message) > 200:
            message = message[:200] + "..."
        self.events_table.setItem(row_position, 5, QTableWidgetItem(message))
        
        # Store full message as user data
        self.events_table.item(row_position, 0).setData(Qt.UserRole, event_data)
    
    def on_fetch_complete(self):
        self.statusBar().showMessage(f"Loaded {self.events_table.rowCount()} events")
    
    def apply_filters(self):
        self.refresh_events()
    
    def show_event_details(self, index):
        row = index.row()
        event_data = self.events_table.item(row, 0).data(Qt.UserRole)
        
        # Create a dialog to show event details
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Event ID: {event_data['EventID']}")
        dialog.resize(800, 600)
        
        layout = QVBoxLayout(dialog)
        
        # Create a text edit to display the full message
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Consolas", 10))
        
        # Format the event data for display
        details = f"""
        Time: {event_data['TimeCreated']}
        Event ID: {event_data['EventID']}
        Level: {event_data['Level']}
        Source: {event_data['Source']}
        Computer: {event_data['Computer']}
        
        Message:
        {event_data['Message']}
        """
        
        text_edit.setPlainText(details)
        
        # Add a close button
        button_box = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        button_box.addStretch()
        button_box.addWidget(close_btn)
        
        # Add widgets to layout
        layout.addWidget(text_edit)
        layout.addLayout(button_box)
        
        # Show the dialog
        dialog.exec_()
    
    def export_events(self):
        if self.events_table.rowCount() == 0:
            QMessageBox.information(self, "Export", "No events to export")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Events", "", "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                # Prepare data for export
                data = []
                headers = ["Time", "Event ID", "Level", "Source", "Computer", "Message"]
                
                for row in range(self.events_table.rowCount()):
                    event_data = self.events_table.item(row, 0).data(Qt.UserRole)
                    data.append([
                        event_data['TimeCreated'],
                        event_data['EventID'],
                        event_data['Level'],
                        event_data['Source'],
                        event_data['Computer'],
                        event_data['Message']
                    ])
                
                # Create DataFrame and save to CSV
                df = pd.DataFrame(data, columns=headers)
                df.to_csv(file_path, index=False)
                
                self.statusBar().showMessage(f"Exported {len(data)} events to {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export events: {str(e)}")
    
    def show_config_dialog(self):
        QMessageBox.information(
            self,
            "Sysmon Configuration", 
            "This feature would show the current Sysmon configuration and allow editing it."
        )
    
    def tab_changed(self, index):
        if index == 0:  # Events tab
            pass
        elif index == 1:  # Dashboard tab
            # Update dashboard data here
            pass
    
    def closeEvent(self, event):
        # Ensure worker thread is properly stopped when closing the application
        if hasattr(self, 'worker') and self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = SysmonGUI()
    window.show()
    
    # Load initial data
    window.refresh_events()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
