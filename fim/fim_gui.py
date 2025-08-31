"""
FIM GUI Module (PyQt5 Version)

Provides a PyQt5-based graphical interface for the File Integrity Monitoring system.
"""
import sys
import os
import logging
import queue
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTabWidget, QLabel, QPushButton, QFileDialog, QMessageBox,
                            QTreeWidget, QTreeWidgetItem, QHeaderView, QSplitter, 
                            QTextEdit, QFormLayout, QLineEdit, QGroupBox, QComboBox,
                            QStatusBar, QAction, QMenu, QToolBar, QStyle)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette

# Local imports
from .core import FileEvent, EventType
from .monitors import DirectoryMonitor, FileMonitor

logger = logging.getLogger('fim.gui')

class EventProcessor(QObject):
    """Worker thread for processing file system events."""
    event_processed = pyqtSignal(object)  # Signal emitted when an event is processed
    
    def __init__(self, event_queue):
        super().__init__()
        self.event_queue = event_queue
        self.running = True
    
    def process_events(self):
        """Process events from the queue."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=0.1)
                self.event_processed.emit(event)
            except Exception as e:
                # Timeout is expected when queue is empty
                if not isinstance(e, queue.Empty):
                    logger.error(f"Error processing event: {e}")
    
    def stop(self):
        """Stop the event processor."""
        self.running = False

class FIMWindow(QMainWindow):
    """Main FIM GUI application window."""
    
    def __init__(self):
        """Initialize the FIM GUI."""
        super().__init__()
        
        # Initialize FIM components
        self.watchers: Dict[str, DirectoryMonitor | FileMonitor] = {}
        self.events: List[FileEvent] = []
        self.event_queue = queue.Queue()
        self.running = False
        self.event_processor = None
        self.processor_thread = None
        
        # Setup UI
        self.setup_ui()
        
        # Setup status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Set window properties
        self.setWindowTitle("File Integrity Monitor (PyQt5)")
        self.setGeometry(100, 100, 1200, 800)
        
        # Start event processing
        self.start_event_processing()
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.setup_menu_bar()
        
        # Create toolbar
        self.setup_toolbar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create dashboard tab
        self.setup_dashboard_tab()
        
        # Create events tab
        self.setup_events_tab()
        
        # Create watchers tab
        self.setup_watchers_tab()
        
        # Create settings tab
        self.setup_settings_tab()
    
    def setup_menu_bar(self):
        """Set up the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        # Add actions
        add_watcher_action = QAction('Add &Watcher', self)
        add_watcher_action.triggered.connect(self.add_watcher_dialog)
        file_menu.addAction(add_watcher_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('&View')
        
        # Tools menu
        tools_menu = menubar.addMenu('&Tools')
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
    
    def setup_toolbar(self):
        """Set up the toolbar."""
        toolbar = self.addToolBar('Main Toolbar')
        
        # Add watcher button
        add_watcher_icon = self.style().standardIcon(QStyle.SP_FileDialogNewFolder)
        add_watcher_action = QAction(add_watcher_icon, 'Add Watcher', self)
        add_watcher_action.triggered.connect(self.add_watcher_dialog)
        toolbar.addAction(add_watcher_action)
        
        # Start/Stop monitoring button
        self.monitor_action = QAction('Start Monitoring', self)
        self.monitor_action.triggered.connect(self.toggle_monitoring)
        toolbar.addAction(self.monitor_action)
    
    def setup_dashboard_tab(self):
        """Set up the dashboard tab."""
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        # Add welcome message
        welcome_label = QLabel("<h1>File Integrity Monitor</h1>")
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)
        
        # Add status group
        status_group = QGroupBox("Status")
        status_layout = QFormLayout()
        
        self.status_label = QLabel("Not Monitoring")
        self.watchers_count = QLabel("0")
        self.events_count = QLabel("0")
        
        status_layout.addRow("Status:", self.status_label)
        status_layout.addRow("Active Watchers:", self.watchers_count)
        status_layout.addRow("Events Captured:", self.events_count)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Add recent events
        recent_events_group = QGroupBox("Recent Events")
        recent_events_layout = QVBoxLayout()
        
        self.recent_events_table = QTreeWidget()
        self.recent_events_table.setHeaderLabels(["Time", "Type", "Path", "Details"])
        self.recent_events_table.setColumnCount(4)
        self.recent_events_table.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        recent_events_layout.addWidget(self.recent_events_table)
        recent_events_group.setLayout(recent_events_layout)
        layout.addWidget(recent_events_group, 1)  # 1 is stretch factor
        
        # Add the tab
        self.tabs.addTab(dashboard_tab, "Dashboard")
    
    def setup_events_tab(self):
        """Set up the events tab."""
        events_tab = QWidget()
        layout = QVBoxLayout(events_tab)
        
        # Add events table
        self.events_table = QTreeWidget()
        self.events_table.setHeaderLabels(["Time", "Type", "Path", "Details"])
        self.events_table.setColumnCount(4)
        self.events_table.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # Add context menu
        self.events_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.events_table.customContextMenuRequested.connect(self.show_events_context_menu)
        
        layout.addWidget(self.events_table)
        
        # Add the tab
        self.tabs.addTab(events_tab, "Events")
    
    def setup_watchers_tab(self):
        """Set up the watchers tab."""
        watchers_tab = QWidget()
        layout = QVBoxLayout(watchers_tab)
        
        # Add watchers table
        self.watchers_table = QTreeWidget()
        self.watchers_table.setHeaderLabels(["Path", "Type", "Status"])
        self.watchers_table.setColumnCount(3)
        self.watchers_table.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # Add context menu
        self.watchers_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.watchers_table.customContextMenuRequested.connect(self.show_watchers_context_menu)
        
        layout.addWidget(self.watchers_table)
        
        # Add the tab
        self.tabs.addTab(watchers_tab, "Watchers")
    
    def setup_settings_tab(self):
        """Set up the settings tab."""
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # Add settings form
        settings_group = QGroupBox("Settings")
        settings_layout = QFormLayout()
        
        # Add settings controls here
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.setCurrentText("INFO")
        self.log_level_combo.currentTextChanged.connect(self.update_log_level)
        
        settings_layout.addRow("Log Level:", self.log_level_combo)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Add the tab
        self.tabs.addTab(settings_tab, "Settings")
    
    def start_event_processing(self):
        """Start the event processing thread."""
        self.event_processor = EventProcessor(self.event_queue)
        self.event_processor.event_processed.connect(self.handle_file_event)
        
        self.processor_thread = QThread()
        self.event_processor.moveToThread(self.processor_thread)
        
        # Connect signals
        self.processor_thread.started.connect(self.event_processor.process_events)
        self.processor_thread.finished.connect(self.event_processor.deleteLater)
        
        # Start the thread
        self.processor_thread.start()
    
    def stop_event_processing(self):
        """Stop the event processing thread."""
        if self.event_processor:
            self.event_processor.stop()
        
        if self.processor_thread and self.processor_thread.isRunning():
            self.processor_thread.quit()
            self.processor_thread.wait()
    
    def add_watcher_dialog(self):
        """Show the 'Add Watcher' dialog."""
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Watch")
        if path:
            self.add_watcher(path)
    
    def add_watcher(self, path):
        """Add a new directory or file watcher."""
        try:
            path = os.path.normpath(path)
            
            # Check if already watching
            if path in self.watchers:
                QMessageBox.information(self, "Already Watching", f"Already watching: {path}")
                return
            
            # Determine if it's a directory or file
            if os.path.isdir(path):
                watcher = DirectoryMonitor(path, self.event_queue)
            else:
                watcher = FileMonitor(path, self.event_queue)
            
            # Start the watcher
            watcher.start()
            
            # Add to watchers dictionary
            self.watchers[path] = watcher
            
            # Update UI
            self.update_watchers_list()
            self.status_bar.showMessage(f"Added watcher for: {path}", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add watcher: {e}")
    
    def remove_watcher(self, path):
        """Remove a watcher."""
        try:
            if path in self.watchers:
                watcher = self.watchers[path]
                watcher.stop()
                del self.watchers[path]
                
                # Update UI
                self.update_watchers_list()
                self.status_bar.showMessage(f"Removed watcher: {path}", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove watcher: {e}")
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if self.running:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start all watchers."""
        try:
            for watcher in self.watchers.values():
                watcher.start()
            
            self.running = True
            self.monitor_action.setText("Stop Monitoring")
            self.status_label.setText("<font color='green'>Monitoring</font>")
            self.status_bar.showMessage("Monitoring started", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop all watchers."""
        try:
            for watcher in self.watchers.values():
                watcher.stop()
            
            self.running = False
            self.monitor_action.setText("Start Monitoring")
            self.status_label.setText("<font color='red'>Not Monitoring</font>")
            self.status_bar.showMessage("Monitoring stopped", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error stopping monitoring: {e}")
    
    def handle_file_event(self, event):
        """Handle a file system event."""
        # Add to events list
        self.events.append(event)
        
        # Update UI
        self.update_events_list()
        self.update_dashboard()
    
    def update_events_list(self):
        """Update the events list with the latest events."""
        self.events_table.clear()
        
        for event in reversed(self.events[-1000:]):  # Show up to 1000 most recent events
            item = QTreeWidgetItem([
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.event_type.name,
                event.path,
                event.details or ""
            ])
            
            # Color code by event type
            if event.event_type == EventType.CREATED:
                item.setForeground(1, QColor(0, 128, 0))  # Green for created
            elif event.event_type == EventType.MODIFIED:
                item.setForeground(1, QColor(0, 0, 255))  # Blue for modified
            elif event.event_type == EventType.DELETED:
                item.setForeground(1, QColor(255, 0, 0))  # Red for deleted
            
            self.events_table.addTopLevelItem(item)
    
    def update_watchers_list(self):
        """Update the watchers list."""
        self.watchers_table.clear()
        
        for path, watcher in self.watchers.items():
            watcher_type = "Directory" if isinstance(watcher, DirectoryMonitor) else "File"
            status = "Running" if watcher.running else "Stopped"
            
            item = QTreeWidgetItem([path, watcher_type, status])
            self.watchers_table.addTopLevelItem(item)
    
    def update_dashboard(self):
        """Update the dashboard with current status."""
        # Update status
        status = "<font color='green'>Monitoring</font>" if self.running else "<font color='red'>Not Monitoring</font>"
        self.status_label.setText(status)
        
        # Update counts
        self.watchers_count.setText(str(len(self.watchers)))
        self.events_count.setText(str(len(self.events)))
        
        # Update recent events (show last 10)
        self.recent_events_table.clear()
        for event in reversed(self.events[-10:]):
            item = QTreeWidgetItem([
                event.timestamp.strftime("%H:%M:%S"),
                event.event_type.name,
                os.path.basename(event.path),
                event.details or ""
            ])
            
            # Color code by event type (same as in update_events_list)
            if event.event_type == EventType.CREATED:
                item.setForeground(1, QColor(0, 128, 0))
            elif event.event_type == EventType.MODIFIED:
                item.setForeground(1, QColor(0, 0, 255))
            elif event.event_type == EventType.DELETED:
                item.setForeground(1, QColor(255, 0, 0))
            
            self.recent_events_table.addTopLevelItem(item)
    
    def show_events_context_menu(self, position):
        """Show context menu for events table."""
        item = self.events_table.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        
        copy_action = menu.addAction("Copy Path")
        open_action = menu.addAction("Open in File Explorer")
        
        action = menu.exec_(self.events_table.viewport().mapToGlobal(position))
        
        if action == copy_action:
            path = item.text(2)  # Path is in column 2
            QApplication.clipboard().setText(path)
            self.status_bar.showMessage(f"Copied to clipboard: {path}", 2000)
            
        elif action == open_action:
            path = item.text(2)  # Path is in column 2
            if os.path.exists(path):
                if os.name == 'nt':  # Windows
                    os.startfile(os.path.dirname(path))
                else:  # macOS and Linux
                    import subprocess
                    subprocess.Popen(['xdg-open', os.path.dirname(path)])
    
    def show_watchers_context_menu(self, position):
        """Show context menu for watchers table."""
        item = self.watchers_table.itemAt(position)
        if not item:
            return
        
        path = item.text(0)  # Path is in column 0
        
        menu = QMenu()
        
        remove_action = menu.addAction("Remove Watcher")
        open_action = menu.addAction("Open in File Explorer")
        
        action = menu.exec_(self.watchers_table.viewport().mapToGlobal(position))
        
        if action == remove_action:
            self.remove_watcher(path)
        elif action == open_action:
            if os.path.exists(path):
                if os.name == 'nt':  # Windows
                    os.startfile(os.path.dirname(path) if os.path.isfile(path) else path)
                else:  # macOS and Linux
                    import subprocess
                    subprocess.Popen(['xdg-open', os.path.dirname(path) if os.path.isfile(path) else path])
    
    def update_log_level(self, level):
        """Update the logging level."""
        level = getattr(logging, level.upper())
        logging.getLogger().setLevel(level)
        self.status_bar.showMessage(f"Log level set to: {logging.getLevelName(level)}", 3000)
    
    def show_about_dialog(self):
        """Show the about dialog."""
        QMessageBox.about(self, "About FIM",
                         "<h2>File Integrity Monitor</h2>"
                         "<p>Version 1.0.0</p>"
                         "<p>A PyQt5-based file integrity monitoring tool.</p>")
    
    def closeEvent(self, event):
        """Handle window close event."""
        if self.running:
            reply = QMessageBox.question(
                self, 'Quit',
                'Monitoring is active. Are you sure you want to quit?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.stop_monitoring()
                self.stop_event_processing()
                event.accept()
            else:
                event.ignore()
        else:
            self.stop_event_processing()
            event.accept()

def main():
    """Main entry point for the FIM GUI application."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create the application
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = FIMWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
