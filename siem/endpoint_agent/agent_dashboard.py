"""
SIEM Agent Dashboard using PyQt5
"""
import sys
import json
import time
import psutil
from datetime import datetime
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QLabel, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
                           QHeaderView, QStatusBar, QComboBox, QLineEdit, QFormLayout,
                           QTextEdit, QCheckBox)
from PyQt5.QtCore import QTimer, Qt, QSize
from PyQt5.QtGui import QIcon, QColor, QFont

class SIEMAgentDashboard(QMainWindow):
    def __init__(self, agent, config):
        super().__init__()
        self.agent = agent
        self.config = config
        self.config_file = Path('agent_config.json')
        
        # Get the log file path from agent config and resolve it to an absolute path
        log_file = self.agent.config.get('log_file', 'siem_agent.log')
        self.log_file = Path(log_file).absolute()
        self.log_position = 0
        
        # Ensure the directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create the log file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch()
        
        # Debug: Print log file info
        print(f"[DEBUG] Log file path: {self.log_file}")
        print(f"[DEBUG] Log file exists: {self.log_file.exists()}")
        if self.log_file.exists():
            try:
                size = self.log_file.stat().st_size
                print(f"[DEBUG] Log file size: {size} bytes")
            except Exception as e:
                print(f"[DEBUG] Error getting log file size: {e}")
        
        # Ensure config directory exists
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.setWindowTitle("SIEM Agent Dashboard")
        self.setMinimumSize(1000, 700)
        
        # Initialize UI
        self.init_ui()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(2000)  # Update every 2 seconds
        
        # Log update timer
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.update_logs)
        self.log_timer.start(1000)  # Update logs every second
        
        # Initial update
        self.update_status()
        self.update_logs()
    
    def init_ui(self):
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Header
        header = QLabel("SIEM Agent Dashboard")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setStyleSheet("padding: 10px;")
        layout.addWidget(header)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create tabs
        self.tabs = QTabWidget()
        
        # Status Tab
        self.status_tab = QWidget()
        self.init_status_tab()
        self.tabs.addTab(self.status_tab, "Status")
        
        # Logs Tab
        self.logs_tab = QWidget()
        self.init_logs_tab()
        self.tabs.addTab(self.logs_tab, "Logs")
        
        # Configuration Tab
        self.config_tab = QWidget()
        self.init_config_tab()
        self.tabs.addTab(self.config_tab, "Configuration")
        
        layout.addWidget(self.tabs)
        
        # Initialize log file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.write_text("SIEM Agent Log File\n" + "="*50 + "\n")
        else:
            # Set initial log position to the end of file
            self.log_position = self.log_file.stat().st_size
        
        # Add some styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f2f5;
            }
            QTabWidget::pane {
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 10px;
                background: white;
            }
            QTabBar::tab {
                background: #e5e7eb;
                padding: 8px 16px;
                border: 1px solid #d1d5db;
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
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:disabled {
                background-color: #9ca3af;
            }
            QTableWidget {
                border: 1px solid #d1d5db;
                border-radius: 4px;
                gridline-color: #e5e7eb;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QHeaderView::section {
                background-color: #f3f4f6;
                padding: 8px;
                border: none;
                border-right: 1px solid #e5e7eb;
                border-bottom: 1px solid #e5e7eb;
            }
        """)
    
    def init_status_tab(self):
        layout = QVBoxLayout(self.status_tab)
        
        # System Status Group
        sys_status_group = QWidget()
        sys_layout = QHBoxLayout(sys_status_group)
        
        # CPU Usage
        cpu_widget = self.create_metric_widget("CPU", "0%", "#3b82f6")
        self.cpu_label = cpu_widget.findChild(QLabel, "value")
        
        # Memory Usage
        mem_widget = self.create_metric_widget("Memory", "0%", "#10b981")
        self.mem_label = mem_widget.findChild(QLabel, "value")
        
        # Disk Usage
        disk_widget = self.create_metric_widget("Disk", "0%", "#f59e0b")
        self.disk_label = disk_widget.findChild(QLabel, "value")
        
        # Logs Sent
        logs_widget = self.create_metric_widget("Logs Sent", "0", "#8b5cf6")
        self.logs_label = logs_widget.findChild(QLabel, "value")
        
        sys_layout.addWidget(cpu_widget)
        sys_layout.addWidget(mem_widget)
        sys_layout.addWidget(disk_widget)
        sys_layout.addWidget(logs_widget)
        
        # Agent Status
        agent_group = QWidget()
        agent_layout = QVBoxLayout(agent_group)
        agent_layout.setContentsMargins(10, 20, 10, 10)
        
        # Agent Status
        self.agent_status = QLabel("Agent Status: Not Connected")
        self.agent_status.setStyleSheet("font-size: 14px; font-weight: bold;")
        agent_layout.addWidget(self.agent_status)
        
        # Last Sync
        self.last_sync = QLabel("Last Sync: Never")
        agent_layout.addWidget(self.last_sync)
        
        # Start/Stop Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Agent")
        self.stop_btn = QPushButton("Stop Agent")
        self.stop_btn.setEnabled(False)
        
        self.start_btn.clicked.connect(self.start_agent)
        self.stop_btn.clicked.connect(self.stop_agent)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        agent_layout.addLayout(btn_layout)
        
        # Update button states based on agent status
        self.update_button_states()
        
        # Add to main layout
        layout.addWidget(sys_status_group)
        layout.addWidget(agent_group)
        layout.addStretch()
    
    def init_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        
        # Log Level Filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Log Level:"))
        
        self.log_level = QComboBox()
        self.log_level.addItems(["All", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        filter_layout.addWidget(self.log_level)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search logs...")
        filter_layout.addWidget(self.search_box)
        
        refresh_btn = QPushButton("Refresh")
        filter_layout.addWidget(refresh_btn)
        
        layout.addLayout(filter_layout)
        
        # Logs Table
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(5)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Level", "Source", "Message", "Details"])
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.logs_table.verticalHeader().setVisible(False)
        self.logs_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        layout.addWidget(self.logs_table)
    
    def init_config_tab(self):
        layout = QFormLayout(self.config_tab)
        
        # Server Configuration
        self.server_host = QLineEdit("localhost")
        self.server_port = QLineEdit("10514")
        self.use_tls = QComboBox()
        self.use_tls.addItems(["Disabled", "Enabled"])
        
        # Agent Configuration
        self.agent_id = QLineEdit()
        self.agent_id.setReadOnly(True)
        self.collect_interval = QLineEdit("60")
        
        # Add to form
        layout.addRow("Server Host:", self.server_host)
        layout.addRow("Server Port:", self.server_port)
        layout.addRow("Use TLS:", self.use_tls)
        layout.addRow("Agent ID:", self.agent_id)
        layout.addRow("Collection Interval (s):", self.collect_interval)
        
        # Save Button
        save_btn = QPushButton("Save Configuration")
        save_btn.clicked.connect(self.save_config)
        layout.addRow(save_btn)
    
    def create_metric_widget(self, title, value, color):
        widget = QWidget()
        widget.setStyleSheet(f"""
            QWidget {{
                background: white;
                border-radius: 8px;
                padding: 15px;
                border: 1px solid #e5e7eb;
            }}
            QLabel#title {{
                color: #6b7280;
                font-size: 12px;
                font-weight: 500;
            }}
            QLabel#value {{
                color: {color};
                font-size: 24px;
                font-weight: 600;
            }}
        """)
        
        layout = QVBoxLayout(widget)
        
        title_label = QLabel(title)
        title_label.setObjectName("title")
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        return widget
    
    def update_button_states(self):
        """Update the enabled/disabled state of control buttons."""
        is_running = hasattr(self, 'agent') and getattr(self.agent, 'running', False)
        self.start_btn.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)
        self.agent_status.setText(f"Agent Status: {'Running' if is_running else 'Stopped'}")
    
    def start_agent(self):
        """Start the SIEM agent."""
        if hasattr(self, 'agent'):
            try:
                self.agent.start()
                self.status_bar.showMessage("Agent started successfully", 3000)
                self.update_button_states()
            except Exception as e:
                self.status_bar.showMessage(f"Error starting agent: {e}", 5000)
    
    def stop_agent(self):
        """Stop the SIEM agent."""
        if hasattr(self, 'agent'):
            try:
                self.agent.stop()
                self.status_bar.showMessage("Agent stopped successfully", 3000)
                self.update_button_states()
            except Exception as e:
                self.status_bar.showMessage(f"Error stopping agent: {e}", 5000)
    
    def update_status(self):
        """Update the status display."""
        try:
            # Update system metrics
            cpu_percent = psutil.cpu_percent()
            mem_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            
            self.cpu_label.setText(f"{cpu_percent:.1f}%")
            self.mem_label.setText(f"{mem_percent:.1f}%")
            self.disk_label.setText(f"{disk_percent:.1f}%")
            
            # Update agent status
            self.update_button_states()
            
            # Update last sync time
            if hasattr(self, 'agent') and hasattr(self.agent, 'last_sync'):
                self.last_sync.setText(f"Last Sync: {self.agent.last_sync}")
            
            # Update status bar
            self.status_bar.showMessage(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            self.status_bar.showMessage(f"Error updating status: {e}", 5000)
    
    def update_logs(self):
        """Update the logs display with new log entries."""
        if not hasattr(self, 'logs_table') or not hasattr(self, 'log_file'):
            print("Log display not properly initialized")
            return
            
        try:
            if not self.log_file.exists():
                error_msg = f"Log file not found: {self.log_file.absolute()}"
                print(error_msg)
                self.status_bar.showMessage(error_msg, 5000)
                return
                
            try:
                # Get current size of log file
                current_size = self.log_file.stat().st_size
            except Exception as e:
                error_msg = f"Error getting log file size: {e}"
                print(error_msg)
                self.status_bar.showMessage(error_msg, 5000)
                return
                
            # If file was truncated, reset position
            if hasattr(self, 'last_log_size') and current_size < self.last_log_size:
                self.log_position = 0
                
            # If file hasn't changed, nothing to do
            if hasattr(self, 'last_log_size') and current_size == self.last_log_size:
                return
                
            # Read new log entries
            try:
                with open(self.log_file, 'r', encoding='utf-8', errors='replace') as f:
                    # If we don't have a position or file was reset, start from beginning
                    if not hasattr(self, 'log_position') or self.log_position > current_size:
                        self.log_position = 0
                        
                    # Go to our last position and read new content
                    f.seek(self.log_position)
                    new_logs = f.readlines()
                    self.log_position = f.tell()
                    self.last_log_size = current_size
                    
                    if not new_logs:
                        return  # No new logs to process
                    
                    # Parse and add new log entries
                    for line in new_logs:
                        try:
                            line = line.strip()
                            if not line:  # Skip empty lines
                                continue
                                
                            # Parse the log line (assuming format: timestamp - name - level - message)
                            parts = line.split(' - ', 3)
                            if len(parts) >= 4:
                                timestamp, name, level, message = parts[:4]
                                
                                # Add to logs table
                                row = self.logs_table.rowCount()
                                self.logs_table.insertRow(row)
                                
                                # Set items
                                self.logs_table.setItem(row, 0, QTableWidgetItem(timestamp))
                                self.logs_table.setItem(row, 1, QTableWidgetItem(level.upper()))
                                self.logs_table.setItem(row, 2, QTableWidgetItem(name))
                                self.logs_table.setItem(row, 3, QTableWidgetItem(message.strip()))
                                
                                # Color code by log level
                                level_upper = level.upper()
                                for col in range(4):
                                    item = self.logs_table.item(row, col)
                                    if item:
                                        if level_upper in ('ERROR', 'CRITICAL'):
                                            item.setBackground(QColor(254, 226, 226))  # Light red
                                        elif level_upper == 'WARNING':
                                            item.setBackground(QColor(254, 243, 199))  # Light yellow
                                        elif level_upper == 'INFO':
                                            item.setBackground(QColor(219, 234, 254))  # Light blue
                                        elif level_upper == 'DEBUG':
                                            item.setBackground(QColor(229, 231, 235))  # Light gray
                                
                                # Auto-scroll to bottom
                                self.logs_table.scrollToBottom()
                            
                        except Exception as e:
                            print(f"Error parsing log line '{line}': {e}")
                            
            except Exception as e:
                error_msg = f"Error reading log file: {e}"
                print(error_msg)
                self.status_bar.showMessage(error_msg, 5000)
                
        except Exception as e:
            self.status_bar.showMessage(f"Error reading log file: {e}", 5000)
    
    def setup_log_tab(self):
        """Set up the log display tab."""
        log_tab = QWidget()
        layout = QVBoxLayout()
        
        # Log level filter
        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setCurrentText("INFO")
        self.log_level_combo.currentTextChanged.connect(self.update_logs)
        log_level_layout.addWidget(self.log_level_combo)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.force_refresh_logs)
        log_level_layout.addWidget(refresh_btn)
        
        # Clear logs button
        clear_btn = QPushButton("Clear Display")
        clear_btn.clicked.connect(self.clear_log_display)
        log_level_layout.addWidget(clear_btn)
        
        log_level_layout.addStretch()
        layout.addLayout(log_level_layout)
        
        # Log display
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setLineWrapMode(QTextEdit.NoWrap)
        self.log_text.setStyleSheet(
            "QTextEdit { "
            "background-color: #1e1e1e; "
            "color: #d4d4d4; "
            "border: 1px solid #3c3c3c; "
            "border-radius: 4px; "
            "padding: 5px; "
            "font-family: 'Consolas', 'Monaco', monospace; "
            "}"
        )
        layout.addWidget(self.log_text)
        
        # Auto-scroll toggle
        self.auto_scroll = QCheckBox("Auto-scroll")
        self.auto_scroll.setChecked(True)
        layout.addWidget(self.auto_scroll)
            
        # Check if log file exists
        if not self.log_file.exists():
            print(f"Log file not found: {self.log_file}")
            self.log_display.setPlainText(f"Log file not found: {self.log_file}")
            return
            
        try:
            # Get current size of log file
            current_size = self.log_file.stat().st_size
            
            # If file hasn't changed, nothing to do
            if hasattr(self, 'last_log_size') and current_size == self.last_log_size:
                return
                
        except Exception as e:
            print(f"Error checking log file: {e}")
            self.log_display.setPlainText(f"Error checking log file: {e}")
            return
        
        # Read new content
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='replace') as f:
                # If we don't have a position or file was reset, start from beginning
                if not hasattr(self, 'log_position') or self.log_position > current_size:
                    self.log_position = 0
                
                # Go to our last position and read new content
                f.seek(self.log_position)
                new_entries = f.readlines()
                self.log_position = f.tell()
                self.last_log_size = current_size
                
                # Process and display new log entries
                for entry in new_entries:
                    entry = entry.strip()
                    if not entry:
                        continue
                        
                    # Determine text color based on log level
                    entry_upper = entry.upper()
                    if 'ERROR' in entry_upper or 'CRITICAL' in entry_upper:
                        color = '#ff8e8e'  # Light red for errors
                    elif 'WARN' in entry_upper:
                        color = '#feca57'  # Yellow for warnings
                    elif 'INFO' in entry_upper:
                        color = '#48dbfb'  # Blue for info
                    elif 'DEBUG' in entry_upper:
                        color = '#a4b0be'  # Gray for debug
                    else:
                        color = '#d4d4d4'  # Default color
                    
                    # Set text color and append the log entry
                    self.log_text.setTextColor(QColor(color))
                    self.log_text.append(entry)
            
            # Auto-scroll to bottom if enabled
            if self.auto_scroll.isChecked():
                scroll_bar = self.log_text.verticalScrollBar()
                scroll_bar.setValue(scroll_bar.maximum())
            
            # Force UI update
            self.log_text.repaint()
            QApplication.processEvents()
            
        except Exception as e:
            self.status_bar.showMessage(f"Error processing log entries: {e}", 5000)
    
    def clear_logs(self):
        """Clear the log display and reset log position."""
        self.log_text.clear()
        self.log_position = 0
        if self.log_file.exists():
            self.log_position = self.log_file.stat().st_size
    
    def save_config(self):
        """Save the current configuration."""
        try:
            # Update config with UI values
            self.config.update({
                'siem_server': self.server_host.text(),
                'siem_port': int(self.server_port.text()),
                'use_tls': self.use_tls.currentText() == 'Enabled',
                'heartbeat_interval': int(self.collect_interval.text())
            })
            
            # Save to file using the agent's save method if available
            if hasattr(self.agent, 'save_config'):
                self.agent.save_config()
            else:
                # Fallback to direct file save
                with open(self.config_file, 'w') as f:
                    json.dump(self.config, f, indent=4)
                    
            # Show success message
            self.status_bar.showMessage("Configuration saved successfully", 3000)
            
            # Log the configuration change
            log_message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - "
                f"INFO - Configuration updated: {self.config}\n"
            )
            with open(self.log_file, 'a') as f:
                f.write(log_message)
                
            return True
            
        except Exception as e:
            error_msg = f"Error saving configuration: {e}"
            self.status_bar.showMessage(error_msg, 5000)
            
            # Log the error
            log_message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - "
                f"ERROR - {error_msg}\n"
            )
            with open(self.log_file, 'a') as f:
                f.write(log_message)
                
            return False

def show_error_dialog(message, details=None):
    """Show an error dialog with optional details."""
    from PyQt5.QtWidgets import QMessageBox
    import traceback
    
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("Application Error")
    msg.setInformativeText(str(message))
    
    if details is None and hasattr(sys, 'last_traceback'):
        details = ''.join(traceback.format_exception(*sys.exc_info()))
    
    if details:
        msg.setDetailedText(details)
    
    msg.setWindowTitle("Error")
    msg.exec_()

def main():
    print("Starting SIEM Agent Dashboard...")
    print(f"Python version: {sys.version}")
    try:
        from PyQt5.QtCore import QT_VERSION_STR
        print(f"PyQt5 version: {QT_VERSION_STR}")
    except Exception as e:
        print(f"Error getting PyQt5 version: {e}")
    
    app = QApplication(sys.argv)
    print("QApplication created")
    
    # Set application style
    app.setStyle('Fusion')
    print("Application style set to Fusion")
    
    config_path = Path('agent_config.json')
    
    try:
        # Ensure the config file exists
        if not config_path.exists():
            with open(config_path, 'w') as f:
                config = {
                    'log_level': 'DEBUG',
                    'log_file': 'siem_agent.log',
                    'api_endpoint': 'http://localhost:5000/api/v1/events',
                    'collectors': {
                        'system_metrics': True,
                        'network_activity': True,
                        'file_integrity': True
                    },
                    'heartbeat_interval': 60
                }
                json.dump(config, f, indent=4)
        
        # Initialize agent and load config
        from .agent import SIEMAgent
        agent = SIEMAgent(str(config_path))
        
        # Start the agent and log some test messages
        agent.start()
        agent.log('INFO', 'SIEM Agent Dashboard started')
        agent.log('DEBUG', 'Debug information: Initializing components...')
        agent.log('INFO', 'Connected to SIEM server at ' + 
                 agent.config.get('api_endpoint', 'unknown'))
        
        # Create and show the main window
        window = SIEMAgentDashboard(agent, agent.config)
        window.show()
        
        # Log additional test messages after a short delay
        def log_test_messages():
            import random
            test_messages = [
                ('INFO', 'System scan completed successfully'),
                ('WARNING', 'High CPU usage detected (92%)'),
                ('ERROR', 'Failed to connect to SIEM server'),
                ('DEBUG', 'Processing batch of 42 events'),
                ('CRITICAL', 'Security alert: Multiple failed login attempts')
            ]
            for level, msg in test_messages:
                agent.log(level, msg)
                QApplication.processEvents()  # Update UI
                time.sleep(0.5)
        
        # Schedule test messages after the UI is shown
        QTimer.singleShot(1000, log_test_messages)
        
        return app.exec_()
        
    except ImportError as e:
        error_msg = "Failed to import required modules. Please install dependencies with: pip install -r requirements.txt"
        print(f"{error_msg}\nError details: {e}")
        show_error_dialog(error_msg, str(e))
        return 1
    except Exception as e:
        error_msg = f"Failed to start application: {str(e)}"
        print(error_msg)
        show_error_dialog("Failed to start the application.", str(e))
        return 1

if __name__ == "__main__":
    main()
