"""
SIEM Agent Dashboard using PyQt5
"""
import sys
import json
import time
import psutil
import socket
import platform
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
        
        # Auto-refresh configuration
        self.auto_refresh_enabled = True
        self.auto_refresh_interval = 1000  # 1 second default
        self.last_refresh_time = datetime.now()
        
        # Log update timer
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.auto_refresh_logs)
        self.log_timer.start(self.auto_refresh_interval)  # Update logs every second
        
        # Initial update
        self.update_status()
        self.update_logs()
    
    def init_ui(self):
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Enhanced Header with icon and modern styling
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        # Header icon (using text symbol as fallback)
        header_icon = QLabel("🛡️")
        header_layout.addWidget(header_icon)
        
        # Header title
        header = QLabel("SIEM Agent Dashboard")
        header_font = QFont("Arial", 16, QFont.Bold)
        header.setFont(header_font)
        header_layout.addWidget(header)
        
        header_layout.addStretch()
        
        # Status indicator
        self.status_indicator = QLabel("●")
        header_layout.addWidget(self.status_indicator)
        
        self.status_text = QLabel("Online")
        header_layout.addWidget(self.status_text)
        
        layout.addWidget(header_widget)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create tabs
        self.tabs = QTabWidget()
        
        # Status Tab
        self.status_tab = QWidget()
        self.init_status_tab()
        self.tabs.addTab(self.status_tab, "📊 Status")
        
        # Logs Tab
        self.logs_tab = QWidget()
        self.init_logs_tab()
        self.tabs.addTab(self.logs_tab, "📋 Logs")
        
        # Configuration Tab
        self.config_tab = QWidget()
        self.init_config_tab()
        self.tabs.addTab(self.config_tab, "⚙️ Configuration")
        
        layout.addWidget(self.tabs)
        
        # Initialize log file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.write_text("SIEM Agent Log File\n" + "="*50 + "\n")
        else:
            # Set initial log position to the end of file
            self.log_position = self.log_file.stat().st_size
        
    
    def init_status_tab(self):
        layout = QVBoxLayout(self.status_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(20)
        
        # System Status Group
        sys_status_group = QWidget()
        sys_layout = QHBoxLayout(sys_status_group)
        sys_layout.setContentsMargins(0, 0, 0, 0)
        sys_layout.setSpacing(15)
        
        # CPU Usage with enhanced widget
        cpu_widget = self.create_metric_widget("CPU Usage", "0%", "#3b82f6")
        self.cpu_label = cpu_widget.findChild(QLabel, "value")
        self.cpu_progress = cpu_widget.progress_bar
        
        # Memory Usage with enhanced widget
        mem_widget = self.create_metric_widget("Memory Usage", "0%", "#10b981")
        self.mem_label = mem_widget.findChild(QLabel, "value")
        self.mem_progress = mem_widget.progress_bar
        
        # Disk Usage with enhanced widget
        disk_widget = self.create_metric_widget("Disk Usage", "0%", "#f59e0b")
        self.disk_label = disk_widget.findChild(QLabel, "value")
        self.disk_progress = disk_widget.progress_bar
        
        # Logs Sent with enhanced widget
        logs_widget = self.create_metric_widget("Events Sent", "0", "#8b5cf6")
        self.logs_label = logs_widget.findChild(QLabel, "value")
        self.logs_progress = logs_widget.progress_bar
        
        sys_layout.addWidget(cpu_widget)
        sys_layout.addWidget(mem_widget)
        sys_layout.addWidget(disk_widget)
        sys_layout.addWidget(logs_widget)
        
        # Agent Status with enhanced eye-friendly styling
        agent_group = QWidget()
        agent_layout = QVBoxLayout(agent_group)
        agent_layout.setContentsMargins(20, 20, 20, 20)
        agent_layout.setSpacing(15)
        
        # Agent Status Header
        agent_header = QLabel("🤖 Agent Control")
        agent_layout.addWidget(agent_header)
        
        # Agent Status with icon
        status_layout = QHBoxLayout()
        self.agent_status_icon = QLabel("●")
        status_layout.addWidget(self.agent_status_icon)
        
        self.agent_status = QLabel("Status: Not Connected")
        status_layout.addWidget(self.agent_status)
        status_layout.addStretch()
        agent_layout.addLayout(status_layout)
        
        # Last Sync
        self.last_sync = QLabel("Last Sync: Never")
        agent_layout.addWidget(self.last_sync)
        
        # Start/Stop Buttons with enhanced styling
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.start_btn = QPushButton("▶️ Start Agent")
        
        self.stop_btn = QPushButton("⏹️ Stop Agent")
        self.stop_btn.setEnabled(False)
        
        self.start_btn.clicked.connect(self.start_agent)
        self.stop_btn.clicked.connect(self.stop_agent)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        agent_layout.addLayout(btn_layout)
        
        # Update button states based on agent status
        self.update_button_states()
        
        # Endpoint Information Group with enhanced eye-friendly styling
        endpoint_group = QWidget()
        endpoint_layout = QVBoxLayout(endpoint_group)
        endpoint_layout.setContentsMargins(20, 20, 20, 20)
        endpoint_layout.setSpacing(12)
        
        # Endpoint Title with icon
        endpoint_header = QLabel("🖥️ Endpoint Information")
        endpoint_layout.addWidget(endpoint_header)
        
        # Hostname with icon
        hostname_layout = QHBoxLayout()
        hostname_icon = QLabel("🏷️")
        hostname_layout.addWidget(hostname_icon)
        self.hostname_label = QLabel("Hostname: Loading...")
        hostname_layout.addWidget(self.hostname_label)
        hostname_layout.addStretch()
        endpoint_layout.addLayout(hostname_layout)
        
        # OS Information with icon
        os_layout = QHBoxLayout()
        os_icon = QLabel("💻")
        os_layout.addWidget(os_icon)
        self.os_info_label = QLabel("OS: Loading...")
        os_layout.addWidget(self.os_info_label)
        os_layout.addStretch()
        endpoint_layout.addLayout(os_layout)
        
        # Public IP with icon
        public_ip_layout = QHBoxLayout()
        public_ip_icon = QLabel("🌐")
        public_ip_layout.addWidget(public_ip_icon)
        self.public_ip_label = QLabel("Public IP: Loading...")
        public_ip_layout.addWidget(self.public_ip_label)
        public_ip_layout.addStretch()
        endpoint_layout.addLayout(public_ip_layout)
        
        # Local IPs with icon
        local_ips_layout = QHBoxLayout()
        local_ips_icon = QLabel("🔗")
        local_ips_layout.addWidget(local_ips_icon)
        self.local_ips_label = QLabel("Local IPs: Loading...")
        self.local_ips_label.setWordWrap(True)
        local_ips_layout.addWidget(self.local_ips_label)
        local_ips_layout.addStretch()
        endpoint_layout.addLayout(local_ips_layout)
        
        # Add to main layout
        layout.addWidget(sys_status_group)
        layout.addWidget(agent_group)
        layout.addWidget(endpoint_group)
        layout.addStretch()
    
    def init_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Enhanced Control Panel with eye-friendly colors
        control_panel = QWidget()
        control_layout = QVBoxLayout(control_panel)
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(12)
        
        # Control Panel Header
        control_header = QLabel("🔍 Log Controls")
        control_layout.addWidget(control_header)
        
        # Auto-refresh and Filter Controls
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(15)
        
        # Auto-refresh controls with icon
        auto_refresh_layout = QHBoxLayout()
        auto_refresh_layout.setSpacing(8)
        auto_refresh_icon = QLabel("🔄")
        auto_refresh_layout.addWidget(auto_refresh_icon)
        
        self.auto_refresh_checkbox = QCheckBox("Auto-refresh")
        self.auto_refresh_checkbox.setChecked(True)
        self.auto_refresh_checkbox.stateChanged.connect(self.toggle_auto_refresh)
        auto_refresh_layout.addWidget(self.auto_refresh_checkbox)
        filter_layout.addLayout(auto_refresh_layout)
        
        # Refresh interval with icon
        interval_layout = QHBoxLayout()
        interval_layout.setSpacing(8)
        interval_icon = QLabel("⏱️")
        interval_layout.addWidget(interval_icon)
        
        self.refresh_interval = QComboBox()
        self.refresh_interval.addItems(["1 sec", "2 sec", "5 sec", "10 sec", "30 sec", "1 min"])
        self.refresh_interval.setCurrentText("1 sec")
        self.refresh_interval.currentTextChanged.connect(self.change_refresh_interval)
        interval_layout.addWidget(self.refresh_interval)
        filter_layout.addLayout(interval_layout)
        
        # Last refresh indicator with icon
        refresh_status_layout = QHBoxLayout()
        refresh_status_layout.setSpacing(8)
        refresh_status_icon = QLabel("🕐")
        refresh_status_layout.addWidget(refresh_status_icon)
        
        self.last_refresh_label = QLabel("Last: Never")
        refresh_status_layout.addWidget(self.last_refresh_label)
        filter_layout.addLayout(refresh_status_layout)
        
        filter_layout.addWidget(QLabel("|"))  # Separator
        
        # Log Level Filter with icon
        level_layout = QHBoxLayout()
        level_layout.setSpacing(8)
        level_icon = QLabel("📊")
        level_layout.addWidget(level_icon)
        level_layout.addWidget(QLabel("Level:"))
        
        self.log_level = QComboBox()
        self.log_level.addItems(["🔍 All", "🔧 DEBUG", "ℹ️ INFO", "⚠️ WARNING", "❌ ERROR", "🚨 CRITICAL"])
        self.log_level.setCurrentText("🔍 All")
        level_layout.addWidget(self.log_level)
        filter_layout.addLayout(level_layout)
        
        # Search box with icon
        search_layout = QHBoxLayout()
        search_layout.setSpacing(8)
        search_icon = QLabel("🔎")
        search_layout.addWidget(search_icon)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search logs...")
        search_layout.addWidget(self.search_box)
        filter_layout.addLayout(search_layout)
        
        # Refresh button with icon
        refresh_btn = QPushButton("🔄 Refresh")
        filter_layout.addWidget(refresh_btn)
        
        filter_layout.addStretch()
        
        # Connect event handlers
        self.log_level.currentTextChanged.connect(self.filter_logs)
        self.search_box.textChanged.connect(self.filter_logs)
        refresh_btn.clicked.connect(self.refresh_logs)
        
        control_layout.addLayout(filter_layout)
        layout.addWidget(control_panel)
        
        # Enhanced Logs Table
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(5)
        self.logs_table.setHorizontalHeaderLabels(["🕐 Timestamp", "📊 Level", "🖥️ Source", "📝 Message", "🔍 Details"])
        
        
        # Configure table behavior
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.logs_table.verticalHeader().setVisible(False)
        self.logs_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.setShowGrid(True)
        
        # Set initial column widths
        self.logs_table.setColumnWidth(0, 180)  # Timestamp
        self.logs_table.setColumnWidth(1, 100)  # Level
        self.logs_table.setColumnWidth(2, 120)  # Source
        self.logs_table.setColumnWidth(3, 300)  # Message
        self.logs_table.setColumnWidth(4, 200)  # Details
        
        # Enable word wrap for message column
        self.logs_table.wordWrap()
        
        layout.addWidget(self.logs_table)
    
    def init_config_tab(self):
        layout = QVBoxLayout(self.config_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(20)
        
        # Server Configuration Section with eye-friendly colors
        server_group = QWidget()
        server_layout = QVBoxLayout(server_group)
        server_layout.setContentsMargins(0, 0, 0, 0)
        server_layout.setSpacing(15)
        
        # Server Section Header
        server_header = QLabel("🌐 Server Configuration")
        server_layout.addWidget(server_header)
        
        # Server Host with icon
        host_layout = QHBoxLayout()
        host_layout.setSpacing(10)
        host_icon = QLabel("🏠")
        host_layout.addWidget(host_icon)
        host_layout.addWidget(QLabel("Host:"))
        self.server_host = QLineEdit("localhost")
        self.server_host.setPlaceholderText("Enter server hostname or IP")
        host_layout.addWidget(self.server_host)
        server_layout.addLayout(host_layout)
        
        # Server Port with icon
        port_layout = QHBoxLayout()
        port_layout.setSpacing(10)
        port_icon = QLabel("🔌")
        port_layout.addWidget(port_icon)
        port_layout.addWidget(QLabel("Port:"))
        self.server_port = QLineEdit("10514")
        self.server_port.setPlaceholderText("Enter server port")
        port_layout.addWidget(self.server_port)
        server_layout.addLayout(port_layout)
        
        # TLS Configuration with icon
        tls_layout = QHBoxLayout()
        tls_layout.setSpacing(10)
        tls_icon = QLabel("🔒")
        tls_layout.addWidget(tls_icon)
        tls_layout.addWidget(QLabel("TLS:"))
        self.use_tls = QComboBox()
        self.use_tls.addItems(["🔓 Disabled", "🔒 Enabled"])
        self.use_tls.setCurrentText("🔓 Disabled")
        tls_layout.addWidget(self.use_tls)
        tls_layout.addStretch()
        server_layout.addLayout(tls_layout)
        
        layout.addWidget(server_group)
        
        # Agent Configuration Section with eye-friendly colors
        agent_group = QWidget()
        agent_layout = QVBoxLayout(agent_group)
        agent_layout.setContentsMargins(0, 0, 0, 0)
        agent_layout.setSpacing(15)
        
        # Agent Section Header
        agent_header = QLabel("🤖 Agent Configuration")
        agent_layout.addWidget(agent_header)
        
        # Agent ID with icon
        agent_id_layout = QHBoxLayout()
        agent_id_layout.setSpacing(10)
        agent_id_icon = QLabel("🆔")
        agent_id_layout.addWidget(agent_id_icon)
        agent_id_layout.addWidget(QLabel("Agent ID:"))
        self.agent_id = QLineEdit()
        self.agent_id.setReadOnly(True)
        self.agent_id.setPlaceholderText("Auto-generated agent ID")
        agent_id_layout.addWidget(self.agent_id)
        agent_layout.addLayout(agent_id_layout)
        
        # Collection Interval with icon
        interval_layout = QHBoxLayout()
        interval_layout.setSpacing(10)
        interval_icon = QLabel("⏱️")
        interval_layout.addWidget(interval_icon)
        interval_layout.addWidget(QLabel("Interval:"))
        self.collect_interval = QLineEdit("60")
        self.collect_interval.setPlaceholderText("Collection interval in seconds")
        interval_layout.addWidget(self.collect_interval)
        interval_layout.addWidget(QLabel("seconds"))
        interval_layout.addStretch()
        agent_layout.addLayout(interval_layout)
        
        layout.addWidget(agent_group)
        
        # Additional Settings Section with eye-friendly colors
        settings_group = QWidget()
        settings_layout = QVBoxLayout(settings_group)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(15)
        
        # Settings Section Header
        settings_header = QLabel("⚙️ Additional Settings")
        settings_layout.addWidget(settings_header)
        
        # Log Level with icon
        log_level_layout = QHBoxLayout()
        log_level_layout.setSpacing(10)
        log_level_icon = QLabel("📊")
        log_level_layout.addWidget(log_level_icon)
        log_level_layout.addWidget(QLabel("Log Level:"))
        self.log_level_config = QComboBox()
        self.log_level_config.addItems(["🔧 DEBUG", "ℹ️ INFO", "⚠️ WARNING", "❌ ERROR"])
        self.log_level_config.setCurrentText("ℹ️ INFO")
        log_level_layout.addWidget(self.log_level_config)
        log_level_layout.addStretch()
        settings_layout.addLayout(log_level_layout)
        
        # Max Log Size with icon
        log_size_layout = QHBoxLayout()
        log_size_layout.setSpacing(10)
        log_size_icon = QLabel("📁")
        log_size_layout.addWidget(log_size_icon)
        log_size_layout.addWidget(QLabel("Max Log Size:"))
        self.max_log_size = QLineEdit("100")
        self.max_log_size.setPlaceholderText("Maximum log size in MB")
        log_size_layout.addWidget(self.max_log_size)
        log_size_layout.addWidget(QLabel("MB"))
        log_size_layout.addStretch()
        settings_layout.addLayout(log_size_layout)
        
        layout.addWidget(settings_group)
        
        # Action Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        # Save Button with enhanced styling
        save_btn = QPushButton("💾 Save Configuration")
        save_btn.clicked.connect(self.save_config)
        button_layout.addWidget(save_btn)
        
        # Reset Button
        reset_btn = QPushButton("🔄 Reset to Defaults")
        reset_btn.clicked.connect(self.reset_config)
        button_layout.addWidget(reset_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        layout.addStretch()
        
        # Initialize configuration
        self.load_config()
    
    def create_metric_widget(self, title, value, color):
        from PyQt5.QtWidgets import QProgressBar
        
        widget = QWidget()
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Title
        title_label = QLabel(title)
        title_label.setObjectName("title")
        layout.addWidget(title_label)
        
        # Value
        value_label = QLabel(value)
        value_label.setObjectName("value")
        layout.addWidget(value_label)
        
        # Progress bar
        progress_bar = QProgressBar()
        progress_bar.setTextVisible(False)
        progress_bar.setRange(0, 100)
        
        # Try to parse percentage from value
        try:
            if '%' in value:
                percent_value = float(value.replace('%', '').strip())
                progress_bar.setValue(int(percent_value))
            else:
                # For non-percentage values, create a visual indicator
                progress_bar.setValue(0)
        except Exception:
            progress_bar.setValue(0)
        
        layout.addWidget(progress_bar)
        
        # Store progress bar reference for updates
        widget.progress_bar = progress_bar
        
        return widget
    
    def get_endpoint_info(self):
        """Get endpoint information including hostname and IP addresses."""
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Get local IP addresses
            local_ips = []
            try:
                # Get all network interfaces
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                            local_ips.append(f"{interface}: {addr.address}")
            except Exception:
                local_ips.append("Unable to get network interfaces")
            
            # Get public IP (if available)
            public_ip = "Not available"
            try:
                # This is a simple method to get public IP
                # Note: This might not work in all environments
                public_ip = socket.gethostbyname(socket.gethostname())
                if public_ip.startswith('127.') or public_ip.startswith('169.254.'):
                    public_ip = "Not available"
            except Exception:
                pass
            
            return {
                'hostname': hostname,
                'local_ips': local_ips,
                'public_ip': public_ip,
                'os_info': f"{platform.system()} {platform.release()}"
            }
        except Exception as e:
            return {
                'hostname': 'Unknown',
                'local_ips': ['Unable to get endpoint info'],
                'public_ip': 'Unknown',
                'os_info': 'Unknown'
            }
    
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
        """Update the status display with enhanced visual indicators."""
        try:
            # Update system metrics with enhanced color-coded progress bars
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            # Get disk usage for the current drive on Windows
            try:
                import os
                current_drive = os.path.splitdrive(os.getcwd())[0] + '\\'
                disk_percent = psutil.disk_usage(current_drive).percent
            except Exception:
                # Fallback to C: drive if current drive fails
                disk_percent = psutil.disk_usage('C:\\').percent
            
            # Update CPU progress bar and label
            self.cpu_progress.setValue(int(cpu_percent))
            if hasattr(self, 'cpu_label'):
                self.cpu_label.setText(f"{int(cpu_percent)}%")
            
            # Update memory progress bar and label
            self.mem_progress.setValue(int(memory_percent))
            if hasattr(self, 'mem_label'):
                self.mem_label.setText(f"{int(memory_percent)}%")
            
            # Update disk progress bar and label
            self.disk_progress.setValue(int(disk_percent))
            if hasattr(self, 'disk_label'):
                self.disk_label.setText(f"{int(disk_percent)}%")
            
            # Update logs sent counter (simulate with random increment for demo)
            if hasattr(self, 'logs_label'):
                current_logs = int(self.logs_label.text())
                new_logs = current_logs + 1
                self.logs_label.setText(str(new_logs))
                if hasattr(self, 'logs_progress'):
                    # Create a visual indicator for logs (0-100 scale based on activity)
                    activity_level = min(new_logs % 100, 100)
                    self.logs_progress.setValue(activity_level)
            
            # Update agent status with enhanced visual indicators
            self.update_button_states()
            
            # Enhanced agent status with multiple states
            if hasattr(self, 'agent') and hasattr(self.agent, 'is_running'):
                if self.agent.is_running:
                    # Check if agent is healthy (responsive)
                    try:
                        # Simulate health check - in real implementation, this would ping the agent
                        import random
                        health_check = random.choice([True, True, True, False])  # 75% success rate
                        
                        if health_check:
                            # Healthy running state
                            self.agent_status.setText("Status: Healthy")
                            self.agent_status_icon.setText("✓")
                            # Update header status indicator
                            if hasattr(self, 'status_indicator'):
                                self.status_indicator.setText("●")
                            if hasattr(self, 'status_text'):
                                self.status_text.setText("Online")
                        else:
                            # Running but degraded state
                            self.agent_status.setText("Status: Degraded")
                            self.agent_status_icon.setText("⚠")
                            # Update header status indicator
                            if hasattr(self, 'status_indicator'):
                                self.status_indicator.setText("●")
                            if hasattr(self, 'status_text'):
                                self.status_text.setText("Degraded")
                    except Exception:
                        # Fallback to basic running state
                        self.agent_status.setText("Status: Running")
                        self.agent_status_icon.setText("●")
                        # Update header status indicator
                        if hasattr(self, 'status_indicator'):
                            self.status_indicator.setText("●")
                        if hasattr(self, 'status_text'):
                            self.status_text.setText("Online")
                else:
                    # Stopped state
                    self.agent_status.setText("Status: Stopped")
                    self.agent_status_icon.setText("✗")
                    # Update header status indicator
                    if hasattr(self, 'status_indicator'):
                        self.status_indicator.setText("●")
                    if hasattr(self, 'status_text'):
                        self.status_text.setText("Offline")
            
            # Update last sync time
            if hasattr(self, 'agent') and hasattr(self.agent, 'last_sync'):
                sync_time = self.agent.last_sync
                if sync_time:
                    self.last_sync.setText(f"Last Sync: {sync_time}")
                else:
                    self.last_sync.setText("Last Sync: Never")
            
            # Update endpoint information
            endpoint_info = self.get_endpoint_info()
            self.hostname_label.setText(f"{endpoint_info['hostname']}")
            self.os_info_label.setText(f"{endpoint_info['os_info']}")
            self.public_ip_label.setText(f"{endpoint_info['public_ip']}")
            
            # Format local IPs for display
            if endpoint_info['local_ips']:
                if len(endpoint_info['local_ips']) == 1:
                    self.local_ips_label.setText(endpoint_info['local_ips'][0])
                else:
                    # Show first IP with count indicator
                    self.local_ips_label.setText(f"{endpoint_info['local_ips'][0]} (+{len(endpoint_info['local_ips'])-1} more)")
            else:
                self.local_ips_label.setText("No network interfaces found")
            
            # Update status bar with enhanced message
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.status_bar.showMessage(f"🔄 Last updated: {current_time} | 📊 System: CPU {cpu_percent:.1f}% | Memory {memory_percent:.1f}% | Disk {disk_percent:.1f}%")
            
        except Exception as e:
            error_msg = f"Error updating status: {e}"
            print(error_msg)
            self.status_bar.showMessage(error_msg, 5000)
    
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
                
            # Get current size of log file
            try:
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
                # If this is the first time and we have logs, load them
                if not hasattr(self, 'logs_loaded') and current_size > 0:
                    self.log_position = 0  # Read from beginning
                    print("[DEBUG] Loading existing logs...")
                else:
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
                    self.logs_loaded = True  # Mark that logs have been loaded
                    
                    if not new_logs:
                        return  # No new logs to process
                    
                    # Parse and add new log entries
                    print(f"[DEBUG] Processing {len(new_logs)} new log lines")
                    for line in new_logs:
                        try:
                            line = line.strip()
                            if not line:  # Skip empty lines
                                continue
                                
                            print(f"[DEBUG] Processing log line: {line[:100]}...")
                            
                            # Try different log formats
                            # Format 1: timestamp - level - message (SIEM format)
                            parts = line.split(' - ', 2)
                            if len(parts) >= 3:
                                timestamp = parts[0]
                                level = parts[1]
                                message = parts[2]
                                name = 'siem_agent'
                            elif len(parts) == 2:
                                # Format 2: timestamp - message
                                timestamp = parts[0]
                                level = 'INFO'
                                message = parts[1]
                                name = 'unknown'
                            else:
                                # Format 3: Simple message
                                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                level = 'INFO'
                                message = line
                                name = 'unknown'
                                
                            print(f"[DEBUG] Parsed: timestamp={timestamp}, name={name}, level={level}, message={message[:50]}...")
                            
                            # Add to logs table
                            row = self.logs_table.rowCount()
                            self.logs_table.insertRow(row)
                            
                            # Set items
                            self.logs_table.setItem(row, 0, QTableWidgetItem(timestamp))
                            self.logs_table.setItem(row, 1, QTableWidgetItem(level.upper()))
                            self.logs_table.setItem(row, 2, QTableWidgetItem(name))
                            self.logs_table.setItem(row, 3, QTableWidgetItem(message.strip()))
                            self.logs_table.setItem(row, 4, QTableWidgetItem(""))  # Empty details column
                            
                            # Set text alignment for better readability
                            for col in range(5):  # Include all 5 columns
                                item = self.logs_table.item(row, col)
                                if item:
                                    item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                            
                            # Auto-scroll to bottom
                            self.logs_table.scrollToBottom()
                        
                        except Exception as e:
                            print(f"Error parsing log line '{line}': {e}")
                    
                    # Apply current filters after adding new logs
                    self.filter_logs()
                    
            except Exception as e:
                error_msg = f"Error reading log file: {e}"
                print(error_msg)
                self.status_bar.showMessage(error_msg, 5000)
        except Exception as e:
            error_msg = f"Error updating logs: {e}"
            print(error_msg)
            self.status_bar.showMessage(error_msg, 5000)
    
    def filter_logs(self):
        """Filter logs based on selected log level and search text with enhanced color coding."""
        if not hasattr(self, 'logs_table'):
            return
            
        try:
            selected_level = self.log_level.currentText()
            search_text = self.search_box.text().lower()
            
            # Map icon-based levels to actual log levels
            level_mapping = {
                "🔍 All": "All",
                "🔧 DEBUG": "DEBUG",
                "ℹ️ INFO": "INFO",
                "⚠️ WARNING": "WARNING",
                "❌ ERROR": "ERROR",
                "🚨 CRITICAL": "CRITICAL"
            }
            
            actual_level = level_mapping.get(selected_level, "All")
            
            # Hide rows that don't match the filter criteria
            for row in range(self.logs_table.rowCount()):
                level_item = self.logs_table.item(row, 1)  # Level column
                message_item = self.logs_table.item(row, 3)  # Message column
                
                show_row = True
                
                # Check log level filter
                if actual_level != "All":
                    if level_item and actual_level not in level_item.text().upper():
                        show_row = False
                
                # Check search text filter
                if search_text and show_row:
                    message_matches = message_item and search_text in message_item.text().lower()
                    timestamp_item = self.logs_table.item(row, 0)  # Timestamp column
                    timestamp_matches = timestamp_item and search_text in timestamp_item.text().lower()
                    source_item = self.logs_table.item(row, 2)  # Source column
                    source_matches = source_item and search_text in source_item.text().lower()
                    
                    if not (message_matches or timestamp_matches or source_matches):
                        show_row = False
                
                # Show or hide the row
                self.logs_table.setRowHidden(row, not show_row)
            
            # Update status bar with enhanced filter info
            visible_count = sum(1 for row in range(self.logs_table.rowCount()) 
                              if not self.logs_table.isRowHidden(row))
            total_count = self.logs_table.rowCount()
            
            if actual_level == "All" and not search_text:
                self.status_bar.showMessage(f"📋 Showing {visible_count} logs")
            else:
                filters = []
                if actual_level != "All":
                    filters.append(f"level: {selected_level}")
                if search_text:
                    filters.append(f"search: '{search_text}'")
                
                filter_text = " and ".join(filters)
                self.status_bar.showMessage(f"🔍 Showing {visible_count} of {total_count} logs ({filter_text})")
                
        except Exception as e:
            error_msg = f"Error filtering logs: {e}"
            print(error_msg)
            self.status_bar.showMessage(error_msg, 5000)
    
    def refresh_logs(self):
        """Refresh the logs display by clearing and reloading all logs."""
        if not hasattr(self, 'logs_table') or not hasattr(self, 'log_file'):
            return
            
        try:
            # Clear the table
            self.logs_table.setRowCount(0)
            
            # Reset log position to read from beginning
            self.log_position = 0
            
            # Clear the logs_loaded flag to force reload
            if hasattr(self, 'logs_loaded'):
                delattr(self, 'logs_loaded')
            
            # Update status bar
            self.status_bar.showMessage("Refreshing logs...", 2000)
            
            # Force update logs
            self.update_logs()
            
            # Apply current filters
            self.filter_logs()
            
        except Exception as e:
            print(f"[DEBUG] Error in refresh_logs: {e}")
            self.status_bar.showMessage(f"Error refreshing logs: {e}", 5000)
    
    def auto_refresh_logs(self):
        """Automatically refresh logs based on the configured interval."""
        if not self.auto_refresh_enabled:
            return
            
        try:
            # Update the logs
            self.update_logs()
            
            # Update the last refresh time
            self.last_refresh_time = datetime.now()
            
            # Update the last refresh label
            time_str = self.last_refresh_time.strftime('%H:%M:%S')
            self.last_refresh_label.setText(f"Last: {time_str}")
            
        except Exception as e:
            print(f"[DEBUG] Error in auto_refresh_logs: {e}")
            # Don't show error in status bar for auto-refresh to avoid spam
    
    def toggle_auto_refresh(self, state):
        """Toggle auto-refresh on/off based on checkbox state."""
        self.auto_refresh_enabled = (state == Qt.Checked)
        
        if self.auto_refresh_enabled:
            # Start the timer
            self.log_timer.start(self.auto_refresh_interval)
            self.status_bar.showMessage("Auto-refresh enabled", 2000)
        else:
            # Stop the timer
            self.log_timer.stop()
            self.status_bar.showMessage("Auto-refresh disabled", 2000)
    
    def change_refresh_interval(self, text):
        """Change the auto-refresh interval based on user selection."""
        # Convert text to milliseconds
        interval_map = {
            "1 sec": 1000,
            "2 sec": 2000,
            "5 sec": 5000,
            "10 sec": 10000,
            "30 sec": 30000,
            "1 min": 60000
        }
        
        self.auto_refresh_interval = interval_map.get(text, 1000)
        
        # If auto-refresh is enabled, restart the timer with the new interval
        if self.auto_refresh_enabled:
            self.log_timer.stop()
            self.log_timer.start(self.auto_refresh_interval)
            
        self.status_bar.showMessage(f"Refresh interval set to {text}", 2000)
    
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
            self.log_text.setPlainText(f"Error checking log file: {e}")
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
                        
                    # Append the log entry with default styling
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
    
    def load_config(self):
        """Load configuration from file and populate UI fields."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                # Set default configuration
                self.config = self.get_default_config()
                
            # Populate UI fields with configuration values
            self.server_host.setText(self.config.get('siem_server', 'localhost'))
            self.server_port.setText(str(self.config.get('siem_port', 10514)))
            
            # Handle TLS setting
            tls_enabled = self.config.get('use_tls', False)
            self.use_tls.setCurrentText("🔒 Enabled" if tls_enabled else "🔓 Disabled")
            
            # Generate agent ID if not exists
            agent_id = self.config.get('agent_id', '')
            if not agent_id:
                import uuid
                agent_id = str(uuid.uuid4())[:8]
                self.config['agent_id'] = agent_id
            self.agent_id.setText(agent_id)
            
            # Collection interval
            interval = self.config.get('heartbeat_interval', 60)
            self.collect_interval.setText(str(interval))
            
            # Additional settings
            log_level = self.config.get('log_level', 'INFO')
            level_mapping = {
                'DEBUG': '🔧 DEBUG',
                'INFO': 'ℹ️ INFO',
                'WARNING': '⚠️ WARNING',
                'ERROR': '❌ ERROR'
            }
            self.log_level_config.setCurrentText(level_mapping.get(log_level, 'ℹ️ INFO'))
            
            max_log_size = self.config.get('max_log_size', 100)
            self.max_log_size.setText(str(max_log_size))
            
            self.status_bar.showMessage("Configuration loaded successfully", 3000)
            
        except Exception as e:
            error_msg = f"Error loading configuration: {e}"
            print(error_msg)
            self.status_bar.showMessage(error_msg, 5000)
            
    def get_default_config(self):
        """Get default configuration values."""
        import uuid
        return {
            'siem_server': 'localhost',
            'siem_port': 10514,
            'use_tls': False,
            'agent_id': str(uuid.uuid4())[:8],
            'heartbeat_interval': 60,
            'log_level': 'INFO',
            'max_log_size': 100
        }
    
    def save_config(self):
        """Save the current configuration with validation."""
        try:
            # Validate input fields
            if not self.server_host.text().strip():
                self.status_bar.showMessage("❌ Server host cannot be empty", 5000)
                return False
                
            try:
                port = int(self.server_port.text())
                if not (1 <= port <= 65535):
                    raise ValueError("Port must be between 1 and 65535")
            except ValueError as e:
                self.status_bar.showMessage(f"❌ Invalid port: {e}", 5000)
                return False
                
            try:
                interval = int(self.collect_interval.text())
                if not (1 <= interval <= 3600):
                    raise ValueError("Interval must be between 1 and 3600 seconds")
            except ValueError as e:
                self.status_bar.showMessage(f"❌ Invalid interval: {e}", 5000)
                return False
                
            try:
                log_size = int(self.max_log_size.text())
                if not (1 <= log_size <= 1000):
                    raise ValueError("Log size must be between 1 and 1000 MB")
            except ValueError as e:
                self.status_bar.showMessage(f"❌ Invalid log size: {e}", 5000)
                return False
            
            # Update config with validated UI values
            self.config.update({
                'siem_server': self.server_host.text().strip(),
                'siem_port': port,
                'use_tls': self.use_tls.currentText() == '🔒 Enabled',
                'agent_id': self.agent_id.text(),
                'heartbeat_interval': interval,
                'log_level': self.log_level_config.currentText().split(' ')[1],  # Remove icon
                'max_log_size': log_size
            })
            
            # Save to file using the agent's save method if available
            if hasattr(self.agent, 'save_config'):
                self.agent.save_config()
            else:
                # Fallback to direct file save
                with open(self.config_file, 'w') as f:
                    json.dump(self.config, f, indent=4)
                    
            # Show success message
            self.status_bar.showMessage("✅ Configuration saved successfully", 3000)
            
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
            self.status_bar.showMessage(f"❌ {error_msg}", 5000)
            
            # Log the error
            log_message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - "
                f"ERROR - {error_msg}\n"
            )
            with open(self.log_file, 'a') as f:
                f.write(log_message)
                
            return False
    
    def reset_config(self):
        """Reset configuration to default values."""
        try:
            # Get default configuration
            default_config = self.get_default_config()
            
            # Populate UI fields with default values
            self.server_host.setText(default_config['siem_server'])
            self.server_port.setText(str(default_config['siem_port']))
            self.use_tls.setCurrentText("🔓 Disabled")
            self.agent_id.setText(default_config['agent_id'])
            self.collect_interval.setText(str(default_config['heartbeat_interval']))
            self.log_level_config.setCurrentText('ℹ️ INFO')
            self.max_log_size.setText(str(default_config['max_log_size']))
            
            # Update internal config
            self.config = default_config
            
            self.status_bar.showMessage("🔄 Configuration reset to defaults", 3000)
            
            # Log the reset
            log_message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - "
                f"INFO - Configuration reset to defaults\n"
            )
            with open(self.log_file, 'a') as f:
                f.write(log_message)
                
        except Exception as e:
            error_msg = f"Error resetting configuration: {e}"
            self.status_bar.showMessage(f"❌ {error_msg}", 5000)

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
    
    # Add the current directory to sys.path to allow imports
    current_dir = Path(__file__).parent
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    
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
        from agent import SIEMAgent
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
