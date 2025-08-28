"""
NIPS GUI Module

Provides a graphical interface for the Network Intrusion Prevention System.
Uses only standard libraries and modules from the nips folder.
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Callable
import os
import queue
import threading
import json
import socket
import ipaddress
import time
from dataclasses import dataclass

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
    filename='nips_gui.log',
    filemode='a'
)
logger = logging.getLogger('nips.gui')

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

class NIPSGUI:
    """Main NIPS GUI application."""
    
    def __init__(self, root):
        """Initialize the NIPS GUI."""
        self.root = root
        self.root.title("Network Intrusion Prevention System")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)
        
        # Initialize NIPS components
        self.monitoring = False
        self.alerts = []
        self.alert_queue = queue.Queue()
        self.rules = {}
        self.threats_blocked = 0
        self.packets_analyzed = 0
        self.connections_active = 0
        self.start_time = datetime.now()
        
        # Initialize NIPS modules
        self.forensic_logger = ForensicLogger()
        self.tls_inspector = TLSInspector()
        self.blocking_engine = BlockingEngine()
        self.threat_feed = ThreatFeedManager()
        self.ioc_processor = IOCProcessor()
        self.cluster_manager = ClusterManager()
        
        # Initialize UI state
        self.setup_ui()
        
        # Start background tasks
        self.running = True
        self.process_alerts()
        self.update_stats()
        
        # Load initial data
        self.load_rules()
        self.load_threat_feeds()
    
    def setup_ui(self):
        """Set up the main UI components."""
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook', tabposition='n')
        self.style.configure('TButton', padding=6)
        self.style.configure('Treeview', rowheight=25)
        
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Data storage
        self.events = []
        self.alerts = []
        self.metrics = {}
        self.running = False
        self.monitoring = False
        
        # Setup logging
        self.setup_logging()
        
        # Setup UI tabs
        self.setup_dashboard_tab()
        self.setup_monitoring_tab()
        self.setup_rules_tab()
        self.setup_threat_intel_tab()
        self.setup_logs_tab()
        
        # Menu bar
        self.setup_menus()
    
    def setup_dashboard_tab(self):
        """Set up the dashboard tab with system stats and alerts."""
        self.dashboard_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.dashboard_frame, text="System Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Stats labels
        stats = [
            ("Uptime:", "00:00:00"),
            ("Monitoring:", "Stopped"),
            ("Packets Analyzed:", "0"),
            ("Threats Blocked:", "0"),
            ("Active Connections:", "0"),
            ("Rules Loaded:", "0")
        ]
        
        self.stats_vars = {}
        for i, (label, default) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=label, width=20, anchor=tk.W).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            ttk.Label(frame, textvariable=var, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.stats_vars[label.lower().replace(":", "").replace(" ", "_")] = var
        
        # Alerts frame
        alerts_frame = ttk.LabelFrame(self.dashboard_frame, text="Recent Alerts", padding="10")
        alerts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Alerts treeview
        columns = ("timestamp", "severity", "source", "destination", "protocol", "description")
        self.alerts_tree = ttk.Treeview(
            alerts_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {
            "timestamp": 150,
            "severity": 80,
            "source": 150,
            "destination": 150,
            "protocol": 80,
            "description": 300
        }
        
        for col in columns:
            self.alerts_tree.heading(col, text=col.title())
            self.alerts_tree.column(col, width=col_widths.get(col, 100), minwidth=50)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True)
        
        # Double-click to view alert details
        self.alerts_tree.bind("<Double-1>", self.show_alert_details)
    
    def setup_monitoring_tab(self):
        """Set up the monitoring configuration tab."""
        self.monitor_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.monitor_frame, text="Monitoring")
        
        # Control buttons
        btn_frame = ttk.Frame(self.monitor_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(
            btn_frame, 
            text="Start Monitoring", 
            command=self.toggle_monitoring,
            style="Accent.TButton"
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(btn_frame, text="View Active Connections").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Packet Capture").pack(side=tk.LEFT, padx=5)
        
        # Interface selection
        if_frame = ttk.LabelFrame(self.monitor_frame, text="Network Interfaces", padding="10")
        if_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.if_tree = ttk.Treeview(if_frame, columns=("interface", "ip", "status"), show="headings")
        for col in ("interface", "ip", "status"):
            self.if_tree.heading(col, text=col.title())
            self.if_tree.column(col, width=100)
        
        # Add some sample interfaces
        interfaces = [
            ("eth0", "192.168.1.100", "Up"),
            ("wlan0", "192.168.1.101", "Up"),
            ("docker0", "172.17.0.1", "Down")
        ]
        for iface in interfaces:
            self.if_tree.insert("", tk.END, values=iface)
        
        self.if_tree.pack(fill=tk.X)
        
        # Protocol filters
        proto_frame = ttk.LabelFrame(self.monitor_frame, text="Protocol Filters", padding="10")
        proto_frame.pack(fill=tk.X, pady=(0, 10))
        
        protocols = [
            ("HTTP/HTTPS", True),
            ("DNS", True),
            ("FTP", False),
            ("SSH", True),
            ("SMTP", False),
            ("RDP", True)
        ]
        
        self.protocol_vars = {}
        for i, (proto, default) in enumerate(protocols):
            var = tk.BooleanVar(value=default)
            cb = ttk.Checkbutton(proto_frame, text=proto, variable=var)
            cb.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.protocol_vars[proto] = var
        
        # Advanced options
        adv_frame = ttk.LabelFrame(self.monitor_frame, text="Advanced Options", padding="10")
        adv_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(adv_frame, text="Packet Capture Filter:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.packet_filter = ttk.Entry(adv_frame, width=50)
        self.packet_filter.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        self.packet_filter.insert(0, "not port 22 and not port 3389")
        
        ttk.Label(adv_frame, text="Max Packet Size:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.max_packet = ttk.Spinbox(adv_frame, from_=64, to=65535, width=10)
        self.max_packet.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        self.max_packet.set("1500")
        
        # Save button
        ttk.Button(
            self.monitor_frame, 
            text="Save Configuration", 
            command=self.save_monitor_config
        ).pack(pady=10)
    
    def setup_rules_tab(self):
        """Set up the rules management tab."""
        self.rules_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.rules_frame, text="Rules")
        
        # Toolbar
        toolbar = ttk.Frame(self.rules_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="Add Rule", command=self.add_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Edit Rule", command=self.edit_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Import Rules", command=self.import_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Export Rules", command=self.export_rules).pack(side=tk.LEFT, padx=5)
        
        # Search frame
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.rule_search = ttk.Entry(search_frame, width=30)
        self.rule_search.pack(side=tk.LEFT, padx=(0, 5))
        self.rule_search.bind("<KeyRelease>", self.filter_rules)
        
        # Rules treeview
        columns = ("enabled", "id", "name", "severity", "protocol", "source", "destination", "action")
        self.rules_tree = ttk.Treeview(
            self.rules_frame, 
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "enabled": 60,
            "id": 50,
            "name": 200,
            "severity": 80,
            "protocol": 80,
            "source": 150,
            "destination": 150,
            "action": 100
        }
        
        for col in columns:
            self.rules_tree.heading(col, text=col.title())
            self.rules_tree.column(col, width=col_widths.get(col, 100), minwidth=50, anchor=tk.CENTER)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(self.rules_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        x_scroll = ttk.Scrollbar(self.rules_frame, orient=tk.HORIZONTAL, command=self.rules_tree.xview)
        self.rules_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.rules_tree.pack(fill=tk.BOTH, expand=True)
        
        # Load sample rules
        self.load_sample_rules()
    
    def setup_threat_intel_tab(self):
        """Set up the threat intelligence tab."""
        self.threat_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.threat_frame, text="Threat Intel")
        
        # Toolbar
        toolbar = ttk.Frame(self.threat_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="Update Feeds", command=self.update_threat_feeds).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Add Feed", command=self.add_threat_feed).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="View IOCs", command=self.view_iocs).pack(side=tk.LEFT, padx=5)
        
        # Feeds frame
        feed_frame = ttk.LabelFrame(self.threat_frame, text="Threat Feeds", padding="10")
        feed_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Feeds treeview
        columns = ("name", "url", "type", "last_updated", "ioc_count", "enabled")
        self.feeds_tree = ttk.Treeview(
            feed_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {
            "name": 200,
            "url": 300,
            "type": 100,
            "last_updated": 150,
            "ioc_count": 80,
            "enabled": 60
        }
        
        for col in columns:
            self.feeds_tree.heading(col, text=col.title().replace("_", " "))
            self.feeds_tree.column(col, width=col_widths.get(col, 100), minwidth=50)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(feed_frame, orient=tk.VERTICAL, command=self.feeds_tree.yview)
        x_scroll = ttk.Scrollbar(feed_frame, orient=tk.HORIZONTAL, command=self.feeds_tree.xview)
        self.feeds_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.feeds_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add sample feeds
        self.load_sample_feeds()
    
    def setup_logs_tab(self):
        """Set up the logs tab."""
        self.logs_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.logs_frame, text="Logs")
        
        # Toolbar
        toolbar = ttk.Frame(self.logs_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT, padx=5)
        
        # Log level filter
        ttk.Label(toolbar, text="Log Level:").pack(side=tk.LEFT, padx=(20, 5))
        
        self.log_level = tk.StringVar(value="INFO")
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        level_menu = ttk.OptionMenu(toolbar, self.log_level, "INFO", *levels, command=self.filter_logs)
        level_menu.pack(side=tk.LEFT, padx=(0, 20))
        
        # Search frame
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.log_search = ttk.Entry(search_frame, width=30)
        self.log_search.pack(side=tk.LEFT, padx=(0, 5))
        self.log_search.bind("<KeyRelease>", self.search_logs)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            self.logs_frame,
            wrap=tk.WORD,
            width=100,
            height=30,
            font=('Consolas', 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout/stderr to log
        self.redirect_stdout()
    
    def setup_menus(self):
        """Set up the menu bar."""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Rule Set", command=self.new_ruleset)
        file_menu.add_command(label="Open Rule Set", command=self.open_ruleset)
        file_menu.add_command(label="Save Rule Set", command=self.save_ruleset)
        file_menu.add_separator()
        file_menu.add_command(label="Export Alerts", command=self.export_alerts)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Preferences", command=self.show_preferences)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_checkbutton(label="Show Toolbar", variable=tk.BooleanVar(value=True))
        view_menu.add_checkbutton(label="Show Status Bar", variable=tk.BooleanVar(value=True))
        view_menu.add_separator()
        view_menu.add_command(label="Refresh", command=self.refresh_data)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Traffic Monitor", command=self.open_traffic_monitor)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="Check for Updates", command=self.check_updates)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off."""
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.start_monitoring()
            self.start_btn.config(text="Stop Monitoring", style="Accent.TButton")
            self.status_var.set("Monitoring started")
        else:
            self.stop_monitoring()
            self.start_btn.config(text="Start Monitoring", style="TButton")
            self.status_var.set("Monitoring stopped")
        
        self.update_ui_state()
    
    def start_monitoring(self):
        """Start monitoring network traffic."""
        logger.info("Starting network monitoring")
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring network traffic."""
        logger.info("Stopping network monitoring")
        self.monitoring = False
    
    def monitor_network(self):
        """Background thread for monitoring network traffic."""
        while self.monitoring:
            try:
                # Simulate packet processing
                time.sleep(0.1)
                self.packets_analyzed += 1
                
                # Simulate occasional alerts
                if self.packets_analyzed % 100 == 0:
                    self.generate_sample_alert()
                
                # Update UI periodically
                if self.packets_analyzed % 10 == 0:
                    self.root.after(0, self.update_stats)
                
            except Exception as e:
                logger.error(f"Error in monitor thread: {e}")
    
    def generate_sample_alert(self):
        """Generate a sample alert for demo purposes."""
        import random
        
        threats = [
            ("Port Scan", "High", "Multiple connection attempts to different ports"),
            ("SQL Injection", "Critical", "Detected SQL injection attempt in HTTP request"),
            ("DDoS Attack", "High", "High volume of traffic from single source"),
            ("Malware C2", "Critical", "Connection to known C2 server"),
            ("Brute Force", "Medium", "Multiple failed login attempts")
        ]
        
        threat = random.choice(threats)
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_ip = "192.168.1.100"
        
        alert = Alert(
            id=str(len(self.alerts) + 1),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            severity=threat[1],
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=random.choice(["TCP", "UDP"]),
            description=threat[2],
            rule_id=f"R{random.randint(1000, 9999)}",
            action="blocked" if random.random() > 0.3 else "detected",
            details=f"Rule ID: {threat[0]}\nPayload: {threat[2]}"
        )
        
        self.alert_queue.put(alert)
    
    def process_alerts(self):
        """Process alerts from the queue and update the UI."""
        try:
            while True:
                try:
                    alert = self.alert_queue.get_nowait()
                    self.alerts.insert(0, alert)
                    
                    # Update alerts tree
                    self.alerts_tree.insert("", 0, values=(
                        alert.timestamp,
                        alert.severity,
                        alert.source_ip,
                        alert.destination_ip,
                        alert.protocol,
                        alert.description
                    ))
                    
                    # Keep only the last 100 alerts in memory
                    if len(self.alerts) > 100:
                        self.alerts = self.alerts[:100]
                        for item in self.alerts_tree.get_children()[100:]:
                            self.alerts_tree.delete(item)
                    
                    # Update stats
                    if alert.action == "blocked":
                        self.threats_blocked += 1
                    
                    # Show notification for high severity alerts
                    if alert.severity in ["High", "Critical"]:
                        self.show_alert_notification(alert)
                    
                except queue.Empty:
                    break
        except Exception as e:
            logger.error(f"Error processing alerts: {e}")
        
        # Schedule next check
        if self.running:
            self.root.after(100, self.process_alerts)
    
    def show_alert_notification(self, alert):
        """Show a notification for a high severity alert."""
        # In a real app, this would show a system notification
        logger.warning(f"ALERT: {alert.severity} - {alert.description}")
        
        # Flash the taskbar icon (Windows)
        if self.root.state() == 'iconic' or not self.root.focus_displayof():
            self.root.bell()
    
    def show_alert_details(self, event):
        """Show details for the selected alert."""
        selected = self.alerts_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        values = self.alerts_tree.item(item, 'values')
        
        # Find the full alert object
        alert = next((a for a in self.alerts if a.timestamp == values[0] and a.description == values[5]), None)
        if not alert:
            return
        
        # Create details window
        win = tk.Toplevel(self.root)
        win.title("Alert Details")
        win.geometry("600x400")
        
        # Make window modal
        win.transient(self.root)
        win.grab_set()
        
        # Frame for details
        frame = ttk.Frame(win, padding="15")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Alert details
        ttk.Label(frame, text=f"Alert ID: {alert.id}", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        
        # Severity indicator
        severity_frame = ttk.Frame(frame)
        severity_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(severity_frame, text="Severity:", font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        severity_color = {
            "Critical": "red",
            "High": "orange",
            "Medium": "yellow",
            "Low": "lightblue"
        }.get(alert.severity, "gray")
        
        severity_lbl = ttk.Label(
            severity_frame, 
            text=alert.severity, 
            foreground="white",
            background=severity_color,
            padding=(10, 2),
            font=('TkDefaultFont', 9, 'bold')
        )
        severity_lbl.pack(side=tk.LEFT, padx=5)
        
        # Details grid
        details = [
            ("Timestamp:", alert.timestamp),
            ("Source IP:", alert.source_ip),
            ("Destination IP:", alert.destination_ip),
            ("Protocol:", alert.protocol),
            ("Action:", alert.action.capitalize()),
            ("Rule ID:", alert.rule_id)
        ]
        
        for i, (label, value) in enumerate(details):
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, pady=2)
            
            ttk.Label(row, text=label, width=15, anchor=tk.W, font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
            ttk.Label(row, text=value, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Description
        ttk.Label(frame, text="Description:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(10, 2))
        desc = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            width=60,
            height=6,
            font=('TkDefaultFont', 9)
        )
        desc.insert(tk.END, alert.description)
        desc.config(state=tk.DISABLED)
        desc.pack(fill=tk.X, padx=5, pady=(0, 10))
        
        # Details
        ttk.Label(frame, text="Details:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(5, 2))
        details_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            width=60,
            height=8,
            font=('Consolas', 9)
        )
        details_text.insert(tk.END, alert.details)
        details_text.config(state=tk.DISABLED)
        details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 10))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Block IP", command=lambda: self.block_ip(alert.source_ip)).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Add Rule", command=lambda: self.add_rule_from_alert(alert)).pack(side=tk.RIGHT, padx=5)
    
    def block_ip(self, ip):
        """Block the specified IP address."""
        try:
            self.blocking_engine.block_ip(ip)
            messagebox.showinfo("IP Blocked", f"Successfully blocked IP: {ip}")
            logger.info(f"Blocked IP: {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block IP: {e}")
            logger.error(f"Error blocking IP {ip}: {e}")
    
    def add_rule_from_alert(self, alert):
        """Add a new rule based on an alert."""
        # In a real app, this would open the rule editor with pre-filled values
        logger.info(f"Adding rule from alert: {alert.id}")
        messagebox.showinfo("Add Rule", f"Would add rule for alert: {alert.id}")
    
    def update_stats(self):
        """Update the statistics display."""
        try:
            # Update uptime
            uptime = datetime.now() - self.start_time
            hours, remainder = divmod(int(uptime.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Update stats
            self.stats_vars["uptime"].set(uptime_str)
            self.stats_vars["monitoring"].set("Running" if self.monitoring else "Stopped")
            self.stats_vars["packets_analyzed"].set(f"{self.packets_analyzed:,}")
            self.stats_vars["threats_blocked"].set(f"{self.threats_blocked:,}")
            self.stats_vars["active_connections"].set(f"{self.connections_active}")
            self.stats_vars["rules_loaded"].set(f"{len(self.rules):,}")
            
            # Schedule next update
            if self.running:
                self.root.after(1000, self.update_stats)
                
        except Exception as e:
            logger.error(f"Error updating stats: {e}")
    
    def update_ui_state(self):
        """Update the UI state based on monitoring status."""
        state = tk.NORMAL if not self.monitoring else tk.DISABLED
        
        # Update monitoring controls
        for child in self.monitor_frame.winfo_children():
            if child != self.start_btn:
                try:
                    child.configure(state=state)
                except:
                    pass
    
    def load_rules(self):
        """Load rules from file."""
        try:
            # In a real app, this would load from a file
            self.rules = {
                "R1001": {"id": "R1001", "name": "Block SSH Brute Force", "severity": "High", "enabled": True},
                "R1002": {"id": "R1002", "name": "Detect SQL Injection", "severity": "Critical", "enabled": True},
                "R1003": {"id": "R1003", "name": "Block Known Malware IPs", "severity": "High", "enabled": True},
                "R1004": {"id": "R1004", "name": "Detect Port Scans", "severity": "Medium", "enabled": True},
                "R1005": {"id": "R1005", "name": "Block Tor Exit Nodes", "severity": "Medium", "enabled": False},
            }
            logger.info(f"Loaded {len(self.rules)} rules")
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
    
    def load_threat_feeds(self):
        """Load threat feeds."""
        try:
            # In a real app, this would load from a file or database
            feeds = [
                ("AbuseIPDB", "https://api.abuseipdb.com/api/v2/blacklist", "IP", "2023-01-01 12:00:00", 1250, True),
                ("AlienVault OTX", "https://otx.alienvault.com/api/v1/indicators/export", "IP/Domain", "2023-01-01 12:05:00", 850, True),
                ("FireHOL", "https://iplists.firehol.org/files/firehol_level1.netset", "IP", "2023-01-01 11:30:00", 5000, True),
                ("Malware Domain List", "https://www.malwaredomainlist.com/hostslist/ip.txt", "Domain", "2023-01-01 10:15:00", 320, False),
            ]
            
            for feed in feeds:
                self.feeds_tree.insert("", tk.END, values=feed)
                
            logger.info(f"Loaded {len(feeds)} threat feeds")
        except Exception as e:
            logger.error(f"Error loading threat feeds: {e}")
    
    def load_sample_rules(self):
        """Load sample rules for demonstration."""
        try:
            rules = [
                (True, "R1001", "Block SSH Brute Force", "High", "TCP/22", "Any", "SSH Server", "Block"),
                (True, "R1002", "Detect SQL Injection", "Critical", "HTTP/HTTPS", "Any", "Web Server", "Alert"),
                (True, "R1003", "Block Known Malware IPs", "High", "Any", "Threat Feed", "Any", "Block"),
                (True, "R1004", "Detect Port Scans", "Medium", "Any", "Any", "Any", "Alert"),
                (False, "R1005", "Block Tor Exit Nodes", "Medium", "Any", "Tor Network", "Any", "Block"),
                (True, "R1006", "Block Exploit Kits", "High", "HTTP/HTTPS", "Any", "Web Server", "Block"),
                (True, "R1007", "Detect Data Exfiltration", "Critical", "Any", "Internal", "External", "Alert"),
            ]
            
            for rule in rules:
                self.rules_tree.insert("", tk.END, values=rule)
                
            logger.info(f"Loaded {len(rules)} sample rules")
        except Exception as e:
            logger.error(f"Error loading sample rules: {e}")
    
    def redirect_stdout(self):
        """Redirect stdout and stderr to the log text area."""
        class StdoutRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget
                
            def write(self, string):
                self.text_widget.insert(tk.END, string)
                self.text_widget.see(tk.END)
                
            def flush(self):
                pass
        
        sys.stdout = StdoutRedirector(self.log_text)
        sys.stderr = StdoutRedirector(self.log_text)
    
    def on_closing(self):
        """Handle window close event."""
        self.running = False
        self.monitoring = False
        self.root.destroy()

def main():
    """Main entry point for the NIPS GUI application."""
    root = tk.Tk()
    app = NIPSGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
        """
        
        messagebox.showinfo("Alert Details", details.strip())
    
    def block_source_ip(self):
        """Block the source IP of the selected alert."""
        selected = self.alert_tree.selection()
        if not selected:
            selected = self.alerts_tree.selection()
            if not selected:
                return
            
            tree = self.alerts_tree
        else:
            tree = self.alert_tree
        
        item = selected[0]
        values = tree.item(item, "values")
        src_ip = values[2]  # Source IP is at index 2 in both trees
        
        if messagebox.askyesno("Confirm", f"Block all traffic from {src_ip}?"):
            # In a real implementation, this would add a firewall rule
            self.add_log_entry(f"Blocked IP: {src_ip}", "INFO")
            self.update_status(f"Blocked IP: {src_ip}")
            
            # Add a visual indicator
            for item in tree.get_children():
                if tree.item(item, "values")[2] == src_ip:
                    tree.item(item, tags=("blocked",))
    
    def add_to_whitelist(self):
        """Add the selected alert's source IP to the whitelist."""
        selected = self.alert_tree.selection()
        if not selected:
            selected = self.alerts_tree.selection()
            if not selected:
                return
            
            tree = self.alerts_tree
        else:
            tree = self.alert_tree
        
        item = selected[0]
        values = tree.item(item, "values")
        src_ip = values[2]  # Source IP is at index 2 in both trees
        
        if messagebox.askyesno("Confirm", f"Add {src_ip} to whitelist?"):
            # In a real implementation, this would add to the whitelist
            self.add_log_entry(f"Added IP to whitelist: {src_ip}", "INFO")
            self.update_status(f"Added {src_ip} to whitelist")
    
    def apply_filters(self):
        """Apply filters to the alerts view."""
        severity = self.severity_var.get()
        source_ip = self.source_ip_var.get().strip()
        
        # In a real implementation, this would filter the alerts
        self.add_log_entry(f"Applied filters - Severity: {severity}, Source IP: {source_ip or 'Any'}", "INFO")
        self.update_status(f"Filters applied: Severity={severity}, Source IP={source_ip or 'Any'}")
    
    def clear_filters(self):
        """Clear all filters."""
        self.severity_var.set("All")
        self.source_ip_var.set("")
        self.add_log_entry("Cleared all filters", "INFO")
        self.update_status("Filters cleared")
    
    def add_rule(self):
        """Add a new NIPS rule."""
        # In a real implementation, this would open a rule editor dialog
        self.add_log_entry("Add rule action triggered", "INFO")
        self.show_rule_editor()
    
    def edit_rule(self):
        """Edit the selected rule."""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        # In a real implementation, this would open the rule editor with the selected rule
        rule_id = self.rules_tree.item(selected[0], "values")[1]
        self.add_log_entry(f"Edit rule: {rule_id}", "INFO")
        self.show_rule_editor(rule_id)
    
    def delete_rule(self):
        """Delete the selected rule."""
        selected = self.rules_tree.selection()
        if not selected:
            return
        
        if messagebox.askyesno("Confirm", "Delete selected rule(s)?"):
            for item in selected:
                rule_id = self.rules_tree.item(item, "values")[1]
                self.rules_tree.delete(item)
                self.add_log_entry(f"Deleted rule: {rule_id}", "INFO")
            
            self.update_status(f"Deleted {len(selected)} rule(s)")
    
    def show_rule_editor(self, rule_id=None):
        """Show the rule editor dialog."""
        editor = tk.Toplevel(self.root)
        editor.title(f"{'Edit' if rule_id else 'Add'} NIPS Rule")
        editor.geometry("600x400")
        
        ttk.Label(editor, text="Rule Editor", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # In a real implementation, this would be a form for editing rule details
        ttk.Label(editor, text="Rule configuration would be edited here").pack(pady=20)
        
        def save_rule():
            self.add_log_entry(f"Rule {'updated' if rule_id else 'saved'}", "INFO")
            editor.destroy()
        
        btn_frame = ttk.Frame(editor)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save_rule).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Cancel", command=editor.destroy).pack(side=tk.LEFT, padx=10)
    
    def load_rules(self):
        """Load NIPS rules from disk."""
        # In a real implementation, this would load rules from a file
        self.rules = {
            "1001": {"enabled": True, "action": "alert", "protocol": "tcp", "src_ip": "any", "dst_ip": "$HOME_NET", "dst_port": "22", "msg": "SSH Traffic"},
            "1002": {"enabled": True, "action": "block", "protocol": "tcp", "src_ip": "any", "dst_ip": "$HOME_NET", "dst_port": "3389", "msg": "RDP Access Attempt"},
            "1003": {"enabled": False, "action": "alert", "protocol": "udp", "src_ip": "any", "dst_ip": "8.8.8.8", "dst_port": "53", "msg": "External DNS Query"}
        }
    
    def add_log_entry(self, message: str, level: str = "INFO"):
        """Add an entry to the log."""
        # In a real implementation, this would add to a log file
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)  # For demo purposes
    
    def update_status(self, message: str):
        """Update the status bar."""
        self.status_var.set(message)
    
    def show_alert_menu(self, event):
        """Show the context menu for alerts."""
        item = self.alert_tree.identify_row(event.y)
        if item:
            self.alert_tree.selection_set(item)
            self.alert_menu.post(event.x_root, event.y)
    
    def show_alerts_context_menu(self, event):
        """Show the context menu for alerts in the alerts tab."""
        item = self.alerts_tree.identify_row(event.y)
        if item:
            self.alerts_tree.selection_set(item)
            self.alerts_context_menu.post(event.x_root, event.y)

def main():
    """Main entry point for the NIPS GUI application."""
    # Create and run the application
    root = tk.Tk()
    app = NIPSGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
