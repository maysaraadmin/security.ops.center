"""
NIPS GUI Module

Provides a graphical interface for the Network Intrusion Prevention System.
Uses only standard libraries and modules from the nips folder.
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import logging
import sys
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
        logger.info("Initializing NIPS GUI...")
        
        try:
            self.root = root
            logger.debug("Root window created")
            
            # Set window properties
            self.root.title("Network Intrusion Prevention System (NIPS)")
            self.root.geometry("1200x800")
            self.root.minsize(1000, 700)
            logger.debug("Window properties set")
            
            # Make the window resizable
            self.root.grid_rowconfigure(0, weight=1)
            self.root.grid_columnconfigure(0, weight=1)
            logger.debug("Window resizing configured")
            
            # Initialize NIPS components
            self.monitoring = False
            self.alerts = []
            self.alert_queue = queue.Queue()
            self.rules = {}
            self.threats_blocked = 0
            self.packets_analyzed = 0
            self.connections_active = 0
            self.start_time = datetime.now()
            
            # Set up the UI
            self.setup_ui()
            logger.info("NIPS GUI initialization complete")
            
            # Ensure window is in the foreground and focused
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.after(100, lambda: self.root.attributes('-topmost', False))
            self.root.focus_force()
            logger.debug("Window focus and visibility set")
            
        except Exception as e:
            logger.error(f"Error initializing NIPS GUI: {e}")
            raise
        
        # Initialize NIPS modules with default configurations
        self.forensic_logger = ForensicLogger({
            'log_dir': 'logs',
            'max_size': 100,  # MB
            'backup_count': 30,
            'compress': True,
            'log_level': 'INFO',
            'enable_console': True,
            'enable_syslog': False,
            'syslog_address': 'localhost:514',
            'enable_network': False,
            'network_endpoints': []
        })
        self.tls_inspector = TLSInspector()
        self.blocking_engine = BlockingEngine()
        
        # Initialize ThreatFeedManager with default configuration
        self.threat_feed = ThreatFeedManager({
            'cache_ttl': 3600,  # 1 hour
            'feeds': {
                'alienvault_otx': {
                    'enabled': False,  # Disabled by default as it requires API key
                    'api_key': '',
                    'update_interval': 3600  # 1 hour
                },
                'mitre_attack': {
                    'enabled': True,
                    'update_interval': 86400  # 24 hours
                },
                'file_hash': {
                    'enabled': True,
                    'sources': [],
                    'update_interval': 3600  # 1 hour
                }
            },
            'enable_caching': True,
            'max_cache_size': 10000,
            'log_level': 'INFO'
        })
        
        # Initialize IOCProcessor with the threat feed manager
        self.ioc_processor = IOCProcessor(feed_manager=self.threat_feed)
        
        # Initialize ClusterManager with default node configuration
        self.cluster_manager = ClusterManager(
            node_id='nips_gui_node',
            cluster_nodes={
                'nips_gui_node': {
                    'host': 'localhost',
                    'port': 5000,
                    'role': 'gui',
                    'status': 'active'
                }
            }
        )
        
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
        
    def import_rules(self):
        """Import rules from a JSON file."""
        file_path = filedialog.askopenfilename(
            title="Select Rules File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return  # User cancelled
            
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
                
            if not isinstance(rules_data, list):
                messagebox.showerror("Error", "Invalid rules format: expected a list of rules")
                return
                
            # Add each rule to the system
            for rule_data in rules_data:
                # Validate required fields
                required_fields = ['id', 'name', 'severity', 'action']
                if not all(field in rule_data for field in required_fields):
                    messagebox.showerror("Error", f"Invalid rule format: missing required fields in rule {rule_data.get('id', 'unknown')}")
                    continue
                    
                # Add the rule to the system
                self.rules[rule_data['id']] = rule_data
                
            # Refresh the rules display
            self.load_rules()
            messagebox.showinfo("Success", f"Successfully imported {len(rules_data)} rules")
            
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON file")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")
            
    def export_rules(self):
        """Export rules to a JSON file."""
        if not self.rules:
            messagebox.showinfo("Info", "No rules to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Rules As"
        )
        
        if not file_path:
            return  # User cancelled
            
        try:
            # Convert rules to a list for export
            rules_list = list(self.rules.values())
            
            with open(file_path, 'w') as f:
                json.dump(rules_list, f, indent=4)
                
            messagebox.showinfo("Success", f"Successfully exported {len(rules_list)} rules to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export rules: {e}")
            
    def filter_rules(self, event=None):
        """Filter the rules list based on search text."""
        search_text = self.rule_search.get().lower()
        
        # Clear current selection
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        # If search is empty, show all rules
        if not search_text:
            self.load_rules()
            return
            
        # Filter and show matching rules
        for rule_id, rule in self.rules.items():
            # Check if search text matches any rule field
            match = any(
                search_text in str(rule.get(field, '')).lower()
                for field in ['id', 'name', 'severity', 'protocol', 'source', 'destination', 'action']
            )
            
            if match:
                self.rules_tree.insert(
                    '', 'end',
                    values=(
                        rule.get('enabled', False),
                        rule_id,
                        rule.get('name', ''),
                        rule.get('severity', 'medium'),
                        rule.get('protocol', 'any'),
                        rule.get('source', 'any'),
                        rule.get('destination', 'any'),
                        rule.get('action', 'alert')
                    )
                )
        
    def save_monitor_config(self):
        """Save monitoring configuration to a file."""
        config = {
            'interface': self.interface_var.get(),
            'promiscuous': self.promisc_var.get(),
            'timeout': int(self.timeout_var.get()),
            'filter': self.filter_var.get(),
            'max_packet': int(self.max_packet.get())
        }
        
        try:
            with open('monitor_config.json', 'w') as f:
                json.dump(config, f, indent=4)
            messagebox.showinfo("Success", "Monitoring configuration saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
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
        # Start the alert processing thread
        self.alert_processing_thread = threading.Thread(target=self.process_alerts, daemon=True)
        self.alert_processing_thread.start()
        
    def clear_logs(self):
        """Clear the logs text widget."""
        if hasattr(self, 'log_text') and self.log_text:
            try:
                self.log_text.config(state=tk.NORMAL)  # Enable editing
                self.log_text.delete(1.0, tk.END)  # Clear all text
                self.log_text.config(state=tk.DISABLED)  # Disable editing
                logger.info("Logs cleared")
            except Exception as e:
                logger.error(f"Error clearing logs: {e}")
                messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
                
    def save_logs(self):
        """Save the current logs to a file."""
        if not hasattr(self, 'log_text') or not self.log_text:
            messagebox.showwarning("No Logs", "No logs available to save.")
            return
            
        try:
            # Open file dialog to choose save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Logs As"
            )
            
            if not file_path:  # User cancelled the dialog
                return
                
            # Get the log content
            log_content = self.log_text.get(1.0, tk.END)
            
            # Write to file
            with open(file_path, 'w') as f:
                f.write(log_content)
                
            logger.info(f"Logs saved to {file_path}")
            messagebox.showinfo("Success", f"Logs successfully saved to {file_path}")
            
        except Exception as e:
            logger.error(f"Error saving logs: {e}")
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
            
    def filter_logs(self, level):
        """Filter logs based on the selected log level."""
        if not hasattr(self, 'log_text') or not hasattr(self, 'log_level'):
            return
            
        try:
            # Get the current log level
            current_level = self.log_level.get()
            
            # Map log level names to their numeric values
            level_map = {
                'DEBUG': 10,
                'INFO': 20,
                'WARNING': 30,
                'ERROR': 40,
                'CRITICAL': 50
            }
            
            # Get the numeric value of the selected level
            selected_level = level_map.get(level, 20)  # Default to INFO
            
            # Get all log records
            records = self.log_handler.records if hasattr(self, 'log_handler') else []
            
            # Clear the current log display
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            
            # Filter and display logs based on the selected level
            for record in records:
                if record.levelno >= selected_level:
                    self.log_text.insert(tk.END, f"{record.asctime} - {record.levelname} - {record.message}\n")
            
            # Disable editing of the log text
            self.log_text.config(state=tk.DISABLED)
            
            # Auto-scroll to the bottom
            self.log_text.see(tk.END)
            
            logger.debug(f"Filtered logs to show level {level} and above")
            
        except Exception as e:
            logger.error(f"Error filtering logs: {e}")
            
    def search_logs(self, event=None):
        """Search through the logs for the given text."""
        if not hasattr(self, 'log_text') or not hasattr(self, 'log_search'):
            return
            
        try:
            # Get the search term
            search_term = self.log_search.get().lower()
            
            # If search term is empty, reset the view
            if not search_term:
                self.filter_logs(self.log_level.get() if hasattr(self, 'log_level') else 'INFO')
                return
                
            # Get all text from the log widget
            self.log_text.tag_remove('found', '1.0', tk.END)
            self.log_text.tag_configure('found', background='yellow')
            
            # Enable the text widget for searching
            self.log_text.config(state=tk.NORMAL)
            
            # Start from the beginning
            idx = '1.0'
            found_count = 0
            
            while True:
                # Search for the pattern
                idx = self.log_text.search(search_term, idx, nocase=1, stopindex=tk.END)
                
                if not idx:
                    break
                    
                # Calculate end index of the found text
                last_idx = f"{idx}+{len(search_term)}c"
                
                # Add tag to the found text
                self.log_text.tag_add('found', idx, last_idx)
                found_count += 1
                
                # Move to the end of the current match
                idx = last_idx
            
            # Disable editing of the log text
            self.log_text.config(state=tk.DISABLED)
            
            # Update status
            status = f"Found {found_count} occurrences of '{search_term}'"
            if hasattr(self, 'status_bar'):
                self.status_bar.config(text=status)
                
            logger.debug(f"Searched logs for '{search_term}': {found_count} results")
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
    
    def new_ruleset(self):
        """Create a new rule set."""
        try:
            # Ask for confirmation if there are unsaved changes
            if self.rules:
                if not messagebox.askyesno(
                    "New Rule Set",
                    "This will clear all current rules. Are you sure you want to continue?"
                ):
                    return
            
            # Clear existing rules
            self.rules = {}
            
            # Update the rules tree
            self.update_rules_tree()
            
            # Update status
            self.status_var.set("Created new empty rule set")
            logger.info("Created new empty rule set")
            
        except Exception as e:
            error_msg = f"Error creating new rule set: {e}"
            messagebox.showerror("Error", error_msg)
            logger.error(error_msg, exc_info=True)
            
    def open_ruleset(self):
        """Open a rule set from a file."""
        try:
            # Ask for confirmation if there are unsaved changes
            if self.rules:
                if not messagebox.askyesno(
                    "Open Rule Set",
                    "This will replace the current rules. Are you sure you want to continue?"
                ):
                    return
            
            # Open file dialog to select rule file
            file_path = filedialog.askopenfilename(
                title="Open Rule Set",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialdir=os.getcwd()
            )
            
            if not file_path:
                return  # User cancelled
                
            # Load rules from file
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
                
            # Validate rules format
            if not isinstance(rules_data, dict):
                raise ValueError("Invalid rule set format: expected a dictionary")
                
            # Clear existing rules
            self.rules = {}
            
            # Add loaded rules
            for rule_id, rule_data in rules_data.items():
                self.rules[rule_id] = rule_data
                
            # Update the rules tree
            self.update_rules_tree()
            
            # Update status
            self.status_var.set(f"Loaded {len(self.rules)} rules from {os.path.basename(file_path)}")
            logger.info(f"Loaded {len(self.rules)} rules from {file_path}")
            
        except json.JSONDecodeError as e:
            error_msg = f"Error parsing rule set file: {e}"
            messagebox.showerror("Error", error_msg)
            logger.error(error_msg, exc_info=True)
            
        except Exception as e:
            error_msg = f"Error loading rule set: {e}"
            messagebox.showerror("Error", error_msg)
            logger.error(error_msg, exc_info=True)
            
    def save_ruleset(self):
        """Save the current rule set to a file."""
        try:
            if not self.rules:
                messagebox.showinfo("No Rules", "There are no rules to save.")
                return
                
            # Open file dialog to select save location
            file_path = filedialog.asksaveasfilename(
                title="Save Rule Set As",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialdir=os.getcwd()
            )
            
            if not file_path:
                return  # User cancelled
                
            # Save rules to file
            with open(file_path, 'w') as f:
                json.dump(self.rules, f, indent=4)
                
            # Update status
            self.status_var.set(f"Saved {len(self.rules)} rules to {os.path.basename(file_path)}")
            logger.info(f"Saved {len(self.rules)} rules to {file_path}")
            
        except Exception as e:
            error_msg = f"Error saving rule set: {e}"
            messagebox.showerror("Error", error_msg)
            logger.error(error_msg, exc_info=True)
            
    def export_alerts(self):
        """Export alerts to a file."""
        try:
            if not hasattr(self, 'alerts') or not self.alerts:
                messagebox.showinfo("No Alerts", "There are no alerts to export.")
                return
                
            # Open file dialog to select save location
            file_path = filedialog.asksaveasfilename(
                title="Export Alerts As",
                defaultextension=".json",
                filetypes=[
                    ("JSON files", "*.json"),
                    ("CSV files", "*.csv"),
                    ("Text files", "*.txt"),
                    ("All files", "*.*")
                ],
                initialdir=os.getcwd()
            )
            
            if not file_path:
                return  # User cancelled
                
            # Get file extension to determine format
            _, ext = os.path.splitext(file_path.lower())
            
            if ext == '.csv':
                # Export as CSV
                import csv
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'Severity', 'Description'])
                    # Write alert data
                    for alert in self.alerts:
                        writer.writerow([
                            alert.get('timestamp', ''),
                            alert.get('src_ip', ''),
                            alert.get('dst_ip', ''),
                            alert.get('port', ''),
                            alert.get('protocol', ''),
                            alert.get('severity', ''),
                            alert.get('description', '')
                        ])
            elif ext == '.txt':
                # Export as plain text
                with open(file_path, 'w') as f:
                    for alert in self.alerts:
                        f.write(f"Timestamp: {alert.get('timestamp', 'N/A')}\n")
                        f.write(f"Source: {alert.get('src_ip', 'N/A')} -> Destination: {alert.get('dst_ip', 'N/A')}:{alert.get('port', 'N/A')}\n")
                        f.write(f"Protocol: {alert.get('protocol', 'N/A')}, Severity: {alert.get('severity', 'N/A')}\n")
                        f.write(f"Description: {alert.get('description', '')}\n")
                        f.write("-" * 80 + "\n\n")
            else:
                # Default to JSON
                with open(file_path, 'w') as f:
                    json.dump(self.alerts, f, indent=4, default=str)
            
            # Update status
            self.status_var.set(f"Exported {len(self.alerts)} alerts to {os.path.basename(file_path)}")
            logger.info(f"Exported {len(self.alerts)} alerts to {file_path}")
            
        except Exception as e:
            error_msg = f"Error exporting alerts: {e}"
            messagebox.showerror("Error", error_msg)
            logger.error(error_msg, exc_info=True)
            
    def refresh_data(self):
        """Refresh data displayed in the UI."""
        try:
            logger.info("Refreshing UI data...")
            
            # Update status bar
            if hasattr(self, 'status_var'):
                self.status_var.set("Refreshing data...")
                
            # Update rules tree
            if hasattr(self, 'rules_tree'):
                self.update_rules_tree()
                
            # Update alerts list
            if hasattr(self, 'alerts_tree'):
                self.update_alerts_tree()
                
            # Update statistics
            if hasattr(self, 'update_statistics'):
                self.update_statistics()
                
            # Update status bar
            if hasattr(self, 'status_var'):
                self.status_var.set("Data refreshed")
                
            logger.info("UI data refresh complete")
            
        except Exception as e:
            error_msg = f"Error refreshing data: {e}"
            if hasattr(self, 'status_var'):
                self.status_var.set("Error refreshing data")
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
            
    def show_about(self):
        """Show the About dialog."""
        try:
            logger.info("Showing About dialog...")
            
            # Create the about dialog
            about_dialog = tk.Toplevel(self.root)
            about_dialog.title("About NIPS")
            about_dialog.transient(self.root)
            about_dialog.grab_set()
            about_dialog.geometry("500x400")
            
            # Create main frame
            main_frame = ttk.Frame(about_dialog, padding=20)
            main_frame.pack(fill='both', expand=True)
            
            # Add application icon/title
            ttk.Label(main_frame, 
                     text="NIPS", 
                     font=('Arial', 24, 'bold'))\
                .pack(pady=(0, 10))
                
            ttk.Label(main_frame, 
                     text="Network Intrusion Prevention System",
                     font=('Arial', 12))\
                .pack(pady=(0, 20))
            
            # Add version info
            version_frame = ttk.LabelFrame(main_frame, text="Version Information", padding=10)
            version_frame.pack(fill='x', pady=(0, 20))
            
            ttk.Label(version_frame, 
                     text="Version: 1.0.0",
                     font=('Arial', 10))\
                .pack(anchor='w')
                
            ttk.Label(version_frame, 
                     text="Build Date: 2023-08-28",
                     font=('Arial', 10))\
                .pack(anchor='w')
            
            # Add copyright info
            ttk.Label(main_frame, 
                     text="© 2023 Security Ops Center",
                     font=('Arial', 9, 'italic'))\
                .pack(side='bottom', pady=(20, 0))
                
            # Add credits
            credits_frame = ttk.LabelFrame(main_frame, text="Credits", padding=10)
            credits_frame.pack(fill='both', expand=True, pady=(0, 20))
            
            credits_text = """Developed by: Security Ops Center Team

This software is part of the Security Ops Center platform.

Dependencies:
- Python 3.8+
- Scapy for packet analysis
- psutil for system monitoring
- Requests for API communication

Licensed under the Apache License 2.0"""
            
            ttk.Label(credits_frame, 
                     text=credits_text,
                     justify='left')\
                .pack(anchor='w')
            
            # Add close button
            ttk.Button(main_frame, 
                      text="Close", 
                      command=about_dialog.destroy)\
                .pack(side='bottom', pady=(10, 0))
            
            # Make the dialog modal
            about_dialog.wait_window()
            
        except Exception as e:
            error_msg = f"Error showing about dialog: {e}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
    
    def check_updates(self):
        """Check for available updates."""
        try:
            logger.info("Checking for updates...")
            
            # In a real application, this would check a server for updates
            # For now, we'll simulate checking for updates
            import random
            has_update = random.choice([True, False])
            
            # Create a dialog to show update status
            update_dialog = tk.Toplevel(self.root)
            update_dialog.title("Check for Updates")
            update_dialog.transient(self.root)
            update_dialog.grab_set()
            update_dialog.geometry("500x300")
            
            # Create main frame
            main_frame = ttk.Frame(update_dialog, padding=20)
            main_frame.pack(fill='both', expand=True)
            
            # Add title
            ttk.Label(main_frame, 
                     text="Check for Updates", 
                     font=('Arial', 14, 'bold'))\
                .pack(pady=(0, 20))
            
            if has_update:
                # Update available
                ttk.Label(main_frame, 
                         text="A new version is available!",
                         font=('Arial', 12, 'bold'),
                         foreground='green').pack(pady=10)
                
                ttk.Label(main_frame, 
                         text="Version 2.0.0 is now available.\n\n"
                              "What's new in this version:\n"
                              "• New traffic monitoring features\n"
                              "• Improved detection algorithms\n"
                              "• Bug fixes and performance improvements",
                         justify='left').pack(pady=10, fill='x')
                
                # Add update button
                btn_frame = ttk.Frame(main_frame)
                btn_frame.pack(pady=20)
                
                ttk.Button(btn_frame, 
                          text="Download Update", 
                          command=lambda: webbrowser.open("https://security.ops.center/download"))\
                    .pack(side='left', padx=5)
                    
                ttk.Button(btn_frame, 
                          text="Release Notes", 
                          command=lambda: webbrowser.open("https://security.ops.center/release-notes"))\
                    .pack(side='left', padx=5)
                
            else:
                # No updates available
                ttk.Label(main_frame, 
                         text="You're up to date!",
                         font=('Arial', 12, 'bold'),
                         foreground='green').pack(pady=20)
                
                ttk.Label(main_frame, 
                         text=f"You have the latest version of NIPS (v1.0.0).\n\n"
                              "Last checked: {}".format(
                                  datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
                         justify='center').pack(pady=10)
                
                # Add close button
                ttk.Button(main_frame, 
                          text="Close", 
                          command=update_dialog.destroy)\
                    .pack(pady=10)
            
            # Add a check for beta updates option
            check_beta = tk.BooleanVar()
            ttk.Checkbutton(main_frame, 
                          text="Include beta/pre-release versions",
                          variable=check_beta).pack(pady=10)
            
            # Make the dialog modal
            update_dialog.wait_window()
            
        except Exception as e:
            error_msg = f"Error checking for updates: {e}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
    
    def show_documentation(self):
        """Show the documentation in a web browser."""
        try:
            logger.info("Opening documentation...")
            
            # In a real application, this would open the actual documentation
            # For now, we'll show a message with a link
            doc_url = "https://docs.security.ops.center/nips"
            
            # Create a dialog to show the documentation link
            doc_dialog = tk.Toplevel(self.root)
            doc_dialog.title("Documentation")
            doc_dialog.transient(self.root)
            doc_dialog.grab_set()
            doc_dialog.geometry("600x400")
            
            # Create main frame
            main_frame = ttk.Frame(doc_dialog, padding=20)
            main_frame.pack(fill='both', expand=True)
            
            # Add title
            ttk.Label(main_frame, 
                     text="NIPS Documentation", 
                     font=('Arial', 14, 'bold'))\
                .pack(pady=(0, 20))
            
            # Add description
            doc_text = """Welcome to the NIPS (Network Intrusion Prevention System) documentation.
            
For detailed information about using the NIPS, please visit our online documentation:
            
{url}
            
The documentation includes:
- Getting Started Guide
- User Manual
- Configuration Reference
- Troubleshooting
- API Documentation

If you need further assistance, please contact support@security.ops.center""".format(url=doc_url)
            
            # Add text widget with scrollbar
            text_frame = ttk.Frame(main_frame)
            text_frame.pack(fill='both', expand=True)
            
            text = tk.Text(text_frame, wrap='word', padx=10, pady=10, font=('Arial', 10))
            text.insert('1.0', doc_text)
            text.config(state='disabled')
            
            # Make the URL clickable
            text.tag_configure('url', foreground='blue', underline=1)
            text.tag_bind('url', '<Button-1>', lambda e: webbrowser.open(doc_url))
            text.tag_bind('url', '<Enter>', lambda e: text.config(cursor='hand2'))
            text.tag_bind('url', '<Leave>', lambda e: text.config(cursor=''))
            
            # Find and tag the URL
            start = doc_text.find(doc_url)
            if start >= 0:
                end = start + len(doc_url)
                text.tag_add('url', f'1.0+{start}c', f'1.0+{end}c')
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(text_frame, command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            
            # Grid layout
            text.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            # Add close button
            btn_frame = ttk.Frame(main_frame)
            btn_frame.pack(fill='x', pady=(20, 0))
            
            ttk.Button(btn_frame, 
                      text="Open in Browser", 
                      command=lambda: webbrowser.open(doc_url))\
                .pack(side='left', padx=5)
                
            ttk.Button(btn_frame, 
                      text="Close", 
                      command=doc_dialog.destroy)\
                .pack(side='right', padx=5)
            
            # Make the dialog modal
            doc_dialog.wait_window()
            
        except Exception as e:
            error_msg = f"Error showing documentation: {e}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
    
    def open_traffic_monitor(self):
        """Open the traffic monitor tool."""
        try:
            logger.info("Opening traffic monitor...")
            
            # Create a new window for the traffic monitor
            monitor = tk.Toplevel(self.root)
            monitor.title("Traffic Monitor")
            monitor.transient(self.root)
            monitor.grab_set()
            monitor.geometry("1000x700")
            
            # Create main frame
            main_frame = ttk.Frame(monitor, padding=10)
            main_frame.pack(fill='both', expand=True)
            
            # Add a simple message for now
            ttk.Label(main_frame, text="Traffic Monitor", font=('Arial', 12, 'bold')).pack(pady=10)
            ttk.Label(main_frame, text="This is a placeholder for the traffic monitoring functionality.").pack(pady=5)
            ttk.Label(main_frame, text="In a full implementation, this would show real-time network traffic,").pack(pady=2)
            ttk.Label(main_frame, text="bandwidth usage, and connection statistics.").pack(pady=2)
            
            # Add a close button
            ttk.Button(main_frame, text="Close", command=monitor.destroy).pack(pady=20)
            
            # Make the dialog modal
            monitor.wait_window()
            
        except Exception as e:
            error_msg = f"Error opening traffic monitor: {e}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
    
    def open_network_scanner(self):
        """Open the network scanner tool."""
        try:
            logger.info("Opening network scanner...")
            
            # Create a new window for the network scanner
            scanner = tk.Toplevel(self.root)
            scanner.title("Network Scanner")
            scanner.transient(self.root)
            scanner.grab_set()
            scanner.geometry("800x600")
            
            # Create main frame
            main_frame = ttk.Frame(scanner, padding=10)
            main_frame.pack(fill='both', expand=True)
            
            # Add a simple message for now
            ttk.Label(main_frame, text="Network Scanner Tool", font=('Arial', 12, 'bold')).pack(pady=10)
            ttk.Label(main_frame, text="This is a placeholder for the network scanner functionality.").pack(pady=5)
            ttk.Label(main_frame, text="In a full implementation, this would allow scanning networks for hosts,").pack(pady=2)
            ttk.Label(main_frame, text="open ports, and services.").pack(pady=2)
            
            # Add a close button
            ttk.Button(main_frame, text="Close", command=scanner.destroy).pack(pady=20)
            
            # Make the dialog modal
            scanner.wait_window()
            
        except Exception as e:
            error_msg = f"Error opening network scanner: {e}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
    
    def open_packet_analyzer(self):
        """Open the packet analyzer tool."""
        try:
            logger.info("Opening packet analyzer...")
            
            # Create a new window for the packet analyzer
            analyzer = tk.Toplevel(self.root)
            analyzer.title("Packet Analyzer")
            analyzer.transient(self.root)
            analyzer.grab_set()
            
            # Set window size and position
            analyzer.geometry("800x600")
            
            # Create main frame
            main_frame = ttk.Frame(analyzer, padding=10)
            main_frame.pack(fill='both', expand=True)
            
            # Create filter frame
            filter_frame = ttk.LabelFrame(main_frame, text="Filters", padding=5)
            filter_frame.pack(fill='x', pady=(0, 10))
            
            # Protocol filter
            ttk.Label(filter_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
            protocol_var = tk.StringVar()
            protocol_combo = ttk.Combobox(filter_frame, textvariable=protocol_var, 
                                        values=["All", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"],
                                        state='readonly', width=10)
            protocol_combo.set("All")
            protocol_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
            
            # Source IP filter
            ttk.Label(filter_frame, text="Source IP:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
            src_ip_entry = ttk.Entry(filter_frame, width=15)
            src_ip_entry.grid(row=0, column=3, padx=5, pady=5, sticky='w')
            
            # Destination IP filter
            ttk.Label(filter_frame, text="Dest IP:").grid(row=0, column=4, padx=5, pady=5, sticky='w')
            dst_ip_entry = ttk.Entry(filter_frame, width=15)
            dst_ip_entry.grid(row=0, column=5, padx=5, pady=5, sticky='w')
            
            # Port filter
            ttk.Label(filter_frame, text="Port:").grid(row=0, column=6, padx=5, pady=5, sticky='w')
            port_entry = ttk.Entry(filter_frame, width=8)
            port_entry.grid(row=0, column=7, padx=5, pady=5, sticky='w')
            
            # Apply filter button
            def apply_filters():
                # This would apply the filters to the packet capture
                logger.info("Applying packet filters...")
                # Implementation would go here
                
            apply_btn = ttk.Button(filter_frame, text="Apply Filters", command=apply_filters)
            apply_btn.grid(row=0, column=8, padx=5, pady=5, sticky='e')
            
            # Create packet list frame
            list_frame = ttk.Frame(main_frame)
            list_frame.pack(fill='both', expand=True)
            
            # Create treeview for packets
            columns = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Info")
            tree = ttk.Treeview(list_frame, columns=columns, show='headings', selectmode='browse')
            
            # Configure columns
            for col in columns:
                tree.heading(col, text=col, command=lambda c=col: sort_treeview(tree, c, False))
                tree.column(col, width=100, minwidth=50, anchor='w')
            
            # Adjust specific column widths
            tree.column("#", width=40)
            tree.column("Time", width=120)
            tree.column("Length", width=70)
            
            # Add scrollbars
            vsb = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
            hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            
            # Grid layout
            tree.grid(row=0, column=0, sticky='nsew')
            vsb.grid(row=0, column=1, sticky='ns')
            hsb.grid(row=1, column=0, sticky='ew')
            
            # Configure grid weights
            list_frame.grid_rowconfigure(0, weight=1)
            list_frame.grid_columnconfigure(0, weight=1)
            
            # Create details frame
            details_frame = ttk.LabelFrame(main_frame, text="Packet Details", padding=5)
            details_frame.pack(fill='x', pady=(10, 0))
            
            # Add text widget for packet details
            details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10)
            details_text.pack(fill='both', expand=True, pady=5)
            
            # Add some sample packet data (in a real app, this would come from packet capture)
            sample_packets = [
                (1, "2023-01-01 12:00:01", "192.168.1.1:1234", "192.168.1.100:80", "TCP", "60", "SYN"),
                (2, "2023-01-01 12:00:02", "192.168.1.100:80", "192.168.1.1:1234", "TCP", "60", "SYN-ACK"),
                (3, "2023-01-01 12:00:03", "192.168.1.1:1234", "192.168.1.100:80", "TCP", "100", "ACK GET /")
            ]
            
            for packet in sample_packets:
                tree.insert('', 'end', values=packet)
            
            # Add button frame
            btn_frame = ttk.Frame(main_frame)
            btn_frame.pack(fill='x', pady=(10, 0))
            
            # Add buttons
            start_btn = ttk.Button(btn_frame, text="Start Capture", command=lambda: None)  # Would start capture
            start_btn.pack(side='left', padx=5)
            
            stop_btn = ttk.Button(btn_frame, text="Stop Capture", state='disabled', command=lambda: None)  # Would stop capture
            stop_btn.pack(side='left', padx=5)
            
            clear_btn = ttk.Button(btn_frame, text="Clear", command=lambda: tree.delete(*tree.get_children()))
            clear_btn.pack(side='right', padx=5)
            
            # Bind double-click to show packet details
            def on_item_double_click(event):
                item = tree.identify('item', event.x, event.y)
                if item:
                    values = tree.item(item, 'values')
                    if values:
                        details_text.delete(1.0, tk.END)
                        details_text.insert(tk.END, f"Packet #{values[0]} Details\n")
                        details_text.insert(tk.END, "-" * 50 + "\n")
                        details_text.insert(tk.END, f"Time: {values[1]}\n")
                        details_text.insert(tk.END, f"Source: {values[2]}\n")
                        details_text.insert(tk.END, f"Destination: {values[3]}\n")
                        details_text.insert(tk.END, f"Protocol: {values[4]}\n")
                        details_text.insert(tk.END, f"Length: {values[5]} bytes\n")
                        details_text.insert(tk.END, f"Info: {values[6]}\n")
            
            tree.bind('<Double-1>', on_item_double_click)
            
            # Make the dialog modal
            analyzer.wait_window()
            
        except Exception as e:
            error_msg = f"Error opening packet analyzer: {e}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)
    
    def show_preferences(self):
        """Show the preferences dialog."""
        try:
            # Create the preferences dialog
            prefs_dialog = tk.Toplevel(self.root)
            prefs_dialog.title("Preferences")
            prefs_dialog.transient(self.root)
            prefs_dialog.grab_set()
            
            # Set dialog size and position
            dialog_width = 500
            dialog_height = 400
            screen_width = prefs_dialog.winfo_screenwidth()
            screen_height = prefs_dialog.winfo_screenheight()
            x = (screen_width // 2) - (dialog_width // 2)
            y = (screen_height // 2) - (dialog_height // 2)
            prefs_dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
            
            # Create notebook for preference categories
            notebook = ttk.Notebook(prefs_dialog)
            notebook.pack(fill='both', expand=True, padx=10, pady=10)
            
            # General tab
            general_frame = ttk.Frame(notebook, padding=10)
            notebook.add(general_frame, text="General")
            
            # Logging level
            ttk.Label(general_frame, text="Logging Level:").grid(row=0, column=0, sticky='w', pady=5)
            log_level = ttk.Combobox(general_frame, values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
            log_level.set(logging.getLevelName(logger.getEffectiveLevel()))
            log_level.grid(row=0, column=1, sticky='ew', pady=5, padx=5)
            
            # Auto-save interval (minutes)
            ttk.Label(general_frame, text="Auto-save Interval (minutes):").grid(row=1, column=0, sticky='w', pady=5)
            auto_save = ttk.Spinbox(general_frame, from_=1, to=60, width=5)
            auto_save.set(getattr(self, 'auto_save_interval', 5))
            auto_save.grid(row=1, column=1, sticky='w', pady=5, padx=5)
            
            # Network tab
            network_frame = ttk.Frame(notebook, padding=10)
            notebook.add(network_frame, text="Network")
            
            # Network interface
            ttk.Label(network_frame, text="Network Interface:").grid(row=0, column=0, sticky='w', pady=5)
            iface = ttk.Combobox(network_frame)
            try:
                import netifaces
                interfaces = netifaces.interfaces()
                iface['values'] = interfaces
                if hasattr(self, 'network_interface') and self.network_interface in interfaces:
                    iface.set(self.network_interface)
                elif interfaces:
                    iface.set(interfaces[0])
            except ImportError:
                iface.insert(0, "netifaces module not installed")
                iface.config(state='disabled')
            iface.grid(row=0, column=1, sticky='ew', pady=5, padx=5)
            
            # Packet capture filter
            ttk.Label(network_frame, text="Packet Filter:").grid(row=1, column=0, sticky='w', pady=5)
            packet_filter = ttk.Entry(network_frame)
            packet_filter.insert(0, getattr(self, 'packet_filter', 'tcp or udp or icmp'))
            packet_filter.grid(row=1, column=1, sticky='ew', pady=5, padx=5)
            
            # Buttons
            button_frame = ttk.Frame(prefs_dialog)
            button_frame.pack(fill='x', padx=10, pady=10)
            
            def apply_changes():
                try:
                    # Apply general settings
                    logger.setLevel(log_level.get())
                    self.auto_save_interval = int(auto_save.get())
                    
                    # Apply network settings
                    if iface.get() and iface['state'] != 'disabled':
                        self.network_interface = iface.get()
                    self.packet_filter = packet_filter.get()
                    
                    # Save preferences
                    self.save_preferences()
                    
                    # Update status
                    self.status_var.set("Preferences saved")
                    logger.info("Preferences saved")
                    
                    # Close dialog
                    prefs_dialog.destroy()
                    
                except Exception as e:
                    error_msg = f"Error applying preferences: {e}"
                    messagebox.showerror("Error", error_msg)
                    logger.error(error_msg, exc_info=True)
            
            ttk.Button(button_frame, text="OK", command=apply_changes).pack(side='right', padx=5)
            ttk.Button(button_frame, text="Cancel", command=prefs_dialog.destroy).pack(side='right', padx=5)
            ttk.Button(button_frame, text="Apply", command=apply_changes).pack(side='right', padx=5)
            
            # Make the dialog modal
            prefs_dialog.wait_window()
            
        except Exception as e:
            error_msg = f"Error showing preferences: {e}"
            messagebox.showerror("Error", error_msg)
            logger.error(error_msg, exc_info=True)
    
    def save_preferences(self):
        """Save preferences to a file."""
        try:
            prefs = {
                'log_level': logging.getLevelName(logger.getEffectiveLevel()),
                'auto_save_interval': getattr(self, 'auto_save_interval', 5),
                'network_interface': getattr(self, 'network_interface', ''),
                'packet_filter': getattr(self, 'packet_filter', 'tcp or udp or icmp'),
                'window_geometry': self.root.geometry()
            }
            
            # Ensure the config directory exists
            config_dir = os.path.join(os.path.expanduser('~'), '.nips')
            os.makedirs(config_dir, exist_ok=True)
            
            # Save to file
            config_file = os.path.join(config_dir, 'preferences.json')
            with open(config_file, 'w') as f:
                json.dump(prefs, f, indent=4)
                
            logger.debug(f"Preferences saved to {config_file}")
            
        except Exception as e:
            logger.error(f"Error saving preferences: {e}", exc_info=True)
            raise
    
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
            
    def update_threat_feeds(self):
        """Update all enabled threat feeds."""
        if not hasattr(self, 'threat_feed'):
            messagebox.showerror("Error", "Threat feed manager not initialized")
            return
            
        try:
            # Clear existing feeds
            for item in self.feeds_tree.get_children():
                self.feeds_tree.delete(item)
                
            # Simulate updating feeds (in a real app, this would call threat_feed.update_feeds())
            updated_feeds = [
                ("AbuseIPDB", "https://api.abuseipdb.com/api/v2/blacklist", "IP", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1300, True),
                ("AlienVault OTX", "https://otx.alienvault.com/api/v1/indicators/export", "IP/Domain", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 900, True),
                ("FireHOL", "https://iplists.firehol.org/files/firehol_level1.netset", "IP", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 5200, True),
                ("Malware Domain List", "https://www.malwaredomainlist.com/hostslist/ip.txt", "Domain", "2023-01-01 10:15:00", 320, False),
            ]
            
            for feed in updated_feeds:
                self.feeds_tree.insert("", tk.END, values=feed)
                
            messagebox.showinfo("Success", "Successfully updated threat feeds")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update threat feeds: {str(e)}")
            
    def view_iocs(self):
        """View IOCs from the selected threat feed."""
        selected = self.feeds_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a threat feed first")
            return
            
        # Get the selected feed details
        item = self.feeds_tree.item(selected[0])
        feed_name = item['values'][0]
        feed_url = item['values'][1]
        feed_type = item['values'][2]
        
        # Create a dialog to display IOCs
        dialog = tk.Toplevel(self.root)
        dialog.title(f"IOCs - {feed_name}")
        dialog.geometry("800x600")
        
        # Add a frame for the toolbar
        toolbar = ttk.Frame(dialog)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # Add search functionality
        ttk.Label(toolbar, text="Search:").pack(side=tk.LEFT, padx=5)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Add a treeview to display IOCs
        columns = ("Value", "Type", "First Seen", "Last Seen", "Source")
        tree = ttk.Treeview(dialog, columns=columns, show="headings", selectmode="browse")
        
        # Configure columns
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor=tk.W)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(dialog, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(dialog, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Pack the tree and scrollbars
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Add a status bar
        status = ttk.Label(dialog, text=f"Showing IOCs from {feed_name}", relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)
        
        def search_iocs():
            """Filter IOCs based on search term."""
            search_term = search_var.get().lower()
            for item in tree.get_children():
                values = [v.lower() for v in tree.item(item)['values']]
                if any(search_term in str(v) for v in values):
                    tree.attach(item, '', 0)  # Move to top if matches
                
        search_entry.bind('<Return>', lambda e: search_iocs())
        ttk.Button(toolbar, text="Search", command=search_iocs).pack(side=tk.LEFT, padx=5)
        
        # Simulate loading IOCs (in a real app, this would come from the feed manager)
        def load_iocs():
            """Load IOCs into the treeview."""
            try:
                # Simulate loading delay
                dialog.config(cursor="watch")
                dialog.update()
                
                # Clear existing items
                for item in tree.get_children():
                    tree.delete(item)
                
                # Simulate sample IOCs based on feed type
                now = datetime.now()
                sample_iocs = []
                
                if "IP" in feed_type:
                    sample_iocs = [
                        ("192.168.1.1", "IPv4", "2023-01-01 10:00:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                        ("10.0.0.5", "IPv4", "2023-01-02 14:30:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                        ("2001:db8::1", "IPv6", "2023-01-03 09:15:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                    ]
                elif "Domain" in feed_type:
                    sample_iocs = [
                        ("example.com", "Domain", "2023-01-01 10:00:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                        ("malware.example.org", "Domain", "2023-01-02 14:30:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                        ("suspicious-site.net", "Domain", "2023-01-03 09:15:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                    ]
                else:
                    sample_iocs = [
                        ("https://example.com/malware.exe", "URL", "2023-01-01 10:00:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                        ("a1b2c3d4e5f6...", "File Hash", "2023-01-02 14:30:00", now.strftime("%Y-%m-%d %H:%M:%S"), feed_name),
                    ]
                
                # Add IOCs to the treeview
                for ioc in sample_iocs:
                    tree.insert("", tk.END, values=ioc)
                
                status.config(text=f"Showing {len(sample_iocs)} IOCs from {feed_name}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load IOCs: {str(e)}")
            finally:
                dialog.config(cursor="")
        
        # Load IOCs in a separate thread to keep the UI responsive
        threading.Thread(target=load_iocs, daemon=True).start()
    
    def add_threat_feed(self):
        """Open a dialog to add a new threat feed."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Threat Feed")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        ttk.Label(dialog, text="Feed Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        name_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=name_var, width=50).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Feed URL:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        url_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=url_var, width=50).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Feed Type:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        type_var = tk.StringVar(value="IP")
        ttk.Combobox(dialog, textvariable=type_var, values=["IP", "Domain", "URL", "Hash"], state="readonly").grid(
            row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="API Key (if required):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        api_key_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=api_key_var, width=50, show="*").grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Enable feed", variable=enabled_var).grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        def save_feed():
            """Save the new feed and update the UI."""
            name = name_var.get().strip()
            url = url_var.get().strip()
            feed_type = type_var.get()
            api_key = api_key_var.get().strip()
            
            if not name or not url:
                messagebox.showerror("Error", "Name and URL are required fields")
                return
                
            try:
                # In a real app, this would save to a config file or database
                # For now, just add to the treeview
                self.feeds_tree.insert(
                    "", 
                    tk.END, 
                    values=(
                        name,
                        url,
                        feed_type,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        0,  # Initial IOC count
                        enabled_var.get()
                    )
                )
                messagebox.showinfo("Success", f"Added feed: {name}")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add feed: {str(e)}")
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_feed).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def load_sample_feeds(self):
        """Load sample threat feeds for demonstration."""
        if not hasattr(self, 'feeds_tree'):
            return
            
        try:
            # Clear existing feeds
            for item in self.feeds_tree.get_children():
                self.feeds_tree.delete(item)
                
            # Sample threat feeds
            sample_feeds = [
                ("AbuseIPDB", "https://api.abuseipdb.com/api/v2/blacklist", "IP", "2023-01-01 12:00:00", 1250, True),
                ("AlienVault OTX", "https://otx.alienvault.com/api/v1/indicators/export", "IP/Domain", "2023-01-01 12:05:00", 850, True),
                ("FireHOL", "https://iplists.firehol.org/files/firehol_level1.netset", "IP", "2023-01-01 11:30:00", 5000, True),
                ("Malware Domain List", "https://www.malwaredomainlist.com/hostslist/ip.txt", "Domain", "2023-01-01 10:15:00", 320, False),
            ]
            
            for feed in sample_feeds:
                self.feeds_tree.insert("", tk.END, values=feed)
                
            logger.info(f"Loaded {len(sample_feeds)} sample threat feeds")
            
        except Exception as e:
            logger.error(f"Error loading sample feeds: {e}")
            messagebox.showerror("Error", f"Failed to load sample feeds: {str(e)}")
    
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
    try:
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('nips_gui.log')
            ]
        )
        logger = logging.getLogger('nips.gui')
        
        logger.info("Starting NIPS GUI application")
        
        # Create the main window
        root = tk.Tk()
        logger.debug("Main window created")
        
        # Create the application
        app = NIPSGUI(root)
        logger.debug("NIPSGUI instance created")
        
        # Start the main event loop
        logger.info("Starting main event loop")
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Fatal error in NIPS GUI: {e}", exc_info=True)
        messagebox.showerror("Fatal Error", 
            f"A fatal error occurred: {str(e)}\n\nCheck nips_gui.log for details.")
    finally:
        logger.info("NIPS GUI application terminated")

if __name__ == "__main__":
    main()
