"""
SIEM GUI - Security Information and Event Management

A modern, modular GUI for the SIEM system with enhanced features and improved user experience.
"""

# Constants
MAX_EVENTS = 10000  # Maximum number of events to keep in memory
ALERT_RETENTION_DAYS = 30  # Days to retain alerts
EVENT_RETENTION_DAYS = 90  # Days to retain events
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog, font as tkfont
from typing import Dict, List, Any, Optional, Tuple, Callable, Union, Set
import queue
import random
import threading
import time
import os
import sys
import json
import yaml
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from enum import Enum
import re
import hashlib
import uuid
import psutil
import numpy as np
from collections import deque, defaultdict, Counter
import pandas as pd

# Import SIEM components with better error handling

# Define basic implementations for missing components
class CorrelationEngine:
    """Basic implementation of the correlation engine."""
    def __init__(self):
        self.rules = []
        
    def add_rule(self, rule):
        self.rules.append(rule)
        
    def process_event(self, event):
        pass

class UEBAAnalyzer:
    """Basic implementation of UEBA analyzer."""
    def __init__(self):
        self.profiles = {}
        
    def update_profile(self, user, behavior):
        if user not in self.profiles:
            self.profiles[user] = {}
        self.profiles[user].update(behavior)
        
    def detect_anomalies(self, user_behavior):
        return {}

class ForensicsCollector:
    """Basic implementation of forensics collector."""
    def collect(self, event):
        return {}
        
class ReportGenerator:
    """Basic implementation of report generator."""
    def generate_report(self, data, report_type):
        return f"Generated {report_type} report"

class TimeSeriesDB:
    """Basic implementation of time series database."""
    def __init__(self):
        self.data = {}
        
    def insert(self, metric, value, timestamp=None):
        if metric not in self.data:
            self.data[metric] = []
        self.data[metric].append((timestamp or datetime.now(), value))

class ImportErrorHandler:
    def __init__(self):
        self.missing_modules = set()
    
    def import_module(self, module_path: str, class_name: str = None) -> Any:
        """Import a module or class with graceful error handling."""
        try:
            module = __import__(module_path, fromlist=[class_name] if class_name else None)
            return getattr(module, class_name) if class_name else module
        except ImportError as e:
            self.missing_modules.add(module_path.split('.')[0])
            logger.warning(f"Failed to import {module_path}: {e}")
            return None

# Initialize import handler
import_handler = ImportErrorHandler()

# Try to import SIEM components
DetectionEngine = import_handler.import_module('siem.detection.engine', 'DetectionEngine')
ResponseEngine = import_handler.import_module('siem.response.engine', 'ResponseEngine')
HistoricalAnalyzer = import_handler.import_module('siem.analytics.historical_analyzer', 'HistoricalAnalyzer')
MonitoringService = import_handler.import_module('siem.monitoring', 'MonitoringService')
CollectorManager = import_handler.import_module('siem.collectors.manager', 'CollectorManager')
ComplianceManager = import_handler.import_module('siem.compliance.manager', 'ComplianceManager')

# Constants
CONFIG_FILE = Path(__file__).parent / 'config' / 'gui_config.yaml'
DEFAULT_CONFIG = {
    'ui': {
        'theme': 'dark',
        'font_family': 'Segoe UI',
        'font_size': 10,
        'window_width': 1400,
        'window_height': 900,
        'min_width': 1200,
        'min_height': 700,
        'refresh_interval': 5000
    },
    'logging': {
        'level': 'INFO',
        'file': 'logs/siem_gui.log',
        'max_size': 10485760,  # 10MB
        'backup_count': 5
    }
}

# Configure logging with rotation
def setup_logging(config: Dict) -> None:
    """Configure logging with rotation and proper formatting."""
    log_file = Path(config['logging']['file'])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Clear existing handlers
    for handler in logging.root.handlers[:]:
        handler.close()
        logging.root.removeHandler(handler)
    
    # Set up file handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config['logging']['max_size'],
        backupCount=config['logging']['backup_count'],
        encoding='utf-8'
    )
    
    # Set up console handler
    console_handler = logging.StreamHandler()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Set formatter for handlers
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Get log level
    log_level = getattr(logging, config['logging']['level'].upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, console_handler]
    )
    
    # Set log level for other loggers
    logging.getLogger('PIL').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

# Load configuration
def load_config() -> Dict:
    """Load configuration from YAML file or create default."""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                config = yaml.safe_load(f) or {}
            # Merge with default config
            return {**DEFAULT_CONFIG, **config}
    except Exception as e:
        logger.error(f"Error loading config file: {e}")
    
    # Create default config directory and file
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
    
    return DEFAULT_CONFIG

# Initialize config and logging
config = load_config()
setup_logging(config)
logger = logging.getLogger('siem.gui')

# Theme colors
themes = {
    'dark': {
        'bg': '#2d2d2d',
        'fg': '#ffffff',
        'accent': '#3498db',
        'success': '#2ecc71',
        'warning': '#f39c12',
        'error': '#e74c3c',
        'bg_secondary': '#3d3d3d',
        'fg_secondary': '#cccccc',
        'border': '#4a4a4a'
    },
    'light': {
        'bg': '#ffffff',
        'fg': '#333333',
        'accent': '#2980b9',
        'success': '#27ae60',
        'warning': '#d35400',
        'error': '#c0392b',
        'bg_secondary': '#f5f5f5',
        'fg_secondary': '#666666',
        'border': '#dddddd'
    }
}

class SIEMGUI:
    """Enhanced SIEM GUI application with advanced security features."""
    
    def load_configuration(self):
        """Load configuration from file or use defaults."""
        self.config = {
            'ui': {
                'theme': 'dark',
                'refresh_interval': 5000,
                'max_events': 10000
            },
            'alerts': {
                'enabled': True,
                'sound': True,
                'email_notifications': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'siem_gui.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5
            }
        }
        
    def load_correlation_rules(self):
        """Load correlation rules from configuration."""
        self.correlation_rules = [
            {
                'name': 'Multiple Failed Logins',
                'description': 'Triggered after multiple failed login attempts',
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'severity': 'high'
            },
            {
                'name': 'Port Scan Detection',
                'description': 'Detects potential port scanning activity',
                'threshold': 10,
                'time_window': 60,  # 1 minute
                'severity': 'medium'
            }
        ]
        
    def load_compliance_templates(self):
        """Load compliance templates."""
        self.compliance_templates = {
            'pci_dss': 'Payment Card Industry Data Security Standard',
            'gdpr': 'General Data Protection Regulation',
            'hipaa': 'Health Insurance Portability and Accountability Act'
        }
        
    def init_data_retention(self):
        """Initialize data retention policies."""
        self.retention_policies = {
            'events': {
                'days': 90,
                'max_size_gb': 10
            },
            'alerts': {
                'days': 365,
                'max_size_gb': 5
            },
            'logs': {
                'days': 30,
                'max_size_gb': 1
            }
        }
        
    def start_background_services(self):
        """Start background services and threads."""
        self.running = True
        self.background_thread = threading.Thread(target=self._background_worker, daemon=True)
        self.background_thread.start()
        
    def start_monitoring(self):
        """Start the monitoring service."""
        if not hasattr(self, 'monitoring_thread') or not self.monitoring_thread.is_alive():
            self.running = True
            self.monitoring_thread = threading.Thread(target=self.run_monitoring, daemon=True)
            self.monitoring_thread.start()
            logger.info("Monitoring started")
    
    def stop_monitoring(self):
        """Stop the monitoring service."""
        self.running = False
        if hasattr(self, 'monitoring_thread') and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2.0)
        logger.info("Monitoring stopped")
    
    def run_monitoring(self):
        """Run the monitoring loop in a separate thread."""
        while self.running:
            try:
                # Check for new events
                if not self.event_queue.empty():
                    event = self.event_queue.get_nowait()
                    self.process_event(event)
                
                # Check for alerts
                if not self.alert_queue.empty():
                    alert = self.alert_queue.get_nowait()
                    self.process_alert(alert)
                
                # Sleep to prevent high CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in monitoring thread: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on error
    
    def _background_worker(self):
        """Background worker thread for processing events and updates."""
        while self.running:
            try:
                # Process queued events
                if not self.event_queue.empty():
                    event = self.event_queue.get()
                    self._process_event(event)
                    
                # Process UI updates
                if not self.ui_update_queue.empty():
                    update_func = self.ui_update_queue.get()
                    self.root.after(0, update_func)
                    
                time.sleep(0.1)  # Small delay to prevent high CPU usage
                
            except Exception as e:
                logger.error(f"Error in background worker: {e}")
                time.sleep(1)  # Prevent tight loop on error
    
    def _process_event(self, event):
        """Process a single event through the correlation engine."""
        try:
            # Add event to time series database
            self.tsdb.insert('events', event)
            
            # Process through correlation engine
            self.correlation_engine.process_event(event)
            
            # Update UEBA profiles
            if 'user' in event:
                self.ueba_analyzer.update_profile(event['user'], event)
                
            # Check for anomalies
            anomalies = self.ueba_analyzer.detect_anomalies(event)
            if anomalies:
                self._handle_anomalies(anomalies, event)
                
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def _handle_anomalies(self, anomalies, event):
        """Handle detected anomalies."""
        for anomaly_type, details in anomalies.items():
            alert = {
                'timestamp': datetime.now().isoformat(),
                'type': 'anomaly',
                'severity': details.get('severity', 'medium'),
                'source': event.get('source', 'unknown'),
                'message': f"Anomaly detected: {anomaly_type}",
                'details': details
            }
            self.alert_queue.put(alert)
            
    def toggle_sidebar(self):
        """Toggle the visibility of the sidebar."""
        if hasattr(self, 'sidebar_visible'):
            self.sidebar_visible = not self.sidebar_visible
        else:
            self.sidebar_visible = True
            
        if hasattr(self, 'sidebar'):
            if self.sidebar_visible:
                self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
            else:
                self.sidebar.pack_forget()
                
    def toggle_theme(self):
        """Toggle between light and dark theme."""
        if not hasattr(self, 'current_theme'):
            self.current_theme = 'dark'
            
        # Toggle between light and dark themes
        if self.current_theme == 'dark':
            self.apply_theme('light')
            self.current_theme = 'light'
        else:
            self.apply_theme('dark')
            self.current_theme = 'dark'
            
    def open_rule_manager(self):
        """Open the rule management dialog."""
        try:
            # Create a new top-level window
            rule_window = tk.Toplevel(self.root)
            rule_window.title("Rule Manager")
            rule_window.geometry("800x600")
            
            # Create a frame for the rule list
            rule_frame = ttk.Frame(rule_window)
            rule_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Add a treeview to display rules
            columns = ('name', 'description', 'severity', 'enabled')
            tree = ttk.Treeview(rule_frame, columns=columns, show='headings')
            
            # Define column headings
            tree.heading('name', text='Rule Name')
            tree.heading('description', text='Description')
            tree.heading('severity', text='Severity')
            tree.heading('enabled', text='Enabled')
            
            # Set column widths
            tree.column('name', width=200)
            tree.column('description', width=400)
            tree.column('severity', width=100, anchor=tk.CENTER)
            tree.column('enabled', width=80, anchor=tk.CENTER)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(rule_frame, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscroll=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Add sample rules (in a real app, these would come from configuration)
            sample_rules = [
                ('Failed Login', 'Multiple failed login attempts', 'High', 'Yes'),
                ('Port Scan', 'Multiple connection attempts to different ports', 'High', 'Yes'),
                ('Data Exfiltration', 'Large data transfer to external IP', 'Critical', 'Yes'),
                ('Malware Detection', 'Known malware signature detected', 'Critical', 'Yes'),
                ('Unauthorized Access', 'Access to restricted resources', 'Medium', 'Yes')
            ]
            
            for rule in sample_rules:
                tree.insert('', tk.END, values=rule)
                
            # Add buttons for rule management
            button_frame = ttk.Frame(rule_window)
            button_frame.pack(fill=tk.X, padx=10, pady=5)
            
            add_btn = ttk.Button(button_frame, text="Add Rule", command=self.add_rule)
            edit_btn = ttk.Button(button_frame, text="Edit Rule", command=lambda: self.edit_rule(tree))
            delete_btn = ttk.Button(button_frame, text="Delete Rule", command=lambda: self.delete_rule(tree))
            
            add_btn.pack(side=tk.LEFT, padx=5)
            edit_btn.pack(side=tk.LEFT, padx=5)
            delete_btn.pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open rule manager: {str(e)}")
            logger.error(f"Error in open_rule_manager: {e}", exc_info=True)
            
    def add_rule(self):
        """Add a new rule."""
        # This would open a dialog to add a new rule
        messagebox.showinfo("Info", "Add Rule functionality would go here")
        
    def edit_rule(self, tree):
        """Edit the selected rule."""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
            
        # This would open a dialog to edit the selected rule
        messagebox.showinfo("Info", f"Edit Rule {selected[0]} functionality would go here")
        
    def delete_rule(self, tree):
        """Delete the selected rule."""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to delete the selected rule?"):
            for item in selected:
                tree.delete(item)
                
    def open_compliance_dashboard(self):
        """Open the compliance dashboard."""
        try:
            # Create a new top-level window for the compliance dashboard
            dashboard = tk.Toplevel(self.root)
            dashboard.title("Compliance Dashboard")
            dashboard.geometry("1000x700")
            
            # Create a notebook for different compliance frameworks
            notebook = ttk.Notebook(dashboard)
            
            # Add tabs for different compliance frameworks
            frameworks = ["PCI DSS", "GDPR", "HIPAA", "NIST"]
            
            for framework in frameworks:
                frame = ttk.Frame(notebook)
                notebook.add(frame, text=framework)
                
                # Add a treeview to display compliance requirements
                columns = ('requirement', 'status', 'last_checked', 'issues')
                tree = ttk.Treeview(frame, columns=columns, show='headings')
                
                # Define column headings
                tree.heading('requirement', text='Requirement')
                tree.heading('status', text='Status')
                tree.heading('last_checked', text='Last Checked')
                tree.heading('issues', text='Issues')
                
                # Set column widths
                tree.column('requirement', width=400)
                tree.column('status', width=100, anchor=tk.CENTER)
                tree.column('last_checked', width=150, anchor=tk.CENTER)
                tree.column('issues', width=100, anchor=tk.CENTER)
                
                # Add sample data (in a real app, this would come from your compliance checks)
                sample_data = [
                    ("Requirement 1.1: Firewall Configuration", "Compliant", "2025-08-28 12:00", "0"),
                    ("Requirement 1.2: Secure Configurations", "Non-Compliant", "2025-08-28 12:00", "3"),
                    ("Requirement 2.1: Vendor Defaults", "Compliant", "2025-08-28 12:00", "0"),
                    ("Requirement 3.1: Protect Stored Data", "Partially Compliant", "2025-08-27 12:00", "1"),
                    ("Requirement 3.2: Encrypt Transmission", "Compliant", "2025-08-28 12:00", "0"),
                ]
                
                for item in sample_data:
                    tree.insert('', tk.END, values=item)
                
                # Add scrollbar
                scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
                tree.configure(yscroll=scrollbar.set)
                
                # Pack the tree and scrollbar
                tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                
                # Add a status bar
                status_frame = ttk.Frame(frame)
                status_frame.pack(fill=tk.X, pady=5)
                
                ttk.Label(status_frame, text="Last Scan: 2025-08-28 12:00").pack(side=tk.LEFT, padx=5)
                ttk.Label(status_frame, text="Overall Status:").pack(side=tk.LEFT, padx=5)
                ttk.Label(status_frame, text="75% Compliant", foreground="orange").pack(side=tk.LEFT)
                
                # Add buttons
                button_frame = ttk.Frame(frame)
                button_frame.pack(fill=tk.X, pady=5)
                
                ttk.Button(button_frame, text="Run Scan", 
                         command=lambda f=framework: self.run_compliance_scan(f)).pack(side=tk.LEFT, padx=5)
                ttk.Button(button_frame, text="Generate Report", 
                         command=lambda f=framework: self.generate_compliance_report(f)).pack(side=tk.LEFT, padx=5)
            
            # Pack the notebook
            notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add a main status bar
            main_status = ttk.Frame(dashboard)
            main_status.pack(fill=tk.X, pady=5)
            
            ttk.Label(main_status, text="Overall Compliance Status:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
            ttk.Label(main_status, text="75% Compliant", font=('Arial', 10, 'bold'), foreground="orange").pack(side=tk.LEFT)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open compliance dashboard: {str(e)}")
            logger.error(f"Error in open_compliance_dashboard: {e}", exc_info=True)
            
    def run_compliance_scan(self, framework):
        """Run a compliance scan for the specified framework."""
        # This would run the actual compliance checks
        messagebox.showinfo("Info", f"Running {framework} compliance scan...")
        logger.info(f"Started {framework} compliance scan")
        
    def generate_compliance_report(self, framework):
        """Generate a compliance report for the specified framework."""
        # This would generate a detailed compliance report
        messagebox.showinfo("Info", f"Generating {framework} compliance report...")
        logger.info(f"Generating {framework} compliance report")
        
    def open_forensics_toolkit(self):
        """Open the digital forensics toolkit."""
        try:
            # Create a new top-level window for the forensics toolkit
            toolkit = tk.Toplevel(self.root)
            toolkit.title("Digital Forensics Toolkit")
            toolkit.geometry("1200x800")
            
            # Create a notebook for different forensics tools
            notebook = ttk.Notebook(toolkit)
            
            # Memory Analysis Tab
            memory_frame = ttk.Frame(notebook)
            notebook.add(memory_frame, text="Memory Analysis")
            
            # Add memory analysis components
            ttk.Label(memory_frame, text="Memory Dump Analysis", font=('Arial', 12, 'bold')).pack(pady=5)
            
            # Memory dump file selection
            mem_frame = ttk.LabelFrame(memory_frame, text="Memory Dump")
            mem_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Button(mem_frame, text="Load Memory Dump...", 
                      command=lambda: self.load_memory_dump()).pack(side=tk.LEFT, padx=5, pady=5)
            
            # Process list
            proc_frame = ttk.LabelFrame(memory_frame, text="Running Processes")
            proc_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Treeview for processes
            columns = ('pid', 'name', 'path', 'user')
            proc_tree = ttk.Treeview(proc_frame, columns=columns, show='headings')
            
            # Define column headings
            proc_tree.heading('pid', text='PID')
            proc_tree.heading('name', text='Process Name')
            proc_tree.heading('path', text='Path')
            proc_tree.heading('user', text='User')
            
            # Set column widths
            proc_tree.column('pid', width=80, anchor=tk.CENTER)
            proc_tree.column('name', width=200)
            proc_tree.column('path', width=400)
            proc_tree.column('user', width=150)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(proc_frame, orient=tk.VERTICAL, command=proc_tree.yview)
            proc_tree.configure(yscroll=scrollbar.set)
            
            # Pack the tree and scrollbar
            proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Add sample processes (in a real app, this would come from the memory dump)
            sample_procs = [
                (1000, 'explorer.exe', 'C:\\Windows\\explorer.exe', 'SYSTEM'),
                (1234, 'chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'user1'),
                (2345, 'notepad.exe', 'C:\\Windows\\System32\\notepad.exe', 'user1'),
                (3456, 'svchost.exe', 'C:\\Windows\\System32\\svchost.exe', 'NETWORK SERVICE'),
                (4567, 'lsass.exe', 'C:\\Windows\\System32\\lsass.exe', 'SYSTEM'),
            ]
            
            for proc in sample_procs:
                proc_tree.insert('', tk.END, values=proc)
            
            # Network Analysis Tab
            net_frame = ttk.Frame(notebook)
            notebook.add(net_frame, text="Network Analysis")
            
            ttk.Label(net_frame, text="Network Connections", font=('Arial', 12, 'bold')).pack(pady=5)
            
            # Network connections treeview
            net_columns = ('proto', 'local', 'remote', 'state', 'pid', 'process')
            net_tree = ttk.Treeview(net_frame, columns=net_columns, show='headings')
            
            # Define column headings
            net_tree.heading('proto', text='Protocol')
            net_tree.heading('local', text='Local Address')
            net_tree.heading('remote', text='Remote Address')
            net_tree.heading('state', text='State')
            net_tree.heading('pid', text='PID')
            net_tree.heading('process', text='Process')
            
            # Set column widths
            net_tree.column('proto', width=80, anchor=tk.CENTER)
            net_tree.column('local', width=200)
            net_tree.column('remote', width=200)
            net_tree.column('state', width=100)
            net_tree.column('pid', width=80, anchor=tk.CENTER)
            net_tree.column('process', width=200)
            
            # Add scrollbar
            net_scrollbar = ttk.Scrollbar(net_frame, orient=tk.VERTICAL, command=net_tree.yview)
            net_tree.configure(yscroll=net_scrollbar.set)
            
            # Pack the tree and scrollbar
            net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            net_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Add sample network connections
            sample_conns = [
                ('TCP', '192.168.1.100:49678', '172.217.16.206:443', 'ESTABLISHED', 1234, 'chrome.exe'),
                ('TCP', '192.168.1.100:49679', '151.101.1.69:443', 'ESTABLISHED', 2345, 'firefox.exe'),
                ('TCP', '192.168.1.100:49680', '13.107.42.14:443', 'TIME_WAIT', 3456, 'teams.exe'),
                ('UDP', '192.168.1.100:53', '8.8.8.8:53', 'N/A', 4567, 'svchost.exe'),
            ]
            
            for conn in sample_conns:
                net_tree.insert('', tk.END, values=conn)
            
            # File Analysis Tab
            file_frame = ttk.Frame(notebook)
            notebook.add(file_frame, text="File Analysis")
            
            ttk.Label(file_frame, text="File System Analysis", font=('Arial', 12, 'bold')).pack(pady=5)
            
            # File system browser
            file_browser = ttk.Treeview(file_frame)
            file_browser.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add sample file system structure
            root_node = file_browser.insert('', 'end', text="C:\\", open=True)
            file_browser.insert(root_node, 'end', text="Windows")
            file_browser.insert(root_node, 'end', text="Program Files")
            file_browser.insert(root_node, 'end', text="Users")
            file_browser.insert(root_node, 'end', text="ProgramData")
            
            # File details frame
            details_frame = ttk.LabelFrame(file_frame, text="File Details")
            details_frame.pack(fill=tk.X, padx=5, pady=5)
            
            # File details
            ttk.Label(details_frame, text="Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(details_frame, text="Size:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(details_frame, text="Created:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(details_frame, text="Modified:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(details_frame, text="MD5:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(details_frame, text="SHA-1:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=2)
            
            # Pack the notebook
            notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add status bar
            status_bar = ttk.Frame(toolkit)
            status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=2)
            ttk.Label(status_bar, text="Ready", relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open forensics toolkit: {str(e)}")
            logger.error(f"Error in open_forensics_toolkit: {e}", exc_info=True)
    
    def load_memory_dump(self):
        """Load a memory dump file for analysis."""
        file_path = filedialog.askopenfilename(
            title="Select Memory Dump File",
            filetypes=[("Memory Dump Files", "*.dmp;*.raw;*.mem"), ("All Files", "*.*")]
        )
        
        if file_path:
            messagebox.showinfo("Info", f"Loading memory dump: {file_path}")
            # In a real application, this would load and parse the memory dump
            logger.info(f"Loading memory dump: {file_path}")
            
    def show_documentation(self):
        """Display the SIEM documentation in a new window."""
        try:
            # Create a new top-level window for documentation
            doc_window = tk.Toplevel(self.root)
            doc_window.title("SIEM Documentation")
            doc_window.geometry("1000x700")
            
            # Create a notebook for different documentation sections
            notebook = ttk.Notebook(doc_window)
            
            # Add tabs for different documentation sections
            sections = [
                ("Getting Started", self._create_getting_started_doc()),
                ("User Guide", self._create_user_guide_doc()),
                ("Rule Management", self._create_rule_management_doc()),
                ("Compliance", self._create_compliance_doc()),
                ("Forensics", self._create_forensics_doc()),
                ("Troubleshooting", self._create_troubleshooting_doc())
            ]
            
            for section_name, content in sections:
                frame = ttk.Frame(notebook)
                text = tk.Text(frame, wrap=tk.WORD, padx=10, pady=10, font=('Arial', 10))
                
                # Add content to the text widget
                text.insert(tk.END, content)
                text.config(state=tk.DISABLED)  # Make it read-only
                
                # Add scrollbar
                scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
                text.configure(yscrollcommand=scrollbar.set)
                
                # Pack the text and scrollbar
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                
                # Add the frame to the notebook
                notebook.add(frame, text=section_name)
            
            # Pack the notebook
            notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add a close button
            button_frame = ttk.Frame(doc_window)
            button_frame.pack(fill=tk.X, pady=5)
            ttk.Button(button_frame, text="Close", command=doc_window.destroy).pack(side=tk.RIGHT, padx=10)
            
            # Set focus to the window
            doc_window.focus_set()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open documentation: {str(e)}")
            logger.error(f"Error in show_documentation: {e}", exc_info=True)
    
    def _create_getting_started_doc(self):
        """Create content for the Getting Started documentation."""
        return """Welcome to Security Ops Center SIEM

1. Overview
   The Security Ops Center SIEM provides comprehensive security information and event management capabilities.
   It helps you monitor, detect, and respond to security threats in real-time.

2. System Requirements
   - Python 3.8 or higher
   - 8GB RAM minimum (16GB recommended)
   - 100MB free disk space for logs and configuration

3. First Steps
   - Configure your data sources in Settings > Data Sources
   - Review and enable detection rules in the Rule Manager
   - Set up alerts and notifications
   - Explore the dashboard for an overview of your security posture

4. Getting Help
   - Press F1 in any window for context-sensitive help
   - Visit our online documentation at [URL]
   - Contact support@securityops.center for assistance
"""

    def _create_user_guide_doc(self):
        """Create content for the User Guide documentation."""
        return """User Guide

1. Dashboard
   The dashboard provides an overview of your security posture, including:
   - Real-time event monitoring
   - Alert status and severity levels
   - Top security events and threats
   - System health and performance metrics

2. Alerts
   - View and manage security alerts
   - Filter and search alerts by severity, status, and time
   - Acknowledge, close, or escalate alerts

3. Events
   - Search and analyze security events
   - Apply filters and save custom views
   - Export event data for further analysis

4. Detection
   - View and manage detection rules
   - Tune rules to reduce false positives
   - Create custom detection rules
"""

    def _create_rule_management_doc(self):
        """Create content for the Rule Management documentation."""
        return """Rule Management

1. Rule Types
   - Correlation Rules: Detect patterns across multiple events
   - Threshold Rules: Trigger on event counts
   - Anomaly Rules: Identify unusual behavior
   - Compliance Rules: Enforce security policies

2. Creating Rules
   - Use the Rule Wizard for guided rule creation
   - Define conditions using the rule builder
   - Test rules before enabling them in production

3. Best Practices
   - Start with a few critical rules and expand gradually
   - Document the purpose of each rule
   - Review and tune rules regularly
   - Test rules in a staging environment first
"""

    def _create_compliance_doc(self):
        """Create content for the Compliance documentation."""
        return """Compliance Management

1. Supported Standards
   - PCI DSS
   - GDPR
   - HIPAA
   - NIST
   - ISO 27001

2. Compliance Dashboard
   - View compliance status across frameworks
   - Identify gaps and areas for improvement
   - Generate compliance reports

3. Automated Controls
   - Continuous compliance monitoring
   - Automated evidence collection
   - Audit trail and change tracking
"""

    def _create_forensics_doc(self):
        """Create content for the Forensics documentation."""
        return """Digital Forensics Toolkit

1. Memory Analysis
   - Analyze running processes and memory dumps
   - Detect suspicious activities and malware
   - Extract artifacts for investigation

2. Network Analysis
   - Monitor network connections
   - Detect suspicious network traffic
   - Analyze packet captures

3. File Analysis
   - Examine file system artifacts
   - Calculate file hashes
   - Search for indicators of compromise
"""

    def _create_troubleshooting_doc(self):
        """Create content for the Troubleshooting documentation."""
        return """Troubleshooting

1. Common Issues
   - No events appearing: Check data source connections
   - High CPU usage: Review rule performance
   - Missing logs: Verify log forwarding configuration

2. Logs and Diagnostics
   - Access system logs in the Logs tab
   - Enable debug logging in Settings > Logging
   - Generate diagnostic bundle for support

3. Getting Help
   - Check the Knowledge Base
   - Contact support@securityops.center
   - Include relevant logs and screenshots

4. Known Issues
   - [List any known issues and workarounds]
"""
        
    def show_about(self):
        """Display the About dialog with version and copyright information."""
        try:
            about_window = tk.Toplevel(self.root)
            about_window.title("About Security Ops Center SIEM")
            about_window.geometry("500x400")
            about_window.resizable(False, False)
            
            # Center the window
            window_width = 500
            window_height = 400
            screen_width = about_window.winfo_screenwidth()
            screen_height = about_window.winfo_screenheight()
            x = (screen_width // 2) - (window_width // 2)
            y = (screen_height // 2) - (window_height // 2)
            about_window.geometry(f'{window_width}x{window_height}+{x}+{y}')
            
            # Add application icon/logo (placeholder)
            logo_frame = ttk.Frame(about_window)
            logo_frame.pack(pady=20)
            
            # You can add an actual logo image here if available
            # logo = tk.PhotoImage(file="logo.png")
            # logo_label = ttk.Label(logo_frame, image=logo)
            # logo_label.image = logo  # Keep a reference
            # logo_label.pack()
            
            # Add application title
            title_label = ttk.Label(
                logo_frame, 
                text="Security Ops Center SIEM", 
                font=('Arial', 16, 'bold')
            )
            title_label.pack(pady=10)
            
            # Version info
            version_label = ttk.Label(about_window, text="Version 1.0.0")
            version_label.pack(pady=5)
            
            # Copyright info
            copyright_label = ttk.Label(
                about_window, 
                text="© 2025 Security Ops Center. All rights reserved.",
                font=('Arial', 8)
            )
            copyright_label.pack(pady=5)
            
            # Description
            desc_frame = ttk.LabelFrame(about_window, text="About")
            desc_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            description = (
                "Security Ops Center SIEM is a comprehensive security information "
                "and event management solution designed to help organizations "
                "monitor, detect, and respond to security threats in real-time."
                "\n\n"
                "This software is part of the Security Ops Center platform, "
                "providing advanced security monitoring, threat detection, "
                "and compliance management capabilities."
            )
            
            desc_text = tk.Text(
                desc_frame, 
                wrap=tk.WORD, 
                height=8,
                padx=10, 
                pady=10,
                font=('Arial', 9)
            )
            desc_text.insert(tk.END, description)
            desc_text.config(state=tk.DISABLED)
            desc_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # System information
            sys_frame = ttk.LabelFrame(about_window, text="System Information")
            sys_frame.pack(fill=tk.X, padx=20, pady=5)
            
            sys_info = [
                ("Python Version:", sys.version.split(' ')[0]),
                ("Platform:", platform.platform()),
                ("System:", platform.system() + " " + platform.release()),
                ("Processor:", platform.processor() or "Unknown")
            ]
            
            for i, (label, value) in enumerate(sys_info):
                ttk.Label(sys_frame, text=label, font=('Arial', 8, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
                ttk.Label(sys_frame, text=value, font=('Arial', 8)).grid(row=i, column=1, sticky=tk.W, padx=5, pady=2)
            
            # Close button
            button_frame = ttk.Frame(about_window)
            button_frame.pack(pady=10)
            
            ttk.Button(
                button_frame, 
                text="OK", 
                command=about_window.destroy,
                width=10
            ).pack(pady=5)
            
            # Make the window modal
            about_window.transient(self.root)
            about_window.grab_set()
            
            # Set focus to the window
            about_window.focus_set()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show about dialog: {str(e)}")
            logger.error(f"Error in show_about: {e}", exc_info=True)
                
    def backup_config(self):
        """Backup the current configuration to a file."""
        try:
            # Get the current time for the filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"siem_backup_{timestamp}.json"
            
            # Ask user for file location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=default_filename
            )
            
            if not file_path:
                return  # User cancelled
                
            # Prepare configuration data to save
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'config': self.config,
                'correlation_rules': self.correlation_rules,
                'compliance_templates': self.compliance_templates,
                'retention_policies': self.retention_policies
            }
            
            # Save to file
            with open(file_path, 'w') as f:
                json.dump(backup_data, f, indent=4)
            
            messagebox.showinfo("Backup Successful", f"Configuration backed up to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Backup Error", f"Failed to backup configuration: {str(e)}")
            logger.error(f"Error backing up configuration: {e}", exc_info=True)
            
    def export_report(self):
        """Export the current report to a file."""
        try:
            # Get the current time for the filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"siem_report_{timestamp}.pdf"
            
            # Ask user for file location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                initialfile=default_filename
            )
            
            if not file_path:
                return  # User cancelled
                
            # Generate the report content
            report_data = {
                'title': 'SIEM Security Report',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'total_events': len(self.events),
                    'alerts_by_severity': dict(Counter(alert['severity'] for alert in self.alerts)),
                    'incidents': len(self.incidents)
                },
                'alerts': list(self.alerts)[-100:],  # Last 100 alerts
                'incidents': self.incidents[-50:],   # Last 50 incidents
            }
            
            # Convert to PDF (simplified example - in a real app, use a proper PDF library)
            with open(file_path, 'w') as f:
                f.write(f"SIEM Security Report\n")
                f.write(f"Generated on: {report_data['timestamp']}\n\n")
                f.write("Summary:\n")
                f.write(f"- Total events: {report_data['summary']['total_events']}\n")
                f.write(f"- Alerts by severity: {report_data['summary']['alerts_by_severity']}\n")
                f.write(f"- Open incidents: {report_data['summary']['incidents']}\n\n")
                
                f.write("Recent Alerts:\n")
                for alert in report_data['alerts']:
                    f.write(f"- [{alert['timestamp']}] {alert['severity'].upper()}: {alert['message']}\n")
            
            messagebox.showinfo("Export Successful", f"Report exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
            logger.error(f"Error exporting report: {e}", exc_info=True)
    
    def __init__(self, root):
        """Initialize the enhanced SIEM GUI with all components."""
        self.root = root
        self.root.title("Advanced Security Information and Event Management")
        self.root.geometry("1600x1000")
        self.root.minsize(1400, 800)
        
        # Initialize refresh interval with default value
        self.refresh_interval = 5000  # Default value, will be updated from config
        self.refresh_interval_var = tk.IntVar(value=self.refresh_interval)
        
        # Initialize style before any UI elements
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Initialize SIEM core components
        self.detection_engine = DetectionEngine()
        self.response_engine = ResponseEngine()
        self.historical_analyzer = HistoricalAnalyzer()
        self.monitoring = MonitoringService({
            'interval': 30,  # More frequent updates for real-time monitoring
            'metrics': ['cpu', 'memory', 'disk', 'network', 'processes']
        })
        
        # Initialize enhanced components
        self.correlation_engine = CorrelationEngine()
        self.ueba_analyzer = UEBAAnalyzer()
        self.forensics_collector = ForensicsCollector()
        self.report_generator = ReportGenerator()
        self.tsdb = TimeSeriesDB()
        
        # Initialize managers
        self.collector_manager = CollectorManager()
        self.compliance_manager = ComplianceManager()
        
        # Data storage
        self.events = deque(maxlen=MAX_EVENTS)
        self.alerts = deque(maxlen=MAX_EVENTS // 2)
        self.event_data = {}  # Dictionary to store raw event data
        
        # Set window icon if available
        try:
            self.root.iconbitmap("assets/icon.ico")
        except:
            pass  # Icon not found, use default
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.root.configure(bg=themes[config['ui']['theme']]['bg'])
        
        # Create menu bar
        self.setup_menu()
        
        # Create main container
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left sidebar for navigation
        self.sidebar = ttk.Frame(self.main_container, width=200, relief=tk.SUNKEN, padding="5")
        self.main_container.add(self.sidebar, weight=0)
        
        # Main content area with notebook
        self.setup_main_content()
        
        # Setup status bar
        self.setup_status_bar()
        
        # Tooltips
        self.setup_tooltips()
        
        # Set up periodic updates
        self.setup_periodic_updates()
    
    def setup_status_bar(self):
        """Set up the status bar at the bottom of the window."""
        # Create status bar frame
        self.status_frame = ttk.Frame(self.root, relief=tk.SUNKEN)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status message
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(
            self.status_frame, 
            textvariable=self.status_var,
            anchor=tk.W,
            padding=(5, 2, 5, 2)
        )
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Version info
        version_label = ttk.Label(
            self.status_frame,
            text="SIEM v1.0.0",
            anchor=tk.E,
            padding=(5, 2, 5, 2)
        )
        version_label.pack(side=tk.RIGHT)
        
    def setup_tooltips(self):
        """Set up tooltips for UI elements."""
        # This is a placeholder for tooltip functionality
        # In a real implementation, you would use a tooltip library or implement hover effects
        pass
        
    def setup_periodic_updates(self):
        """Set up periodic updates for the UI."""
        # Update metrics
        self.update_metrics()
        
        # Update alerts
        self.update_alerts()
        
        # Update events
        self.update_events()
        
        # Schedule the next update
        self.root.after(self.refresh_interval, self.setup_periodic_updates)
    
    def setup_menu(self):
        """Set up the main menu bar."""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_command(label="Backup Configuration", command=self.backup_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_checkbutton(label="Show Sidebar", variable=tk.BooleanVar(value=True), command=self.toggle_sidebar)
        view_menu.add_checkbutton(label="Dark Mode", variable=tk.BooleanVar(value=True), command=self.toggle_theme)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Rule Manager", command=self.open_rule_manager)
        tools_menu.add_command(label="Compliance Dashboard", command=self.open_compliance_dashboard)
        tools_menu.add_command(label="Forensics Toolkit", command=self.open_forensics_toolkit)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_sidebar(self):
        """Set up the sidebar navigation."""
        self.sidebar = ttk.Frame(self.main_container, width=200, style='Sidebar.TFrame')
        
        # Dashboard button
        btn_dashboard = ttk.Button(
            self.sidebar, 
            text="Dashboard", 
            command=lambda: self.show_tab('dashboard'),
            style='Sidebar.TButton'
        )
        btn_dashboard.pack(fill=tk.X, padx=5, pady=2)
        
        # Real-Time Monitoring button
        btn_monitoring = ttk.Button(
            self.sidebar, 
            text="Real-Time Monitoring", 
            command=lambda: self.show_tab('monitoring'),
            style='Sidebar.TButton'
        )
        btn_monitoring.pack(fill=tk.X, padx=5, pady=2)
        
        # Add more sidebar buttons for other features
        buttons = [
            ("Threat Detection", 'threat'),
            ("Incident Response", 'incidents'),
            ("Compliance", 'compliance'),
            ("UEBA", 'ueba'),
            ("Reports", 'reports'),
            ("Settings", 'settings')
        ]
        
        for text, tab in buttons:
            btn = ttk.Button(
                self.sidebar, 
                text=text, 
                command=lambda t=tab: self.show_tab(t),
                style='Sidebar.TButton'
            )
            btn.pack(fill=tk.X, padx=5, pady=2)
        
        self.main_container.add(self.sidebar, weight=0)
    
    def setup_main_content(self):
        """Set up the main content area with tabs."""
        # Create a frame to hold the notebook
        content_frame = ttk.Frame(self.main_container)
        self.main_container.add(content_frame, weight=1)
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_monitoring_tab()
        self.setup_threat_detection_tab()
        self.setup_incident_response_tab()
        self.setup_compliance_tab()
        self.setup_ueba_tab()
        self.setup_reports_tab()
        self.setup_settings_tab()
    
    def create_pie_chart(self, parent, data=None):
        """Create a simple pie chart using Tkinter Canvas.
        
        Args:
            parent: Parent widget
            data: List of (value, label, color) tuples
            
        Returns:
            Canvas widget with the pie chart
        """
        if data is None:
            data = [
                (45, 'High', '#ff6b6b'),
                (30, 'Medium', '#ffd166'),
                (20, 'Low', '#06d6a0'),
                (5, 'Info', '#118ab2')
            ]
            
        canvas = tk.Canvas(parent, bg='white', height=300)
        width = 300
        height = 300
        
        # Draw pie chart
        start = 0
        for value, label, color in data:
            extent = 360 * value / 100
            canvas.create_arc(10, 10, width-10, height-10, 
                            start=start, extent=extent, 
                            fill=color, outline='')
            start += extent
            
        # Add legend
        y_offset = 20
        for value, label, color in data:
            canvas.create_rectangle(width + 10, y_offset, width + 30, y_offset + 15, 
                                  fill=color, outline='')
            canvas.create_text(width + 40, y_offset + 7, anchor=tk.W, 
                             text=f"{label} ({value}%)")
            y_offset += 20
            
        return canvas
        
    def create_line_chart(self, parent, data=None):
        """Create a simple line chart using Tkinter Canvas.
        
        Args:
            parent: Parent widget
            data: List of (x, y) values
            
        Returns:
            Canvas widget with the line chart
        """
        if data is None:
            # Sample data if none provided
            data = [(i, random.randint(10, 100)) for i in range(10)]
            
        canvas = tk.Canvas(parent, bg='white', height=300)
        width = 400
        height = 300
        padding = 40
        
        # Draw axes
        canvas.create_line(padding, height - padding, width - padding, height - padding, width=2)  # X-axis
        canvas.create_line(padding, padding, padding, height - padding, width=2)  # Y-axis
        
        # Add labels
        canvas.create_text(width // 2, height - 10, text="Time")
        canvas.create_text(10, height // 2, text="Count", angle=90)
        
        # Calculate scaling factors
        max_y = max(y for x, y in data) if data else 100
        x_scale = (width - 2 * padding) / (len(data) - 1) if len(data) > 1 else 1
        y_scale = (height - 2 * padding) / max_y if max_y > 0 else 1
        
        # Draw data points and lines
        points = []
        for i, (x, y) in enumerate(data):
            x_pos = padding + i * x_scale
            y_pos = height - padding - y * y_scale
            points.extend([x_pos, y_pos])
            
            # Draw point
            canvas.create_oval(x_pos - 3, y_pos - 3, x_pos + 3, y_pos + 3, 
                             fill='blue', outline='')
            
            # Add label for every other point to avoid clutter
            if i % 2 == 0:
                canvas.create_text(x_pos, y_pos - 10, text=str(y))
        
        # Draw line connecting points
        if len(points) > 2:
            canvas.create_line(*points, fill='blue', width=2)
            
        return canvas
        
    def setup_dashboard_tab(self):
        """Set up the dashboard tab with key metrics and visualizations."""
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        # Top metrics row
        metrics_frame = ttk.Frame(self.dashboard_frame)
        metrics_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add metric cards
        self.metric_vars = {}
        metrics = [
            ('threats', 'Active Threats', 'high'),
            ('incidents', 'Open Incidents', 'medium'),
            ('alerts', 'New Alerts', 'warning'),
            ('compliance', 'Compliance Score', 'success')
        ]
        
        for i, (key, label, severity) in enumerate(metrics):
            frame = ttk.Frame(metrics_frame, style=f'Metric.{severity.capitalize()}.TFrame')
            ttk.Label(frame, text=label, style='Metric.Title.TLabel').pack()
            self.metric_vars[key] = tk.StringVar(value="0")
            ttk.Label(frame, textvariable=self.metric_vars[key], style='Metric.Value.TLabel').pack()
            frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        # Add charts and visualizations
        charts_frame = ttk.Frame(self.dashboard_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left chart - Alerts by Severity
        alert_chart_frame = ttk.LabelFrame(charts_frame, text="Alerts by Severity")
        self.alert_chart = self.create_pie_chart(alert_chart_frame)
        alert_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right chart - Events Over Time
        events_chart_frame = ttk.LabelFrame(charts_frame, text="Events Over Time")
        self.events_chart = self.create_line_chart(events_chart_frame)
        events_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Recent alerts table
        alerts_frame = ttk.LabelFrame(self.dashboard_frame, text="Recent Alerts")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('timestamp', 'severity', 'source', 'message')
        self.alerts_table = ttk.Treeview(
            alerts_frame, 
            columns=columns, 
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        for col in columns:
            self.alerts_table.heading(col, text=col.capitalize())
            self.alerts_table.column(col, width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_table.yview)
        self.alerts_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_table.pack(fill=tk.BOTH, expand=True)
    def setup_monitoring_tab(self):
        """Set up the real-time monitoring tab."""
        self.monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitoring_frame, text="Real-Time Monitoring")
        
        # Real-time event stream
        event_stream_frame = ttk.LabelFrame(self.monitoring_frame, text="Event Stream")
        event_stream_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Event filter controls
        filter_frame = ttk.Frame(event_stream_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.event_filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.event_filter_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(filter_frame, text="Apply", command=self.apply_event_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear", command=self.clear_event_filter).pack(side=tk.LEFT, padx=5)
        
        # Event table
        columns = ('timestamp', 'source', 'event_type', 'severity', 'message')
        self.events_table = ttk.Treeview(
            event_stream_frame, 
            columns=columns, 
            show='headings',
            selectmode='extended',
            height=15
        )
        
        # Configure columns
        col_widths = {'timestamp': 150, 'source': 120, 'event_type': 120, 'severity': 80, 'message': 300}
        for col in columns:
            self.events_table.heading(col, text=col.capitalize())
            self.events_table.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(event_stream_frame, orient=tk.VERTICAL, command=self.events_table.yview)
        self.events_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.events_table.pack(fill=tk.BOTH, expand=True)
        
        # Right-click context menu
        self.setup_event_context_menu()
        
        # Event details panel
        details_frame = ttk.LabelFrame(self.monitoring_frame, text="Event Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.event_details = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            width=80,
            height=10,
            state='disabled'
        )
        self.event_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Action buttons
        button_frame = ttk.Frame(details_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Create Alert", command=self.create_alert_from_event).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add to Incident", command=self.add_to_incident).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Events", command=self.export_events).pack(side=tk.RIGHT, padx=5)
    
    def setup_event_context_menu(self):
        """Set up the context menu for event items."""
        self.event_context_menu = tk.Menu(self.root, tearoff=0)
        self.event_context_menu.add_command(
            label="View Details",
            command=self.view_event_details
        )
        self.event_context_menu.add_command(
            label="Add to Watchlist",
            command=self.add_to_watchlist
        )
        self.event_context_menu.add_separator()
        self.event_context_menu.add_command(
            label="Copy to Clipboard",
            command=self.copy_event_to_clipboard
        )
        
        # Bind right-click to show context menu
        self.events_table.bind(
            "<Button-3>",
            lambda e: self.show_event_context_menu(e)
        )
        
        # Also bind to the Windows/Mac right-click button
        self.events_table.bind(
            "<Button-2>",
            lambda e: self.show_event_context_menu(e)
        )
    
    def show_event_context_menu(self, event):
        """Show the context menu for the selected event."""
        # Select the item that was right-clicked
        item = self.events_table.identify_row(event.y)
        if item:
            self.events_table.selection_set(item)
            self.event_context_menu.post(event.x_root, event.y_root)
    
    def view_event_details(self):
        """Display detailed information about the selected event."""
        selected = self.events_table.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an event to view details.")
            return
            
        item = selected[0]
        values = self.events_table.item(item, 'values')
        
        # Enable the text widget, insert the details, then disable it again
        self.event_details.config(state='normal')
        self.event_details.delete(1.0, tk.END)
        
        # Format and insert the event details
        details_text = (
            f"Timestamp: {values[0]}\n"
            f"Source: {values[1]}\n"
            f"Event Type: {values[2]}\n"
            f"Severity: {values[3]}\n"
            f"\nMessage:\n{values[4]}"
        )
        
        self.event_details.insert(tk.END, details_text)
        self.event_details.config(state='disabled')
    
    def add_to_watchlist(self):
        """Add the selected event's source to the watchlist."""
        selected = self.events_table.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an event to add to watchlist.")
            return
            
        item = selected[0]
        values = self.events_table.item(item, 'values')
        source = values[1]  # Source is the second column
        
        # In a real application, you would add this to a watchlist
        # For now, just show a message
        messagebox.showinfo("Info", f"Added {source} to watchlist.")
        logger.info(f"Added {source} to watchlist")
    
    def copy_event_to_clipboard(self):
        """Copy the selected event details to the clipboard."""
        selected = self.events_table.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an event to copy.")
            return
            
        item = selected[0]
        values = self.events_table.item(item, 'values')
        
        # Format the event details as a string
        event_text = (
            f"Timestamp: {values[0]}\n"
            f"Source: {values[1]}\n"
            f"Event Type: {values[2]}\n"
            f"Severity: {values[3]}\n"
            f"Message: {values[4]}"
        )
        
        # Copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(event_text)
        self.root.update()  # Required to finalize the clipboard update
        
        # Provide feedback
        messagebox.showinfo("Info", "Event details copied to clipboard.")
    
    def create_alert_from_event(self):
        """Create an alert from the selected event."""
        selected = self.events_table.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an event to create an alert.")
            return
            
        item = selected[0]
        values = self.events_table.item(item, 'values')
        
        # In a real application, you would create an alert here
        messagebox.showinfo("Info", f"Created alert for event: {values}")
        logger.info(f"Created alert for event: {values}")
    
    def add_to_incident(self):
        """Add the selected event to an incident."""
        selected = self.events_table.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an event to add to an incident.")
            return
            
        # In a real application, you would show a dialog to select or create an incident
        messagebox.showinfo("Info", "Add to incident functionality will be implemented here.")
    
    def export_events(self):
        """Export the current events to a file."""
        # In a real application, you would show a file dialog and export the events
        messagebox.showinfo("Info", "Export events functionality will be implemented here.")
    
    def setup_threat_detection_tab(self):
        """Set up the threat detection tab."""
        # Implementation for threat detection tab
        pass
    
    def setup_incident_response_tab(self):
        """Set up the incident response tab."""
        # Implementation for incident response tab
        pass
    
    def setup_compliance_tab(self):
        """Set up the compliance tab."""
        # Implementation for compliance tab
        pass
    
    def setup_ueba_tab(self):
        """Set up the UEBA tab."""
        # Implementation for UEBA tab
        pass
    
    def setup_reports_tab(self):
        """Set up the reports tab."""
        # Implementation for reports tab
        pass
    
    def save_settings(self):
        """Save application settings to config and update UI accordingly."""
        try:
            # Update config with new values
            config['ui']['theme'] = self.theme_var.get()
            config['ui']['refresh_interval'] = self.refresh_interval_var.get()
            config['ui']['auto_refresh'] = self.auto_refresh_var.get()
            
            # Save config to file
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            # Update refresh interval if changed
            self.refresh_interval = self.refresh_interval_var.get()
            
            # Apply theme
            self.apply_theme()
            
            # Show success message
            self.settings_status_var.set("Settings saved successfully!")
            self.root.after(3000, lambda: self.settings_status_var.set(""))
            
            logger.info("Settings saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving settings: {str(e)}")
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def setup_settings_tab(self):
        """Set up the settings tab."""
        # Create the settings tab
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Create a frame for settings
        settings_frame = ttk.LabelFrame(self.settings_tab, text="Application Settings", padding=10)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Theme selection
        ttk.Label(settings_frame, text="Theme:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.theme_var = tk.StringVar(value=config['ui'].get('theme', 'light'))
        theme_combo = ttk.Combobox(
            settings_frame, 
            textvariable=self.theme_var, 
            values=('light', 'dark'),
            state='readonly',
            width=15
        )
        theme_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        theme_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_theme())
        
        # Refresh interval
        ttk.Label(settings_frame, text="Refresh Interval (ms):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.refresh_interval_var = tk.IntVar(value=config['ui'].get('refresh_interval', 5000))
        ttk.Spinbox(
            settings_frame, 
            from_=1000, 
            to=30000, 
            increment=1000,
            textvariable=self.refresh_interval_var,
            width=10
        ).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Auto-refresh toggle
        self.auto_refresh_var = tk.BooleanVar(value=config['ui'].get('auto_refresh', True))
        ttk.Checkbutton(
            settings_frame, 
            text="Enable Auto-refresh",
            variable=self.auto_refresh_var
        ).grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Save button
        ttk.Button(
            settings_frame,
            text="Save Settings",
            command=self.save_settings
        ).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Status label
        self.settings_status_var = tk.StringVar()
        ttk.Label(
            settings_frame,
            textvariable=self.settings_status_var,
            foreground='green'
        ).grid(row=4, column=0, columnspan=2)
    
    def setup_alerts_tab(self):
        """Set up the alerts tab."""
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="Alerts")
        
        # Filter frame
        filter_frame = ttk.Frame(self.alerts_tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Severity filter
        ttk.Label(filter_frame, text="Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="All")
        severities = ["All", "Low", "Medium", "High", "Critical"]
        ttk.OptionMenu(
            filter_frame, 
            self.severity_var, 
            "All", 
            *severities,
            command=self.filter_alerts
        ).pack(side=tk.LEFT, padx=5)
        
        # Search box
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)
        search_entry.bind("<Return>", lambda e: self.filter_alerts())
        
        # Alerts treeview
        columns = ("Time", "Severity", "Source", "Message", "Status")
        self.all_alerts_tree = ttk.Treeview(
            self.alerts_tab, 
            columns=columns, 
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        for col in columns:
            self.all_alerts_tree.heading(col, text=col)
            self.all_alerts_tree.column(col, width=120, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.alerts_tab, orient=tk.VERTICAL, command=self.all_alerts_tree.yview)
        self.all_alerts_tree.configure(yscroll=scrollbar.set)
        
        # Pack widgets
        self.all_alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.setup_context_menu()
    
    def setup_events_tab(self):
        """Set up the events tab with Sysmon event integration."""
        self.events_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.events_tab, text="Events")
        
        # Create a frame for the filter controls
        filter_frame = ttk.Frame(self.events_tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Event type filter
        ttk.Label(filter_frame, text="Event Type:").pack(side=tk.LEFT, padx=5)
        self.event_type_var = tk.StringVar(value="All")
        event_types = ["All", "Security", "Application", "System", "Sysmon"]
        ttk.OptionMenu(
            filter_frame, 
            self.event_type_var, 
            "All", 
            *event_types,
            command=lambda _: self.filter_events()
        ).pack(side=tk.LEFT, padx=5)
        
        # Search box
        self.event_search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.event_search_var, width=40)
        search_entry.pack(side=tk.RIGHT, padx=5)
        search_entry.bind("<Return>", lambda e: self.filter_events())
        ttk.Button(
            filter_frame, 
            text="Search", 
            command=self.filter_events,
            width=10
        ).pack(side=tk.RIGHT, padx=5)
        
        # Refresh button
        ttk.Button(
            filter_frame,
            text="Refresh",
            command=self.refresh_events,
            width=10
        ).pack(side=tk.RIGHT, padx=5)
        
        # Events treeview
        columns = ("Timestamp", "Source", "Event ID", "Type", "Details")
        self.events_tree = ttk.Treeview(
            self.events_tab, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=120, anchor=tk.W)
        
        # Configure tags for different event types
        self.events_tree.tag_configure('sysmon', background='#e6f7ff')
        self.events_tree.tag_configure('security', background='#fff0f0')
        self.events_tree.tag_configure('application', background='#f0fff0')
        self.events_tree.tag_configure('system', background='#ffffe0')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.events_tab, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscroll=scrollbar.set)
        
        # Pack widgets
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load initial events
        self.refresh_events()
    
    def apply_event_filter(self):
        """Apply the event filter to the events table."""
        try:
            filter_text = self.event_filter_var.get().lower()
            
            # Clear current selection
            self.events_table.selection_remove(self.events_table.selection())
            
            # If no filter, show all rows
            if not filter_text:
                for item in self.events_table.get_children():
                    self.events_table.attach(item, '', 'end')
                return
            
            # Show only matching rows
            for item in self.events_table.get_children():
                values = self.events_table.item(item, 'values')
                if any(filter_text in str(value).lower() for value in values):
                    self.events_table.attach(item, '', 'end')
                else:
                    self.events_table.detach(item)
                    
        except Exception as e:
            messagebox.showerror("Filter Error", f"Failed to apply filter: {str(e)}")
            logger.error(f"Error in apply_event_filter: {e}", exc_info=True)
    
    def clear_event_filter(self):
        """Clear the event filter and show all events."""
        try:
            self.event_filter_var.set("")
            for item in self.events_table.get_children():
                self.events_table.attach(item, '', 'end')
        except Exception as e:
            messagebox.showerror("Filter Error", f"Failed to clear filter: {str(e)}")
            logger.error(f"Error in clear_event_filter: {e}", exc_info=True)
    
    def _populate_sample_events(self):
        """Populate the events table with sample data."""
        import random
        from datetime import datetime, timedelta
        
        event_types = ["Login", "Logout", "File Access", "Process Start", "Network Connection"]
        severities = ["Low", "Medium", "High", "Critical"]
        sources = ["Workstation-01", "Server-01", "Firewall-01", "Router-01", "Switch-01"]
        messages = [
            "User login successful",
            "Failed login attempt",
            "File accessed",
            "New process started",
            "Network connection established",
            "Configuration changed",
            "Security alert triggered",
            "System update installed"
        ]
        
        now = datetime.now()
        
        for i in range(100):
            timestamp = now - timedelta(minutes=random.randint(0, 1440))  # Last 24 hours
            source = random.choice(sources)
            event_type = random.choice(event_types)
            severity = random.choice(severities)
            message = random.choice(messages)
            
            self.events_table.insert(
                '', 'end',
                values=(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    source,
                    event_type,
                    severity,
                    message
                ),
                tags=(severity.lower(),)
            )
        
        # Configure tag colors
        self.events_table.tag_configure('low', background='#e6f3ff')
        self.events_table.tag_configure('medium', background='#fff3cd')
        self.events_table.tag_configure('high', background='#f8d7da')
        self.events_table.tag_configure('critical', background='#dc3545', foreground='white')
    
    def setup_detection_tab(self):
        """Set up the detection rules tab."""
        self.detection_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.detection_tab, text="Detection Rules")
        
        # Rules treeview
        columns = ("ID", "Name", "Severity", "Status", "Last Matched")
        self.rules_tree = ttk.Treeview(
            self.detection_tab, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=120, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.detection_tab, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscroll=scrollbar.set)
        
        # Pack widgets
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add some sample rules
        self.populate_sample_rules()
    
    def setup_logs_tab(self):
        """Set up the logs tab."""
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Log level filter
        filter_frame = ttk.Frame(self.logs_tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Log Level:").pack(side=tk.LEFT, padx=5)
        self.log_level_var = tk.StringVar(value="INFO")
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        ttk.OptionMenu(
            filter_frame, 
            self.log_level_var, 
            "INFO", 
            *log_levels,
            command=self.filter_logs
        ).pack(side=tk.LEFT, padx=5)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            self.logs_tab,
            wrap=tk.WORD,
            width=100,
            height=30,
            font=('Consolas', 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
    def setup_context_menu(self):
        """Set up the context menu for the events tree."""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_event_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Event ID", command=self.copy_event_id)
        self.context_menu.add_command(label="Search Online", command=self.search_event_online)
        
        # Bind right-click to show context menu
        self.events_tree.bind("<Button-3>", self.show_context_menu)
        
    def view_event_details(self):
        """Show detailed information about the selected event."""
        selected_item = self.events_tree.selection()
        if not selected_item:
            return
            
        item_id = selected_item[0]
        event_data = self.event_data.get(item_id, {})
        
        # Create a new window to display event details
        details_window = tk.Toplevel(self.root)
        details_window.title("Event Details")
        details_window.geometry("800x600")
        
        # Create a text widget with scrollbar
        text_frame = ttk.Frame(details_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text.yview)
        
        # Format and display the event data
        text.insert(tk.END, "=== Event Details ===\n\n")
        
        # Add basic info
        values = self.events_tree.item(item_id, 'values')
        if values:
            text.insert(tk.END, f"Time: {values[0]}\n")
            text.insert(tk.END, f"Source: {values[1]}\n")
            text.insert(tk.END, f"Event ID: {values[2]}\n")
            text.insert(tk.END, f"Level: {values[3]}\n\n")
            text.insert(tk.END, f"Message: {values[4]}\n\n")
        
        # Add raw data if available
        if event_data:
            text.insert(tk.END, "=== Raw Data ===\n\n")
            try:
                # Try to format as JSON if it's a dictionary
                import json
                formatted_data = json.dumps(event_data, indent=2, sort_keys=True)
                text.insert(tk.END, formatted_data)
            except:
                # Fall back to string representation
                text.insert(tk.END, str(event_data))
        
        # Make the text read-only
        text.config(state=tk.DISABLED)
        
        # Add a close button
        button_frame = ttk.Frame(details_window)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        close_button = ttk.Button(button_frame, text="Close", command=details_window.destroy)
        close_button.pack(side=tk.RIGHT, padx=5)
        
        # Add a copy button
        copy_button = ttk.Button(button_frame, text="Copy to Clipboard", 
                               command=lambda: self.copy_to_clipboard(text.get("1.0", tk.END)))
        copy_button.pack(side=tk.RIGHT, padx=5)
    
    def copy_to_clipboard(self, text):
        """Copy text to the system clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()  # Required on some platforms
    
    def copy_event_id(self):
        """Copy the selected event ID to the clipboard."""
        selected_item = self.events_tree.selection()
        if selected_item:
            values = self.events_tree.item(selected_item[0], 'values')
            if values and len(values) > 2:  # Check if we have an Event ID
                event_id = values[2]
                self.root.clipboard_clear()
                self.root.clipboard_append(event_id)
    
    def search_event_online(self):
        """Search for the selected event ID online."""
        selected_item = self.events_tree.selection()
        if selected_item:
            values = self.events_tree.item(selected_item[0], 'values')
            if values and len(values) > 2:  # Check if we have an Event ID
                event_id = values[2]
                import webbrowser
                webbrowser.open(f"https://www.google.com/search?q=sysmon+event+{event_id}")
    
    def show_context_menu(self, event):
        """Show the context menu on right-click."""
        # Select the row that was right-clicked
        row_id = self.events_tree.identify_row(event.y)
        if row_id:
            self.events_tree.selection_set(row_id)
            self.context_menu.post(event.x_root, event.y)

            self.all_alerts_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def view_alert_details(self):
        """Show details for the selected alert."""
        selected = self.all_alerts_tree.selection()
        if not selected:
            return
            
        # Get alert details
        item = self.all_alerts_tree.item(selected[0])
        details = item['values']
        
        # Show details in a messagebox
        messagebox.showinfo(
            "Alert Details",
            f"Time: {details[0]}\n"
            f"Severity: {details[1]}\n"
            f"Source: {details[2]}\n"
            f"Message: {details[3]}\n"
            f"Status: {details[4]}"
        )
    
    def resolve_alert(self):
        """Mark the selected alert as resolved."""
        selected = self.all_alerts_tree.selection()
        if not selected:
            return
            
        for item in selected:
            self.all_alerts_tree.set(item, "Status", "Resolved")
        
        self.update_status(f"Marked {len(selected)} alert(s) as resolved")
    
    def export_alerts_csv(self):
        """Export alerts to a CSV file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as f:
                # Write header
                columns = [self.all_alerts_tree.heading(col)['text'] for col in self.all_alerts_tree['columns']]
                f.write(",".join(columns) + "\n")
                
                # Write data
                for item in self.all_alerts_tree.get_children():
                    values = self.all_alerts_tree.item(item)['values']
                    f.write(",".join(str(v) for v in values) + "\n")
            
            self.update_status(f"Exported alerts to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export alerts: {e}")
    
    def filter_alerts(self, *args):
        """Filter alerts based on severity and search text."""
        severity = self.severity_var.get().lower()
        search_text = self.search_var.get().lower()
        
        for item in self.all_alerts_tree.get_children():
            values = self.all_alerts_tree.item(item)['values']
            severity_match = (severity == "all" or values[1].lower() == severity)
            search_match = (not search_text or 
                          any(search_text in str(v).lower() for v in values))
            
            if severity_match and search_match:
                self.all_alerts_tree.reattach(item, '', 'end')
            else:
                self.all_alerts_tree.detach(item)
    
    def filter_logs(self, *args):
        """Filter logs based on log level."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        log_level = getattr(logging, self.log_level_var.get())
        log_file = config['logging']['file']
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Extract log level from log line
                    log_parts = line.split()
                    if len(log_parts) >= 3:
                        line_level = log_parts[2].strip(':')
                        line_level = getattr(logging, line_level, logging.INFO)
                        
                        if line_level >= log_level:
                            self.log_text.insert(tk.END, line)
        except Exception as e:
            self.log_text.insert(tk.END, f"Error reading log file: {e}\n")
        
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
    
    def populate_sample_rules(self):
        """Populate the rules tree with sample detection rules."""
        sample_rules = [
            ("R001", "Multiple Failed Logins", "High", "Enabled", "2023-01-01 10:30:00"),
            ("R002", "Port Scan Detected", "High", "Enabled", "2023-01-01 11:45:00"),
            ("R003", "Suspicious Process Execution", "Critical", "Enabled", "2023-01-02 09:15:00"),
            ("R004", "Data Exfiltration Attempt", "Critical", "Enabled", "2023-01-02 14:20:00"),
            ("R005", "Unauthorized Access", "High", "Enabled", "2023-01-03 16:30:00")
        ]
        
        for rule in sample_rules:
            self.rules_tree.insert("", tk.END, values=rule)
    

    def refresh_events(self):
        """Refresh the events display with current events."""
        # Make sure events_tree exists
        if not hasattr(self, 'events_tree') or self.events_tree is None:
            return
            
        try:
            # Clear current events and data
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
            self.event_data.clear()
            
            # Add real Sysmon events
            self._add_real_events()
            
            # Apply any active filters
            self.filter_events()
            
            # Update status bar
            if hasattr(self, 'status_bar'):
                event_count = len(self.events_tree.get_children())
                self.status_bar.config(text=f"Loaded {event_count} events")
                self.root.after(3000, lambda: self.status_bar.config(text=""))
                
        except Exception as e:
            logger.error(f"Error refreshing events: {e}")
            if hasattr(self, 'status_bar'):
                self.status_bar.config(text=f"Error refreshing events: {str(e)[:100]}...")
                self.root.after(5000, lambda: self.status_bar.config(text=""))
    
    def filter_events(self, *args):
        """Filter events based on the current filter criteria."""
        # Check if required attributes exist
        if not hasattr(self, 'events_tree') or not hasattr(self, 'event_type_var') or not hasattr(self, 'event_search_var'):
            return
            
        try:
            event_type = self.event_type_var.get().lower()
            search_text = self.event_search_var.get().lower()
            
            for item in self.events_tree.get_children():
                item_values = self.events_tree.item(item, 'values')
                item_text = ' '.join(str(v) for v in item_values).lower()
                
                # Check type filter
                type_match = (event_type == 'all' or 
                            (event_type == 'sysmon' and 'sysmon' in self.events_tree.item(item, 'tags')) or
                            (event_type != 'all' and event_type in item_text))
                
                # Check search text
                search_match = not search_text or search_text in item_text
                
                if type_match and search_match:
                    self.events_tree.attach(item, '', 'end')
                else:
                    self.events_tree.detach(item)
        except Exception as e:
            logger.error(f"Error filtering events: {e}")
            if hasattr(self, 'status_bar'):
                self.status_bar.config(text=f"Error filtering events: {str(e)[:100]}...")
                self.root.after(5000, lambda: self.status_bar.config(text=""))
    
    def _add_real_events(self):
        """Fetch and display real Sysmon events."""
        try:
            # Import the Sysmon collector
            from siem.collectors.sysmon_collector import SysmonCollector
            
            # Initialize the collector
            collector = SysmonCollector()
            
            # Get the latest events
            events = collector.get_events(limit=100)
            
            # Add each event to the tree
            for event in events:
                event_type = event.get('type', 'Unknown Event')
                event_tag = 'sysmon'
                
                # Determine level and color
                level = event.get('level', 'INFO').upper()
                if level in ['ERROR', 'CRITICAL']:
                    color = "#f2dede"  # Light red
                elif level == 'WARNING':
                    color = "#fcf8e3"  # Light yellow
                else:
                    color = "#d9edf7"  # Light blue
                
                # Add the event to the tree
                item_id = self.events_tree.insert(
                    "", "end",
                    values=(
                        event.get('timestamp', ''),  # Time
                        event.get('source', 'Unknown'),  # Source
                        event.get('event_id', ''),  # Event ID
                        level,  # Level
                        event.get('details', 'No details available')  # Message
                    ),
                    tags=(event_tag,)
                )
                
                # Store the raw data for context menu
                self.event_data[item_id] = event.get('raw_data', {})
                
                # Apply color based on level
                self.events_tree.tag_configure(event_tag, background=color)
                
        except Exception as e:
            logger.error(f"Error fetching Sysmon events: {str(e)}")
            # Fall back to sample data if there's an error
            self._add_fallback_sample_events()
    
    def _add_fallback_sample_events(self):
        """Add sample events if real Sysmon events can't be fetched."""
        import random
        from datetime import datetime, timedelta
        
        # Sample event types and their tags
        event_types = [
            ("Security", "security"),
            ("Application", "application"),
            ("System", "system"),
            ("Sysmon", "sysmon")
        ]
        
        # Sample event levels and their colors
        levels = [
            ("INFO", "#d9edf7"),
            ("WARNING", "#fcf8e3"),
            ("ERROR", "#f2dede"),
            ("CRITICAL", "#f2dede")
        ]
        
        # Generate sample events for the last 24 hours
        now = datetime.now()
        for i in range(50):  # Fewer sample events
            # Random time in the last 24 hours
            hours_ago = random.uniform(0, 24)
            event_time = now - timedelta(hours=hours_ago)
            
            # Random event type and level
            event_type, event_tag = random.choice(event_types)
            level, color = levels[0]  # Default to INFO
            
            # Generate sample event details based on type
            if event_type == "Security":
                details = f"Security event {random.randint(1000, 9999)}: " \
                         f"User {random.choice(['admin', 'user1', 'user2', 'svc_account'])} " \
                         f"performed {random.choice(['login', 'logout', 'file access', 'permission change'])}"
            elif event_type == "Application":
                details = f"Application {random.choice(['chrome.exe', 'explorer.exe', 'svchost.exe'])} " \
                         f"reported: {random.choice(['Started successfully', 'Warning message', 'Error occurred'])}"
            elif event_type == "System":
                details = f"System event: {random.choice(['Service started', 'Device connected', 'Driver loaded', 'Network change detected'])}"
            else:  # Sysmon
                details = f"Sysmon event {random.choice(['Process Create', 'Network Connect', 'File Create', 'Registry Event'])}: " \
                         f"Process {random.choice(['explorer.exe', 'chrome.exe', 'powershell.exe'])} " \
                         f"with PID {random.randint(1000, 9999)}"
            
            # Format timestamp for display
            timestamp = event_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Add the event to the tree
            item_id = self.events_tree.insert(
                "", "end",
                values=(
                    timestamp,  # Time
                    f"{event_type} Event",  # Source
                    str(random.randint(1000, 9999)),  # Event ID
                    level,  # Level
                    details  # Message
                ),
                tags=(event_tag,)
            )
            
            # Store empty data for consistency
            self.event_data[item_id] = {}
            
            # Apply color based on level
            self.events_tree.tag_configure(event_tag, background=color)
    
    def refresh_data(self):
        """Refresh all data in the UI."""
        self.update_metrics()
        self.update_alerts()
        self.refresh_events()
        # Update events
        self.update_events()
        
        # Schedule next refresh
        self.root.after(self.refresh_interval, self.refresh_data)
    
    def update_metrics(self):
        """Update system metrics display."""
        try:
            # Get current system metrics
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Update UI elements
            if hasattr(self, 'cpu_label'):
                self.cpu_label.config(text=f"CPU: {cpu_percent}%")
            if hasattr(self, 'memory_label'):
                self.memory_label.config(text=f"Memory: {memory.percent}%")
            if hasattr(self, 'disk_label'):
                self.disk_label.config(text=f"Disk: {disk.percent}%")
                
        except Exception as e:
            logger.error(f"Error updating metrics: {e}", exc_info=True)
            
    def update_alerts(self):
        """Update alerts display."""
        try:
            if not hasattr(self, 'alerts_tree'):
                return
                
            # Clear existing items
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
                
            # Add sample alerts (replace with real data)
            sample_alerts = [
                ("High", "Failed Login Attempts", "192.168.1.1", "2023-01-01 12:00:00"),
                ("Medium", "Port Scan Detected", "10.0.0.5", "2023-01-01 12:05:00"),
                ("Low", "Policy Violation", "user1", "2023-01-01 12:10:00")
            ]
            
            for alert in sample_alerts:
                self.alerts_tree.insert("", "end", values=alert)
                
        except Exception as e:
            logger.error(f"Error updating alerts: {e}", exc_info=True)
            
    def update_events(self):
        """Update events display."""
        try:
            if not hasattr(self, 'events_tree'):
                return
                
            # Clear existing items
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
                
            # Add sample events (replace with real data)
            sample_events = [
                ("2023-01-01 12:00:00", "Login", "user1", "192.168.1.1", "Success"),
                ("2023-01-01 12:01:00", "File Access", "user1", "192.168.1.1", "Read"),
                ("2023-01-01 12:02:00", "Logout", "user1", "192.168.1.1", "Success")
            ]
            
            for event in sample_events:
                self.events_tree.insert("", "end", values=event)
                
        except Exception as e:
            logger.error(f"Error updating events: {e}")
    
    def on_alert_double_click(self, event):
        """Handle double-click on an alert to show details."""
        selected = self.alerts_tree.selection()
        if selected:
            self.view_alert_details()

    def apply_theme(self):
        """Apply the selected theme to the UI."""
        try:
            theme = themes[config['ui']['theme']]
            
            # Configure base styles
            self.style.configure('.', 
                               background=theme['bg'], 
                               foreground=theme['fg'],
                               font=('Segoe UI', 10))
            
            # Configure specific widget styles
            self.style.configure('TFrame', background=theme['bg'])
            self.style.configure('TLabel', 
                               background=theme['bg'], 
                               foreground=theme['fg'])
            self.style.configure('TButton', 
                               padding=5,
                               background=theme['bg_secondary'],
                               foreground=theme['fg'])
            self.style.configure('TEntry', 
                               padding=5,
                               fieldbackground=theme['bg_secondary'],
                               foreground=theme['fg'])
            
            # Configure notebook
            self.style.configure('TNotebook', background=theme['bg'])
            self.style.configure('TNotebook.Tab', 
                               background=theme['bg_secondary'],
                               foreground=theme['fg'],
                               padding=[10, 5],
                               font=('Segoe UI', 9, 'bold'))
            self.style.map('TNotebook.Tab', 
                         background=[('selected', theme['accent'])],
                         foreground=[('selected', 'white')])
            
            # Configure treeview
            self.style.configure('Treeview', 
                               background=theme['bg_secondary'],
                               foreground=theme['fg'],
                               fieldbackground=theme['bg_secondary'],
                               borderwidth=0,
                               rowheight=25)
            self.style.map('Treeview', 
                         background=[('selected', theme['accent'])],
                         foreground=[('selected', 'white')])
            
            # Configure treeview heading
            self.style.configure('Treeview.Heading',
                               background=theme['bg_secondary'],
                               foreground=theme['fg'],
                               relief='flat',
                               font=('Segoe UI', 9, 'bold'))
            
            # Configure scrollbar
            self.style.configure('Vertical.TScrollbar', 
                               background=theme['bg_secondary'],
                               troughcolor=theme['bg'],
                               bordercolor=theme['bg'],
                               arrowcolor=theme['fg'],
                               gripcount=0)
            
            # Configure status bar
            if hasattr(self, 'status_bar'):
                self.status_bar.configure(background=theme['bg_secondary'], 
                                        foreground=theme['fg'])
            
            # Update all widgets to apply the theme
            self.root.update_idletasks()
            
        except Exception as e:
            logger.error(f"Error applying theme: {e}")
            # Fall back to default theme on error
            self.style.theme_use('default')

    def on_closing(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.stop_monitoring()
            self.root.destroy()

    def setup_logging(self):
        """Set up logging for the application."""
        log_file = Path(config['logging']['file'])
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        logging.basicConfig(
            level=config['logging']['level'],
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    log_file,
                    maxBytes=config['logging']['max_size'],
                    backupCount=config['logging']['backup_count']
                ),
                logging.StreamHandler()
            ]
        )
        
        # Set log level for other loggers
        logging.getLogger('PIL').setLevel(logging.WARNING)
        logging.getLogger('matplotlib').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        
        logger = logging.getLogger('siem.gui')
        logger.info("SIEM GUI initialized")
        self.setup_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def run_monitoring(self):
        """Run the monitoring loop in a separate thread."""
        try:
            # TODO: Implement actual monitoring logic
            while self.monitoring:
                # Simulate receiving events
                event = self.siem_core.get_next_event()
                if event:
                    self.process_event(event)
                
                # Small delay to prevent high CPU usage
                import time
                time.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Error in monitoring thread: {e}")
            self.update_status(f"Error: {str(e)}")
    
    def process_event(self, event):
        """Process a security event."""
        try:
            # Add to events list
            self.events.append(event)
            
            # Run detection
            alerts = self.detection_engine.analyze(event)
            
            # Process any generated alerts
            for alert in alerts:
                self.process_alert(alert)
                
            # Update UI
            self.update_event_count()
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def process_alert(self, alert):
        """Process a security alert."""
        try:
            # Add to alerts list
            self.alerts.append(alert)
            
            # Update UI
            self.update_alerts_table(alert)
            self.update_alert_count()
            
            # Log the alert
            logger.warning(f"ALERT: {alert.get('message', 'No message')}")
            
            # Show notification for high severity alerts
            if alert.get('severity', 'low').lower() in ['high', 'critical']:
                self.show_alert_notification(alert)
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def update_alerts_table(self, alert):
        """Update the alerts table with a new alert."""
        # This method runs in a background thread, so we need to use after()
        def _update():
            # Limit number of displayed alerts
            if self.alerts_table.get_children() > 1000:
                self.alerts_table.delete(*self.alerts_table.get_children()[-100:])
            
            # Add new alert to the top
            self.alerts_table.insert(
                "", 0, 
                values=(
                    alert.get('timestamp', ''),
                    alert.get('severity', 'info').upper(),
                    alert.get('source', 'N/A'),
                    alert.get('message', 'No message')
                ),
                tags=(alert.get('severity', 'info'),)
            )
            
            # Configure tag colors
            self.alerts_table.tag_configure('critical', background='#ff6b6b', foreground='white')
            self.alerts_table.tag_configure('high', background='#ffa07a', foreground='black')
            self.alerts_table.tag_configure('medium', background='#ffd700', foreground='black')
            self.alerts_table.tag_configure('low', background='#98fb98', foreground='black')
            self.alerts_table.tag_configure('info', background='#e6e6fa', foreground='black')
        
        # Schedule the update on the main thread
        self.root.after(0, _update)
    
    def show_alert_details(self, event):
        """Show details for the selected alert."""
        selected = self.alerts_table.selection()
        if not selected:
            return
            
        # Get the alert details
        item = self.alerts_table.item(selected[0])
        alert_details = dict(zip(
            [col for col in self.alerts_table['columns']],
            item['values']
        ))
        
        # Create a dialog to show details
        details_win = tk.Toplevel(self.root)
        details_win.title("Alert Details")
        details_win.geometry("800x600")
        
        # Add a text widget to show the full alert details
        text = tk.Text(details_win, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format the alert details as JSON
        try:
            import json
            text.insert(tk.END, json.dumps(alert_details, indent=2))
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to serialize alert details: {e}")
            text.insert(tk.END, str(alert_details))
        
        text.config(state=tk.DISABLED)
        
        # Add a close button
        btn_frame = ttk.Frame(details_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="Close", 
            command=details_win.destroy
        ).pack(side=tk.RIGHT)
    
    def show_alert_notification(self, alert):
        """Show a notification for a high-priority alert."""
        def _show():
            messagebox.showwarning(
                f"{alert.get('severity', 'Alert').upper()} Alert",
                alert.get('message', 'A security alert has been triggered.')
            )
        self.root.after(0, _show)
    
    def export_alerts(self):
        """Export alerts to a file."""
        if not self.alerts:
            messagebox.showinfo("No Alerts", "There are no alerts to export.")
            return
        
        # Ask for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Alerts As"
        )
        
        if not filename:
            return  # User cancelled
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.alerts, f, indent=2)
            
            self.update_status(f"Alerts exported to {filename}")
            logger.info(f"Exported {len(self.alerts)} alerts to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export alerts: {e}")
            logger.error(f"Export failed: {e}")
    
    def update_status(self, message: str):
        """Update the status bar."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_var.set(f"{timestamp} | {message}")
    
    def update_alert_count(self):
        """Update the alert count display."""
        def _update():
            self.alert_count.config(text=str(len(self.alerts)))
        self.root.after(0, _update)
    
    def update_event_count(self):
        """Update the event count display."""
        def _update():
            self.event_count.config(text=str(len(self.events)))
        self.root.after(0, _update)
    
    def on_closing(self):
        """Handle window close event."""
        # Stop any running monitoring
        if hasattr(self, 'monitoring') and self.monitoring:
            self.stop_monitoring()
        
        # Close the application


class TextRedirector:
    """Redirects stdout/stderr to a Tkinter Text widget."""
    
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
    
    def write(self, str):
        self.widget.config(state=tk.NORMAL)
        self.widget.insert(tk.END, str, (self.tag,))
        self.widget.see(tk.END)
        self.widget.config(state=tk.DISABLED)
    
    def flush(self):
        pass


def main():
    """Main entry point for the SIEM GUI application."""
    try:
        # Create the main window
        root = tk.Tk()
        
        # Set application icon if available
        try:
            icon_path = Path(__file__).parent / "assets" / "siem_icon.ico"
            if icon_path.exists():
                root.iconbitmap(str(icon_path))
        except Exception as e:
            logger.warning(f"Failed to set window icon: {e}")
        
        # Set window title
        root.title("Security Information and Event Management")
        
        # Set window size and position
        window_width = config['ui'].get('window_width', 1400)
        window_height = config['ui'].get('window_height', 900)
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Set minimum window size
        min_width = config['ui'].get('min_width', 1200)
        min_height = config['ui'].get('min_height', 700)
        root.minsize(min_width, min_height)
        
        # Create and run the application
        app = SIEMGUI(root)
        
        # Start the main loop
        root.mainloop()
        
        return 0
    except Exception as e:
        logger.critical(f"Fatal error in SIEM GUI: {e}", exc_info=True)
        messagebox.showerror("Fatal Error", f"A fatal error occurred: {e}")
        return 10


if __name__ == "__main__":
    import sys
    sys.exit(main())
