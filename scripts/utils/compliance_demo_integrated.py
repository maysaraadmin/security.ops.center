"""
Compliance Module Demo - Integrated with SIEM Dashboard

This script demonstrates the integration of the Compliance Module with the SIEM dashboard,
including the GUI components and their interaction with the ComplianceManager.
"""

import os
import sys
import json
import tempfile
import shutil
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from compliance.manager import ComplianceManager
from views.compliance_view import ComplianceView

class SIEMDashboard:
    """Mock SIEM Dashboard for demonstration purposes."""
    
    def __init__(self, root):
        """Initialize the SIEM Dashboard."""
        self.root = root
        self.root.title("SIEM Dashboard - Compliance Module Demo")
        self.root.geometry("1200x800")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # Create a menu bar
        self._create_menu_bar()
        
        # Create a status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        status_bar.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        # Create a notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Create a dashboard tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Create a compliance tab
        self.compliance_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.compliance_tab, text="Compliance")
        
        # Create a logs tab
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Set up the dashboard
        self._setup_dashboard()
        
        # Set up the logs view
        self._setup_logs()
    
    def _create_menu_bar(self):
        """Create the menu bar."""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Settings", command=self._show_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _setup_dashboard(self):
        """Set up the dashboard tab."""
        # Configure grid weights
        self.dashboard_tab.columnconfigure(0, weight=1)
        self.dashboard_tab.columnconfigure(1, weight=1)
        self.dashboard_tab.rowconfigure(0, weight=1)
        
        # Left panel - Alerts
        alert_frame = ttk.LabelFrame(self.dashboard_tab, text="Security Alerts", padding=10)
        alert_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Add a treeview for alerts
        columns = ("Time", "Severity", "Source", "Message")
        self.alert_tree = ttk.Treeview(
            alert_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        for col in columns:
            self.alert_tree.heading(col, text=col)
            self.alert_tree.column(col, width=100, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            alert_frame, 
            orient=tk.VERTICAL, 
            command=self.alert_tree.yview
        )
        self.alert_tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout
        self.alert_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights for alert frame
        alert_frame.columnconfigure(0, weight=1)
        alert_frame.rowconfigure(0, weight=1)
        
        # Right panel - Compliance Status
        compliance_frame = ttk.LabelFrame(
            self.dashboard_tab, 
            text="Compliance Status", 
            padding=10
        )
        compliance_frame.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Add a treeview for compliance status
        columns = ("Standard", "Status", "Last Checked")
        self.compliance_tree = ttk.Treeview(
            compliance_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        for col in columns:
            self.compliance_tree.heading(col, text=col)
            self.compliance_tree.column(col, width=100, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            compliance_frame, 
            orient=tk.VERTICAL, 
            command=self.compliance_tree.yview
        )
        self.compliance_tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout
        self.compliance_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights for compliance frame
        compliance_frame.columnconfigure(0, weight=1)
        compliance_frame.rowconfigure(0, weight=1)
        
        # Add sample data
        self._add_sample_data()
    
    def _setup_logs(self):
        """Set up the logs tab."""
        # Configure grid weights
        self.logs_tab.columnconfigure(0, weight=1)
        self.logs_tab.rowconfigure(0, weight=1)
        
        # Create a text widget for logs
        self.log_text = tk.Text(
            self.logs_tab, 
            wrap=tk.WORD, 
            state=tk.DISABLED
        )
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.logs_tab, 
            orient=tk.VERTICAL, 
            command=self.log_text.yview
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout
        self.log_text.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Add sample logs
        self._add_sample_logs()
    
    def _add_sample_data(self):
        """Add sample data to the dashboard."""
        # Add sample alerts
        sample_alerts = [
            ("2023-01-01 10:30:00", "High", "Firewall", "Blocked suspicious IP 192.168.1.100"),
            ("2023-01-01 10:25:00", "Medium", "IDS", "Possible SQL injection attempt detected"),
            ("2023-01-01 10:15:00", "Low", "System", "User johndoe logged in from 192.168.1.101"),
            ("2023-01-01 10:10:00", "High", "Antivirus", "Malware detected: Trojan.Win32.Generic"),
            ("2023-01-01 10:05:00", "Medium", "Firewall", "Port scan detected from 192.168.1.200")
        ]
        
        for alert in sample_alerts:
            self.alert_tree.insert("", tk.END, values=alert)
        
        # Add sample compliance status
        sample_status = [
            ("GDPR", "Compliant", "2023-01-01 09:00:00"),
            ("HIPAA", "Non-Compliant", "2023-01-01 09:15:00"),
            ("PCI DSS", "In Progress", "2023-01-01 09:30:00"),
            ("SOX", "Not Started", "")
        ]
        
        for status in sample_status:
            self.compliance_tree.insert("", tk.END, values=status)
    
    def _add_sample_logs(self):
        """Add sample logs to the logs tab."""
        self.log_text.config(state=tk.NORMAL)
        
        # Add sample logs with timestamps
        logs = [
            "[2023-01-01 10:00:00] INFO: SIEM system started",
            "[2023-01-01 10:01:00] INFO: Loading compliance modules...",
            "[2023-01-01 10:02:00] INFO: Compliance module loaded successfully",
            "[2023-01-01 10:03:00] WARNING: No compliance checks scheduled",
            "[2023-01-01 10:04:00] INFO: Dashboard initialized"
        ]
        
        for log in logs:
            self.log_text.insert(tk.END, log + "\n")
        
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
    
    def _show_settings(self):
        """Show the settings dialog."""
        settings_dialog = tk.Toplevel(self.root)
        settings_dialog.title("Settings")
        settings_dialog.geometry("400x300")
        
        # Add some content to the settings dialog
        ttk.Label(
            settings_dialog, 
            text="SIEM Settings", 
            font=('TkDefaultFont', 12, 'bold')
        ).pack(pady=10)
        
        ttk.Label(
            settings_dialog, 
            text="This is where you would configure SIEM settings."
        ).pack(pady=5)
        
        ttk.Button(
            settings_dialog, 
            text="Close", 
            command=settings_dialog.destroy
        ).pack(pady=20)
    
    def _show_about(self):
        """Show the about dialog."""
        about_dialog = tk.Toplevel(self.root)
        about_dialog.title("About")
        about_dialog.geometry("300x200")
        
        # Add content to the about dialog
        ttk.Label(
            about_dialog, 
            text="SIEM Dashboard", 
            font=('TkDefaultFont', 14, 'bold')
        ).pack(pady=10)
        
        ttk.Label(
            about_dialog, 
            text="Version 1.0.0\n\nCompliance Module Demo"
        ).pack(pady=10)
        
        ttk.Button(
            about_dialog, 
            text="OK", 
            command=about_dialog.destroy
        ).pack(pady=20)

def setup_compliance_environment():
    """Set up a test environment for the Compliance Module."""
    # Create a temporary directory for test data
    temp_dir = tempfile.mkdtemp()
    
    # Create a templates directory
    templates_dir = os.path.join(temp_dir, 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Create a reports directory
    reports_dir = os.path.join(temp_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Create a sample GDPR template
    gdpr_template = {
        "name": "GDPR",
        "version": "1.0",
        "description": "General Data Protection Regulation - EU's data protection law",
        "checks": [
            {
                "id": "gdpr_1",
                "description": "Data encryption in transit",
                "severity": "high",
                "remediation": "Enable TLS 1.2 or higher for all data transmissions"
            },
            {
                "id": "gdpr_2",
                "description": "Data retention policy",
                "severity": "medium",
                "remediation": "Define and implement data retention policies"
            },
            {
                "id": "gdpr_3",
                "description": "User consent management",
                "severity": "high",
                "remediation": "Implement a system for obtaining and managing user consent"
            }
        ]
    }
    
    # Save the template to a file
    with open(os.path.join(templates_dir, 'gdpr.json'), 'w') as f:
        json.dump(gdpr_template, f, indent=2)
    
    # Create a sample HIPAA template
    hipaa_template = {
        "name": "HIPAA",
        "version": "1.0",
        "description": "Health Insurance Portability and Accountability Act - US healthcare data protection",
        "checks": [
            {
                "id": "hipaa_1",
                "description": "Access controls",
                "severity": "high",
                "remediation": "Implement role-based access controls for all systems"
            },
            {
                "id": "hipaa_2",
                "description": "Audit logging",
                "severity": "medium",
                "remediation": "Enable and review audit logs for all systems"
            }
        ]
    }
    
    # Save the template to a file
    with open(os.path.join(templates_dir, 'hipaa.json'), 'w') as f:
        json.dump(hipaa_template, f, indent=2)
    
    return temp_dir, templates_dir, reports_dir

def main():
    """Main function to run the demo."""
    # Set up the test environment
    temp_dir, templates_dir, reports_dir = setup_compliance_environment()
    
    try:
        # Create the main application window
        root = tk.Tk()
        
        # Create the SIEM dashboard
        dashboard = SIEMDashboard(root)
        
        # Create a compliance manager
        compliance_manager = ComplianceManager(
            templates_dir=templates_dir,
            reports_dir=reports_dir
        )
        
        # Create the compliance view
        compliance_view = ComplianceView(
            parent=dashboard.compliance_tab,
            compliance_manager=compliance_manager
        )
        
        # Pack the compliance view to fill the tab
        compliance_view.frame.pack(fill=tk.BOTH, expand=True)
        
        # Start the main event loop
        root.mainloop()
        
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
