"""
NIPS GUI Module

Provides a graphical interface for the Network Intrusion Prevention System.
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import os
import queue
import threading
import json
import socket
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nips.gui')

class NIPSGUI:
    """Main NIPS GUI application."""
    
    def __init__(self, root):
        """Initialize the NIPS GUI."""
        self.root = root
        self.root.title("Network Intrusion Prevention System")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize NIPS components
        self.monitoring = False
        self.alerts = []
        self.alert_queue = queue.Queue()
        self.rules = {}
        self.load_rules()
        self.threats_blocked = 0
        self.packets_analyzed = 0
        
        # Setup UI
        self.setup_ui()
        
        # Start event processing
        self.process_alerts()
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_alerts_tab()
        self.setup_rules_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W,
            padding=5
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(tab, text="Network Status", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Stats grid
        stats = [
            ("Monitoring", "Stopped"),
            ("Threats Blocked", "0"),
            ("Packets Analyzed", "0"),
            ("Active Rules", str(len(self.rules)))
        ]
        
        for i, (label, value) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=i//2, column=i%2, padx=10, pady=5, sticky="nsew")
            
            ttk.Label(frame, text=label, font=('Arial', 10, 'bold')).pack()
            var = tk.StringVar(value=value)
            ttk.Label(frame, textvariable=var, font=('Arial', 12)).pack()
            
            # Store variables for updates
            setattr(self, f"stat_{label.lower().replace(' ', '_')}", var)
        
        # Alert summary
        alert_frame = ttk.LabelFrame(tab, text="Recent Alerts", padding=10)
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Time", "Severity", "Source IP", "Destination IP", "Signature", "Action")
        self.alert_tree = ttk.Treeview(
            alert_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {
            "Time": 150, 
            "Severity": 80, 
            "Source IP": 150, 
            "Destination IP": 150,
            "Signature": 400,
            "Action": 100
        }
        
        for col in columns:
            self.alert_tree.heading(col, text=col)
            self.alert_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(alert_frame, orient="vertical", command=self.alert_tree.yview)
        hsb = ttk.Scrollbar(alert_frame, orient="horizontal", command=self.alert_tree.xview)
        self.alert_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Context menu
        self.alert_menu = tk.Menu(alert_frame, tearoff=0)
        self.alert_menu.add_command(label="View Details", command=self.view_alert_details)
        self.alert_menu.add_command(label="Block Source IP", command=self.block_source_ip)
        self.alert_menu.add_separator()
        self.alert_menu.add_command(label="Add to Whitelist", command=self.add_to_whitelist)
        
        self.alert_tree.bind("<Button-3>", self.show_alert_menu)
        self.alert_tree.bind("<Double-1>", self.view_alert_details)
        
        # Add sample alerts
        self.add_sample_alerts()
    
    def setup_alerts_tab(self):
        """Setup the alerts tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Alerts")
        
        # Filter controls
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="All")
        ttk.Combobox(
            filter_frame,
            textvariable=self.severity_var,
            values=["All", "High", "Medium", "Low", "Info"],
            state="readonly",
            width=10
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Source IP:").pack(side=tk.LEFT, padx=5)
        self.source_ip_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.source_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            filter_frame,
            text="Apply Filters",
            command=self.apply_filters
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            filter_frame,
            text="Clear Filters",
            command=self.clear_filters
        ).pack(side=tk.LEFT, padx=5)
        
        # Alerts list
        alerts_frame = ttk.LabelFrame(tab, text="Security Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Time", "Severity", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Signature", "Action")
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Time": 150, 
            "Severity": 80, 
            "Source IP": 120, 
            "Source Port": 80,
            "Destination IP": 140,
            "Destination Port": 80,
            "Protocol": 80,
            "Signature": 300,
            "Action": 100
        }
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        hsb = ttk.Scrollbar(alerts_frame, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Context menu
        self.alerts_context_menu = tk.Menu(alerts_frame, tearoff=0)
        self.alerts_context_menu.add_command(label="View Details", command=self.view_alert_details)
        self.alerts_context_menu.add_command(label="Block Source IP", command=self.block_source_ip)
        self.alerts_context_menu.add_separator()
        self.alerts_context_menu.add_command(label="Add to Whitelist", command=self.add_to_whitelist)
        
        self.alerts_tree.bind("<Button-3>", self.show_alerts_context_menu)
        self.alerts_tree.bind("<Double-1>", self.view_alert_details)
        
        # Add sample alerts
        self.add_sample_alerts_to_tab()
    
    def setup_rules_tab(self):
        """Setup the rules management tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Rules")
        
        # Top controls
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            control_frame,
            text="Add Rule",
            command=self.add_rule
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            control_frame,
            text="Edit Rule",
            command=self.edit_rule
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            control_frame,
            text="Delete Rule",
            command=self.delete_rule
        ).pack(side=tk.LEFT, padx=5)
        
        # Rules list
        rules_frame = ttk.LabelFrame(tab, text="NIPS Rules", padding=10)
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Enabled", "ID", "Action", "Protocol", "Source", "Destination", "Ports", "Message")
        self.rules_tree = ttk.Treeview(
            rules_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Enabled": 60,
            "ID": 60,
            "Action": 80,
            "Protocol": 80,
            "Source": 150,
            "Destination": 150,
            "Ports": 100,
            "Message": 300
        }
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(rules_frame, orient="vertical", command=self.rules_tree.yview)
        hsb = ttk.Scrollbar(rules_frame, orient="horizontal", command=self.rules_tree.xview)
        self.rules_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Add sample rules
        self.add_sample_rules()
    
    # ===== Sample Data Generation =====
    
    def add_sample_alerts(self):
        """Add sample alerts for demonstration."""
        sample_alerts = [
            {
                "timestamp": "2023-11-01 14:30:15",
                "severity": "High",
                "src_ip": "192.168.1.100",
                "src_port": 54321,
                "dst_ip": "10.0.0.1",
                "dst_port": 22,
                "protocol": "TCP",
                "signature": "SSH Brute Force Attempt",
                "action": "Block"
            },
            {
                "timestamp": "2023-11-01 14:31:22",
                "severity": "Medium",
                "src_ip": "192.168.1.101",
                "src_port": 12345,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "protocol": "TCP",
                "signature": "Possible SQL Injection Attempt",
                "action": "Alert"
            },
            {
                "timestamp": "2023-11-01 14:32:45",
                "severity": "Low",
                "src_ip": "192.168.1.102",
                "src_port": 54321,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "UDP",
                "signature": "DNS Query to External DNS Server",
                "action": "Allow"
            }
        ]
        
        for alert in sample_alerts:
            self.add_alert(alert)
    
    def add_sample_alerts_to_tab(self):
        """Add sample alerts to the alerts tab."""
        for alert in self.alerts:
            self.alerts_tree.insert(
                "", 
                tk.END, 
                values=(
                    alert.get("timestamp"),
                    alert.get("severity"),
                    alert.get("src_ip"),
                    alert.get("src_port"),
                    alert.get("dst_ip"),
                    alert.get("dst_port"),
                    alert.get("protocol"),
                    alert.get("signature"),
                    alert.get("action")
                ),
                tags=(alert.get("severity", "Medium").lower(),)
            )
    
    def add_sample_rules(self):
        """Add sample rules for demonstration."""
        sample_rules = [
            (True, "1001", "Alert", "TCP", "any", "$HOME_NET", "22", "SSH Traffic"),
            (True, "1002", "Block", "TCP", "any", "$HOME_NET", "3389", "RDP Access Attempt"),
            (False, "1003", "Alert", "UDP", "any", "8.8.8.8", "53", "External DNS Query")
        ]
        
        for rule in sample_rules:
            self.rules_tree.insert("", tk.END, values=rule)
    
    # ===== Core Functionality =====
    
    def toggle_monitoring(self):
        """Toggle network monitoring."""
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start network monitoring."""
        self.monitoring = True
        self.stat_monitoring.set("Running")
        self.add_log_entry("Network monitoring started", "INFO")
        self.update_status("Monitoring network traffic...")
        
        # In a real implementation, this would start packet capture
        self.simulate_network_traffic()
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring = False
        self.stat_monitoring.set("Stopped")
        self.add_log_entry("Network monitoring stopped", "INFO")
        self.update_status("Monitoring stopped")
    
    def simulate_network_traffic(self):
        """Simulate network traffic for demo purposes."""
        if not self.monitoring:
            return
        
        # Update stats
        self.packets_analyzed += 10
        self.stat_packets_analyzed.set(str(self.packets_analyzed))
        
        # Schedule next update
        self.root.after(1000, self.simulate_network_traffic)
    
    def add_alert(self, alert: Dict[str, Any]):
        """Add a new alert to the queue."""
        self.alert_queue.put(alert)
    
    def process_alerts(self):
        """Process queued alerts."""
        try:
            while not self.alert_queue.empty():
                alert = self.alert_queue.get_nowait()
                self.alerts.append(alert)
                self.add_alert_to_ui(alert)
                self.alert_queue.task_done()
                
                # Update stats
                if alert.get("action") == "Block":
                    self.threats_blocked += 1
                    self.stat_threats_blocked.set(str(self.threats_blocked))
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_alerts)
    
    def add_alert_to_ui(self, alert: Dict[str, Any]):
        """Add an alert to the UI."""
        # Add to dashboard
        self.alert_tree.insert(
            "", 
            0, 
            values=(
                alert.get("timestamp"),
                alert.get("severity", "Medium"),
                alert.get("src_ip", "N/A"),
                alert.get("dst_ip", "N/A"),
                alert.get("signature", "Unknown"),
                alert.get("action", "Alert")
            ),
            tags=(alert.get("severity", "Medium").lower(),)
        )
        
        # Keep only the last 100 alerts in the dashboard
        if len(self.alert_tree.get_children()) > 100:
            self.alert_tree.delete(self.alert_tree.get_children()[-1])
        
        # Add to alerts tab
        self.alerts_tree.insert(
            "", 
            0, 
            values=(
                alert.get("timestamp"),
                alert.get("severity", "Medium"),
                alert.get("src_ip", "N/A"),
                alert.get("src_port", ""),
                alert.get("dst_ip", "N/A"),
                alert.get("dst_port", ""),
                alert.get("protocol", "N/A"),
                alert.get("signature", "Unknown"),
                alert.get("action", "Alert")
            ),
            tags=(alert.get("severity", "Medium").lower(),)
        )
        
        # Auto-scroll to show new alerts
        self.alert_tree.see(tk.END)
        self.alerts_tree.see(tk.END)
    
    def view_alert_details(self, event=None):
        """Show details of the selected alert."""
        tree = self.alert_tree if event is None or event.widget == self.alert_tree else self.alerts_tree
        selected = tree.selection()
        if not selected:
            return
        
        item = selected[0]
        values = tree.item(item, "values")
        
        # Create a detailed view of the alert
        details = f"""
        Alert Details:
        - Time: {values[0]}
        - Severity: {values[1]}
        - Source: {values[2]}
        - Destination: {values[3]}
        - Signature: {values[4]}
        - Action: {values[5]}
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
