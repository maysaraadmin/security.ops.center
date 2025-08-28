"""
EDR GUI Module

Provides a graphical interface for the Endpoint Detection and Response system.
Only uses modules from the edr folder and standard library.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import threading
import queue
import os
import sys
import json

# Local imports from edr package
from . import __version__
from .core.detection import ThreatDetector
from .rule_manager import RuleManager
from .threat_detection import ThreatDetectionEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('edr.gui')

class EDRApp:
    """Main EDR GUI application."""
    
    def __init__(self, root):
        """Initialize the EDR GUI."""
        self.root = root
        self.root.title(f"Endpoint Detection and Response v{__version__}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize EDR components
        self.detector = ThreatDetector()
        self.rule_manager = RuleManager()
        self.detection_engine = ThreatDetectionEngine()
        
        # Data storage
        self.alerts = []
        self.events_queue = queue.Queue()
        self.running = False
        
        # Setup UI
        self.setup_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_alerts_tab()
        self.setup_rules_tab()
        self.setup_logs_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab."""
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.dashboard_tab, text="System Status", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Stats labels
        stats = [
            ("Threats Detected:", "0"),
            ("Active Rules:", str(len(self.rule_manager.rules))),
            ("System Status:", "Running" if self.running else "Stopped")
        ]
        
        for i, (label, value) in enumerate(stats):
            ttk.Label(stats_frame, text=label, font=('Arial', 10, 'bold')).grid(row=0, column=i*2, padx=10, pady=5, sticky=tk.W)
            ttk.Label(stats_frame, text=value).grid(row=0, column=i*2+1, padx=10, pady=5, sticky=tk.W)
        
        # Controls frame
        ctrl_frame = ttk.Frame(self.dashboard_tab)
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Control buttons
        self.start_btn = ttk.Button(
            ctrl_frame,
            text="Start Monitoring",
            command=self.start_monitoring,
            style="Accent.TButton"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            ctrl_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Recent alerts frame
        alerts_frame = ttk.LabelFrame(self.dashboard_tab, text="Recent Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alerts treeview
        columns = ("Time", "Severity", "Rule", "Description")
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {"Time": 150, "Severity": 100, "Rule": 200, "Description": 400}
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        vsb = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        hsb = ttk.Scrollbar(alerts_frame, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_alerts_tab(self):
        """Setup the alerts tab."""
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="Alerts")
        
        # Alerts controls
        ctrl_frame = ttk.Frame(self.alerts_tab)
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Filter controls
        ttk.Label(ctrl_frame, text="Filter by:").pack(side=tk.LEFT, padx=5)
        
        self.severity_var = tk.StringVar()
        self.severity_filter = ttk.Combobox(
            ctrl_frame,
            textvariable=self.severity_var,
            values=["All", "Low", "Medium", "High", "Critical"],
            state="readonly",
            width=10
        )
        self.severity_filter.current(0)
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        
        # Search box
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(ctrl_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind("<Return>", lambda e: self.filter_alerts())
        
        search_btn = ttk.Button(
            ctrl_frame,
            text="Search",
            command=self.filter_alerts
        )
        search_btn.pack(side=tk.LEFT, padx=5)
        
        # Alerts treeview
        alerts_frame = ttk.Frame(self.alerts_tab)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Time", "Severity", "Rule", "Process", "Description")
        self.all_alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Time": 150,
            "Severity": 100,
            "Rule": 200,
            "Process": 150,
            "Description": 300
        }
        
        for col in columns:
            self.all_alerts_tree.heading(col, text=col)
            self.all_alerts_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        vsb = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.all_alerts_tree.yview)
        hsb = ttk.Scrollbar(alerts_frame, orient="horizontal", command=self.all_alerts_tree.xview)
        self.all_alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.all_alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Alert details
        details_frame = ttk.LabelFrame(self.alerts_tab, text="Alert Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        self.alert_details = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            height=8,
            state=tk.DISABLED
        )
        self.alert_details.pack(fill=tk.BOTH, expand=True)
        
        # Bind selection event
        self.all_alerts_tree.bind("<<TreeviewSelect>>", self.on_alert_select)
    
    def setup_rules_tab(self):
        """Setup the rules management tab."""
        self.rules_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_tab, text="Rules")
        
        # Rules list frame
        list_frame = ttk.Frame(self.rules_tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Rules treeview
        columns = ("Enabled", "Name", "Severity", "Description")
        self.rules_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {"Enabled": 60, "Name": 200, "Severity": 100, "Description": 400}
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.rules_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.rules_tree.xview)
        self.rules_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Buttons frame
        btn_frame = ttk.Frame(self.rules_tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        add_btn = ttk.Button(
            btn_frame,
            text="Add Rule",
            command=self.add_rule
        )
        add_btn.pack(side=tk.LEFT, padx=5)
        
        edit_btn = ttk.Button(
            btn_frame,
            text="Edit Rule",
            command=self.edit_rule
        )
        edit_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = ttk.Button(
            btn_frame,
            text="Delete Rule",
            command=self.delete_rule
        )
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        # Load rules into the treeview
        self.load_rules()
    
    def setup_logs_tab(self):
        """Setup the logs tab."""
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Logs text widget
        self.logs_text = scrolledtext.ScrolledText(
            self.logs_tab,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self.logs_tab, orient="vertical", command=self.logs_text.yview)
        hsb = ttk.Scrollbar(self.logs_tab, orient="horizontal", command=self.logs_text.xview)
        self.logs_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Log level filter
        log_frame = ttk.Frame(self.logs_tab)
        log_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(log_frame, text="Log Level:").pack(side=tk.LEFT, padx=5)
        
        self.log_level = tk.StringVar(value="INFO")
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        log_menu = ttk.OptionMenu(
            log_frame,
            self.log_level,
            "INFO",
            *log_levels,
            command=self.update_log_level
        )
        log_menu.pack(side=tk.LEFT, padx=5)
        
        # Log actions
        clear_btn = ttk.Button(
            log_frame,
            text="Clear Logs",
            command=self.clear_logs
        )
        clear_btn.pack(side=tk.RIGHT, padx=5)
        
        save_btn = ttk.Button(
            log_frame,
            text="Save Logs",
            command=self.save_logs
        )
        save_btn.pack(side=tk.RIGHT, padx=5)
    
    def start_monitoring(self):
        """Start the EDR monitoring."""
        try:
            self.log("Starting EDR monitoring...")
            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            # Start monitoring in a separate thread
            monitor_thread = threading.Thread(
                target=self.run_monitoring,
                daemon=True
            )
            monitor_thread.start()
            
            # Start UI update loop
            self.update_ui()
            
            self.update_status("Monitoring started")
            self.log("EDR monitoring started successfully")
            
        except Exception as e:
            self.log(f"Error starting monitoring: {e}", logging.ERROR)
            messagebox.showerror("Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop the EDR monitoring."""
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_status("Monitoring stopped")
        self.log("EDR monitoring stopped")
    
    def run_monitoring(self):
        """Run the EDR monitoring in a background thread."""
        try:
            while self.running:
                # Simulate monitoring
                # In a real implementation, this would monitor system events
                time.sleep(1)
                
                # Simulate occasional alerts
                if self.running and time.time() % 10 < 0.1:  # ~every 10 seconds
                    alert = {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": "Medium",
                        "rule": "Suspicious Process Detected",
                        "process": "suspicious.exe",
                        "description": "A potentially malicious process was detected"
                    }
                    self.events_queue.put(("alert", alert))
                    
        except Exception as e:
            self.events_queue.put(("error", str(e)))
    
    def update_ui(self):
        """Update the UI with new events and alerts."""
        try:
            while True:
                try:
                    event_type, data = self.events_queue.get_nowait()
                    if event_type == "alert":
                        self.handle_alert(data)
                    elif event_type == "error":
                        self.log(f"Error in monitoring: {data}", logging.ERROR)
                except queue.Empty:
                    break
            
            # Schedule the next update
            if self.running:
                self.root.after(100, self.update_ui)
                
        except Exception as e:
            self.log(f"Error updating UI: {e}", logging.ERROR)
    
    def handle_alert(self, alert: Dict[str, Any]):
        """Handle a new alert."""
        self.alerts.append(alert)
        
        # Add to alerts tree
        self.all_alerts_tree.insert("", "end", values=(
            alert["time"],
            alert["severity"],
            alert["rule"],
            alert["process"],
            alert["description"]
        ))
        
        # Also add to dashboard if it's a high severity alert
        if alert["severity"] in ["High", "Critical"]:
            self.alerts_tree.insert("", "end", values=(
                alert["time"],
                alert["severity"],
                alert["rule"],
                alert["description"]
            ))
            
            # Keep only the last 10 alerts in the dashboard
            if len(self.alerts_tree.get_children()) > 10:
                self.alerts_tree.delete(self.alerts_tree.get_children()[0])
        
        self.log(f"Alert: {alert['description']}")
    
    def filter_alerts(self):
        """Filter alerts based on search criteria."""
        search_term = self.search_var.get().lower()
        severity = self.severity_var.get()
        
        # Clear current selection
        for item in self.all_alerts_tree.get_children():
            self.all_alerts_tree.delete(item)
        
        # Filter and add matching alerts
        for alert in self.alerts:
            if (severity == "All" or alert["severity"] == severity) and \
               (not search_term or 
                search_term in alert["description"].lower() or
                search_term in alert["process"].lower() or
                search_term in alert["rule"].lower()):
                
                self.all_alerts_tree.insert("", "end", values=(
                    alert["time"],
                    alert["severity"],
                    alert["rule"],
                    alert["process"],
                    alert["description"]
                ))
    
    def on_alert_select(self, event):
        """Handle alert selection event."""
        selected = self.all_alerts_tree.selection()
        if not selected:
            return
            
        # Get the selected alert
        item = self.all_alerts_tree.item(selected[0])
        values = item['values']
        
        # Display alert details
        details = f"""Time: {values[0]}
Severity: {values[1]}
Rule: {values[2]}
Process: {values[3]}

Description:
{values[4]}"""
        
        self.alert_details.config(state=tk.NORMAL)
        self.alert_details.delete(1.0, tk.END)
        self.alert_details.insert(tk.END, details)
        self.alert_details.config(state=tk.DISABLED)
    
    def load_rules(self):
        """Load rules into the rules treeview."""
        try:
            # Clear existing rules
            for item in self.rules_tree.get_children():
                self.rules_tree.delete(item)
            
            # Add rules from rule manager
            for rule in self.rule_manager.rules:
                self.rules_tree.insert("", "end", values=(
                    "✓" if rule.get("enabled", True) else "✗",
                    rule.get("name", "Unnamed"),
                    rule.get("severity", "Medium"),
                    rule.get("description", "No description")
                ))
                
        except Exception as e:
            self.log(f"Error loading rules: {e}", logging.ERROR)
    
    def add_rule(self):
        """Add a new rule."""
        # In a real implementation, this would open a dialog to create a new rule
        messagebox.showinfo("Info", "Add Rule functionality will be implemented here")
    
    def edit_rule(self):
        """Edit the selected rule."""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
            
        # In a real implementation, this would open a dialog to edit the rule
        messagebox.showinfo("Info", "Edit Rule functionality will be implemented here")
    
    def delete_rule(self):
        """Delete the selected rule."""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to delete the selected rule?"):
            # In a real implementation, this would delete the rule from the rule manager
            self.rules_tree.delete(selected[0])
            self.log(f"Deleted rule: {selected[0]}")
    
    def update_log_level(self, level: str):
        """Update the log level filter."""
        logging.getLogger().setLevel(level)
        self.log(f"Log level set to {level}")
    
    def clear_logs(self):
        """Clear the logs."""
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.config(state=tk.DISABLED)
    
    def save_logs(self):
        """Save logs to a file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                
                self.log(f"Logs saved to {file_path}")
                messagebox.showinfo("Save Complete", f"Logs saved to {file_path}")

            except Exception as e:
                self.log(f"Error saving logs: {e}", logging.ERROR)
                messagebox.showerror("Save Error", f"Failed to save logs: {e}")
    
    def log(self, message: str, level: int = logging.INFO):
        """Log a message to the log window and the console."""
        logger.log(level, message)
        
        # Update log text widget
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.insert(tk.END, f"[{logging.getLevelName(level)}] {message}\n")
        self.logs_text.see(tk.END)
        self.logs_text.config(state=tk.DISABLED)
    
    def update_status(self, message: str):
        """Update the status bar."""
        self.status_var.set(message)
    
    def on_closing(self):
        """Handle window close event."""
        if self.running:
            if messagebox.askokcancel("Quit", "Monitoring is still active. Are you sure you want to quit?"):
                self.running = False
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """Main entry point for the EDR GUI application."""
    try:
        # Set up the root window
        root = tk.Tk()
        
        # Set theme and styles
        style = ttk.Style()
        available_themes = style.theme_names()
        # Use 'clam' if available, otherwise use the first available theme
        theme = 'clam' if 'clam' in available_themes else available_themes[0] if available_themes else None
        if theme:
            style.theme_use(theme)
        
        # Set window icon if available
        try:
            # Try to set a window icon if available in the edr package
            icon_path = os.path.join(os.path.dirname(__file__), 'resources', 'edr_icon.ico')
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except Exception as e:
            logging.warning(f"Could not set window icon: {e}")
        
        # Create and run the application
        app = EDRApp(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        root.mainloop()
        
    except Exception as e:
        logging.critical(f"Fatal error in EDR GUI: {e}", exc_info=True)
        messagebox.showerror(
            "Fatal Error",
            f"A fatal error occurred in the EDR application:\n{str(e)}\n\n"
            "Please check the logs for more details."
        )

if __name__ == "__main__":
    main()
