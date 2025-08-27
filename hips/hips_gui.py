"""
HIPS GUI Module

Provides a graphical interface for the Host Intrusion Prevention System.
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import os
import queue
import threading
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('hips.gui')

class HIPSGUI:
    """Main HIPS GUI application."""
    
    def __init__(self, root):
        """Initialize the HIPS GUI."""
        self.root = root
        self.root.title("Host Intrusion Prevention System")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize HIPS components
        self.monitoring = False
        self.events = []
        self.event_queue = queue.Queue()
        self.rules = {}
        self.load_rules()
        
        # Setup UI
        self.setup_ui()
        
        # Start event processing
        self.process_events()
    
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
        self.setup_process_monitor_tab()
        self.setup_network_firewall_tab()
        self.setup_rules_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(tab, text="System Status", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Stats grid
        stats = [
            ("Process Monitoring", "Stopped"),
            ("Network Firewall", "Inactive"),
            ("Exploit Prevention", "Inactive"),
            ("Active Rules", "0")
        ]
        
        for i, (label, value) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=i//2, column=i%2, padx=5, pady=5, sticky="nsew")
            
            ttk.Label(frame, text=label, font=('Arial', 10, 'bold')).pack()
            var = tk.StringVar(value=value)
            ttk.Label(frame, textvariable=var, font=('Arial', 12)).pack()
            
            # Store variables for updates
            setattr(self, f"stat_{label.lower().replace(' ', '_')}", var)
        
        # Recent events
        events_frame = ttk.LabelFrame(tab, text="Recent Security Events", padding=10)
        events_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Time", "Type", "Process", "Action", "Details")
        self.events_tree = ttk.Treeview(
            events_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {"Time": 150, "Type": 100, "Process": 150, "Action": 100, "Details": 300}
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(events_frame, orient="vertical", command=self.events_tree.yview)
        hsb = ttk.Scrollbar(events_frame, orient="horizontal", command=self.events_tree.xview)
        self.events_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Context menu
        self.event_menu = tk.Menu(events_frame, tearoff=0)
        self.event_menu.add_command(label="View Details", command=self.view_event_details)
        self.event_menu.add_command(label="Add to Rules", command=self.add_to_rules)
        self.events_tree.bind("<Button-3>", self.show_event_menu)
    
    def setup_process_monitor_tab(self):
        """Setup the process monitor tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Process Monitor")
        
        # Controls
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_monitor_btn = ttk.Button(
            control_frame,
            text="Start Monitoring",
            command=self.toggle_monitoring,
            style="Accent.TButton"
        )
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            control_frame,
            text="Add Rule",
            command=self.add_process_rule
        ).pack(side=tk.LEFT, padx=5)
        
        # Process list
        process_frame = ttk.LabelFrame(tab, text="Running Processes", padding=10)
        process_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("PID", "Name", "User", "CPU %", "Memory %", "Status")
        self.process_tree = ttk.Treeview(
            process_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {"PID": 80, "Name": 200, "User": 150, "CPU %": 80, "Memory %": 80, "Status": 100}
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_tree.yview)
        hsb = ttk.Scrollbar(process_frame, orient="horizontal", command=self.process_tree.xview)
        self.process_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Context menu
        self.process_menu = tk.Menu(process_frame, tearoff=0)
        self.process_menu.add_command(label="End Process", command=self.end_process)
        self.process_menu.add_command(label="Add to Blocklist", command=self.add_to_blocklist)
        self.process_menu.add_command(label="Properties", command=self.show_process_properties)
        self.process_tree.bind("<Button-3>", self.show_process_menu)
    
    def setup_network_firewall_tab(self):
        """Setup the network firewall tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Network Firewall")
        
        # Controls
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            control_frame,
            text="Add Rule",
            command=self.add_firewall_rule
        ).pack(side=tk.LEFT, padx=5)
        
        # Rules list
        rules_frame = ttk.LabelFrame(tab, text="Firewall Rules", padding=10)
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Enabled", "Name", "Direction", "Protocol", "Source", "Destination", "Ports", "Action")
        self.firewall_tree = ttk.Treeview(
            rules_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Enabled": 60, "Name": 150, "Direction": 80, "Protocol": 80,
            "Source": 120, "Destination": 120, "Ports": 100, "Action": 80
        }
        
        for col in columns:
            self.firewall_tree.heading(col, text=col)
            self.firewall_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(rules_frame, orient="vertical", command=self.firewall_tree.yview)
        hsb = ttk.Scrollbar(rules_frame, orient="horizontal", command=self.firewall_tree.xview)
        self.firewall_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.firewall_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Context menu
        self.rule_menu = tk.Menu(rules_frame, tearoff=0)
        self.rule_menu.add_command(label="Edit Rule", command=self.edit_firewall_rule)
        self.rule_menu.add_command(label="Delete Rule", command=self.delete_firewall_rule)
        self.rule_menu.add_separator()
        self.rule_menu.add_command(label="Enable/Disable", command=self.toggle_firewall_rule)
        self.firewall_tree.bind("<Button-3>", self.show_rule_menu)
    
    def setup_rules_tab(self):
        """Setup the rules management tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Rules")
        
        # Rules list
        rules_frame = ttk.LabelFrame(tab, text="HIPS Rules", padding=10)
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Enabled", "Name", "Type", "Target", "Action", "Description")
        self.rules_tree = ttk.Treeview(
            rules_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Enabled": 60, "Name": 150, "Type": 100,
            "Target": 200, "Action": 80, "Description": 300
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
        
        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="Add Rule", command=self.add_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Edit Rule", command=self.edit_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Import Rules", command=self.import_rules).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Export Rules", command=self.export_rules).pack(side=tk.RIGHT, padx=5)
        
        # Load sample rules
        self.load_sample_rules()
    
    def load_sample_rules(self):
        """Load sample rules into the UI."""
        sample_rules = [
            (True, "Block CMD", "Process", "cmd.exe", "Block", "Prevent command prompt execution"),
            (True, "Block PowerShell", "Process", "powershell.exe", "Block", "Prevent PowerShell execution"),
            (True, "Block Registry Edits", "Registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Block", "Prevent auto-run registry changes")
        ]
        
        for rule in sample_rules:
            self.rules_tree.insert("", tk.END, values=rule)
    
    def toggle_monitoring(self):
        """Toggle process monitoring."""
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.start_monitor_btn.config(text="Stop Monitoring")
            self.update_status("Process monitoring started")
            self.stat_process_monitoring.set("Running")
        else:
            self.start_monitor_btn.config(text="Start Monitoring")
            self.update_status("Process monitoring stopped")
            self.stat_process_monitoring.set("Stopped")
    
    def add_process_rule(self):
        """Add a new process rule."""
        self.show_rule_editor("process")
    
    def add_firewall_rule(self):
        """Add a new firewall rule."""
        self.show_rule_editor("firewall")
    
    def edit_firewall_rule(self):
        """Edit the selected firewall rule."""
        selected = self.firewall_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        # In a real implementation, this would open an editor with the rule details
        item = selected[0]
        values = self.firewall_tree.item(item, "values")
        self.show_rule_editor("firewall", values)
    
    def delete_firewall_rule(self):
        """Delete the selected firewall rule."""
        selected = self.firewall_tree.selection()
        if not selected:
            return
        
        if messagebox.askyesno("Confirm", "Delete selected rule(s)?"):
            for item in selected:
                self.firewall_tree.delete(item)
            self.update_status(f"Deleted {len(selected)} firewall rule(s)")
    
    def toggle_firewall_rule(self):
        """Toggle the selected firewall rule."""
        selected = self.firewall_tree.selection()
        if not selected:
            return
        
        for item in selected:
            values = list(self.firewall_tree.item(item, "values"))
            values[0] = not values[0]  # Toggle enabled state
            self.firewall_tree.item(item, values=values)
    
    def add_rule(self):
        """Add a new HIPS rule."""
        self.show_rule_editor("hips")
    
    def edit_rule(self):
        """Edit the selected HIPS rule."""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        # In a real implementation, this would open an editor with the rule details
        item = selected[0]
        values = self.rules_tree.item(item, "values")
        self.show_rule_editor("hips", values)
    
    def delete_rule(self):
        """Delete the selected HIPS rule."""
        selected = self.rules_tree.selection()
        if not selected:
            return
        
        if messagebox.askyesno("Confirm", "Delete selected rule(s)?"):
            for item in selected:
                self.rules_tree.delete(item)
            self.update_status(f"Deleted {len(selected)} rule(s)")
    
    def import_rules(self):
        """Import rules from a file."""
        file_path = filedialog.askopenfilename(
            title="Import Rules",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                rules = json.load(f)
                
                # In a real implementation, this would validate and add each rule
                messagebox.showinfo("Success", f"Imported {len(rules)} rules from {os.path.basename(file_path)}")
                self.update_status(f"Imported {len(rules)} rules from {os.path.basename(file_path)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")
            self.update_status(f"Failed to import rules: {e}")
    
    def export_rules(self):
        """Export rules to a file."""
        file_path = filedialog.asksaveasfilename(
            title="Export Rules",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # In a real implementation, this would collect all rules
            rules = [{"name": "Sample Rule", "type": "process", "action": "block"}]
            
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=4)
            
            messagebox.showinfo("Success", f"Exported {len(rules)} rules to {os.path.basename(file_path)}")
            self.update_status(f"Exported {len(rules)} rules to {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export rules: {e}")
            self.update_status(f"Failed to export rules: {e}")
    
    def show_rule_editor(self, rule_type, values=None):
        """Show the rule editor dialog."""
        editor = tk.Toplevel(self.root)
        editor.title(f"Add/Edit {rule_type.capitalize()} Rule")
        editor.geometry("500x300")
        
        # In a real implementation, this would have a form for editing rule details
        ttk.Label(editor, text=f"{rule_type.capitalize()} Rule Editor", font=('Arial', 12, 'bold')).pack(pady=10)
        
        if values:
            ttk.Label(editor, text=f"Editing rule: {values[1] if len(values) > 1 else 'Untitled'}").pack(pady=5)
        else:
            ttk.Label(editor, text="Create a new rule").pack(pady=5)
        
        # Simple form for demonstration
        ttk.Label(editor, text="Rule Name:").pack(pady=5)
        name_entry = ttk.Entry(editor, width=40)
        name_entry.pack(pady=5)
        
        if values and len(values) > 1:
            name_entry.insert(0, values[1])
        
        def save_rule():
            rule_name = name_entry.get().strip()
            if not rule_name:
                messagebox.showerror("Error", "Rule name is required")
                return
            
            # In a real implementation, this would save the rule
            messagebox.showinfo("Success", f"Rule '{rule_name}' saved")
            editor.destroy()
        
        btn_frame = ttk.Frame(editor)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save_rule).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Cancel", command=editor.destroy).pack(side=tk.LEFT, padx=10)
    
    def load_rules(self):
        """Load rules from disk."""
        # In a real app, this would load from a file
        self.rules = {
            "process": [],
            "firewall": [],
            "hips": []
        }
    
    def view_event_details(self):
        """Show details of the selected event."""
        selected = self.events_tree.selection()
        if not selected:
            return
        
        # In a real implementation, this would show detailed event information
        item = selected[0]
        values = self.events_tree.item(item, "values")
        messagebox.showinfo("Event Details", f"Details for event: {values}")
    
    def add_to_rules(self):
        """Add the selected event to rules."""
        selected = self.events_tree.selection()
        if not selected:
            return
        
        # In a real implementation, this would create a rule based on the event
        messagebox.showinfo("Info", "This would create a rule based on the selected event")
    
    def end_process(self):
        """End the selected process."""
        selected = self.process_tree.selection()
        if not selected:
            return
        
        if messagebox.askyesno("Confirm", "End the selected process(es)?"):
            # In a real implementation, this would terminate the process
            self.update_status(f"Ended {len(selected)} process(es)")
    
    def add_to_blocklist(self):
        """Add the selected process to blocklist."""
        selected = self.process_tree.selection()
        if not selected:
            return
        
        # In a real implementation, this would add the process to the blocklist
        self.update_status(f"Added {len(selected)} process(es) to blocklist")
    
    def show_process_properties(self):
        """Show properties of the selected process."""
        selected = self.process_tree.selection()
        if not selected:
            return
        
        # In a real implementation, this would show process details
        messagebox.showinfo("Process Properties", "Detailed process information would be shown here")
    
    def show_event_menu(self, event):
        """Show the context menu for events."""
        item = self.events_tree.identify_row(event.y)
        if item:
            self.events_tree.selection_set(item)
            self.event_menu.post(event.x_root, event.y)
    
    def show_process_menu(self, event):
        """Show the context menu for processes."""
        item = self.process_tree.identify_row(event.y)
        if item:
            self.process_tree.selection_set(item)
            self.process_menu.post(event.x_root, event.y)
    
    def show_rule_menu(self, event):
        """Show the context menu for rules."""
        item = self.firewall_tree.identify_row(event.y)
        if item:
            self.firewall_tree.selection_set(item)
            self.rule_menu.post(event.x_root, event.y)
    
    def process_events(self):
        """Process queued events."""
        try:
            while not self.event_queue.empty():
                event = self.event_queue.get_nowait()
                self.events.append(event)
                self.add_event_to_ui(event)
                self.event_queue.task_done()
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_events)
    
    def add_event_to_ui(self, event):
        """Add an event to the UI."""
        # In a real implementation, this would format the event for display
        self.events_tree.insert(
            "", 
            tk.END, 
            values=(
                datetime.now().strftime("%H:%M:%S"),
                "Security",
                event.get("process", "N/A"),
                event.get("action", "N/A"),
                event.get("details", "No details available")
            )
        )
        
        # Auto-scroll to show new events
        self.events_tree.see(tk.END)
    
    def update_status(self, message):
        """Update the status bar."""
        self.status_var.set(message)
        logger.info(f"Status: {message}")

def main():
    """Main entry point for the HIPS GUI application."""
    # Create and run the application
    root = tk.Tk()
    app = HIPSGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
