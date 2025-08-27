"""
DLP View - GUI for Data Loss Prevention functionality.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from datetime import datetime
import threading
import queue
import os
from typing import Dict, List, Optional, Any, Callable

from src.dlp.manager import DLPManager

class DLPView:
    """GUI for Data Loss Prevention functionality."""
    
    def __init__(self, parent, dlp_manager: DLPManager = None):
        """
        Initialize the DLP view.
        
        Args:
            parent: Parent widget
            dlp_manager: Optional DLPManager instance (will create one if not provided)
        """
        self.parent = parent
        self.style = ttk.Style()
        
        # Create DLP manager if not provided
        self.dlp = dlp_manager or DLPManager(alert_callback=self._handle_alert)
        
        # Configure styles
        self._configure_styles()
        
        # Create main frame
        self.frame = ttk.Frame(parent, padding=10)
        self.is_visible = False
        
        # Create GUI elements
        self._create_widgets()
        
        # Start with monitoring off
        self.monitoring = False
        
        # Queue for thread-safe GUI updates
        self.update_queue = queue.Queue()
        self.parent.after(100, self.process_queue)
        
        # Start with default watch directories
        self._add_default_watch_dirs()
    
    def _configure_styles(self):
        """Configure custom styles for the DLP view."""
        self.style.configure('DLP.TFrame', background='white')
        self.style.configure('DLP.Header.TLabel', font=('Arial', 14, 'bold'), background='white')
        self.style.configure('DLP.Metric.TLabel', font=('Arial', 18, 'bold'), background='white')
        self.style.configure('DLP.Alert.High.TLabel', background='#ffebee', foreground='#c62828', font=('Arial', 10, 'bold'))
        self.style.configure('DLP.Alert.Medium.TLabel', background='#fff8e1', foreground='#ff8f00', font=('Arial', 10, 'bold'))
        self.style.configure('DLP.Alert.Low.TLabel', background='#e8f5e9', foreground='#2e7d32', font=('Arial', 10))
    
    def _create_widgets(self):
        """Create and arrange all GUI widgets."""
        # Main container with scrollbar
        main_container = ttk.Frame(self.frame, style='DLP.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='DLP.TFrame')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Header
        header_frame = ttk.Frame(scrollable_frame, style='DLP.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            header_frame,
            text="Data Loss Prevention",
            style='DLP.Header.TLabel'
        ).pack(side=tk.LEFT)
        
        # Control buttons
        btn_frame = ttk.Frame(header_frame, style='DLP.TFrame')
        btn_frame.pack(side=tk.RIGHT)
        
        self.start_btn = ttk.Button(
            btn_frame,
            text="Start Monitoring",
            command=self.toggle_monitoring
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        # Status indicators
        status_frame = ttk.Frame(scrollable_frame, style='DLP.TFrame')
        status_frame.pack(fill=tk.X, pady=10)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(
            status_frame,
            text="Statistics",
            style='DLP.TFrame',
            padding=10
        )
        stats_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Stats grid
        self._create_stat_widgets(stats_frame)
        
        # Alert summary frame
        alert_frame = ttk.LabelFrame(
            status_frame,
            text="Alerts",
            style='DLP.TFrame',
            padding=10
        )
        alert_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Alert summary
        self._create_alert_summary(alert_frame)
        
        # Watch directories frame
        dirs_frame = ttk.LabelFrame(
            scrollable_frame,
            text="Monitored Directories",
            style='DLP.TFrame',
            padding=10
        )
        dirs_frame.pack(fill=tk.X, pady=(10, 5))
        
        # Directory list with scrollbar
        dir_list_frame = ttk.Frame(dirs_frame)
        dir_list_frame.pack(fill=tk.X, pady=5)
        
        self.dir_list = tk.Listbox(
            dir_list_frame,
            height=5,
            selectmode=tk.SINGLE
        )
        scrollbar_dirs = ttk.Scrollbar(dir_list_frame, orient="vertical")
        scrollbar_dirs.config(command=self.dir_list.yview)
        self.dir_list.config(yscrollcommand=scrollbar_dirs.set)
        
        self.dir_list.pack(side=tk.LEFT, fill=tk.X, expand=True)
        scrollbar_dirs.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Directory buttons
        dir_btn_frame = ttk.Frame(dirs_frame)
        dir_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            dir_btn_frame,
            text="Add Directory",
            command=self._add_directory
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            dir_btn_frame,
            text="Remove Selected",
            command=self._remove_directory
        ).pack(side=tk.LEFT, padx=2)
        
        # Rules frame
        rules_frame = ttk.LabelFrame(
            scrollable_frame,
            text="Detection Rules",
            style='DLP.TFrame',
            padding=10
        )
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        
        # Create rules treeview
        self._create_rules_table(rules_frame)
        
        # Alert log frame
        log_frame = ttk.LabelFrame(
            scrollable_frame,
            text="Alert Log",
            style='DLP.TFrame',
            padding=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create alert log
        self.alert_log = ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=10,
            font=('Consolas', 9),
            state='disabled'
        )
        self.alert_log.pack(fill=tk.BOTH, expand=True)
    
    def _create_stat_widgets(self, parent):
        """Create statistic widgets."""
        # Stats grid
        stats_grid = ttk.Frame(parent, style='DLP.TFrame')
        stats_grid.pack(fill=tk.X)
        
        # Files scanned
        ttk.Label(stats_grid, text="Files Scanned:", style='DLP.TLabel').grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.files_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.files_var, style='DLP.Metric.TLabel').grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Alerts triggered
        ttk.Label(stats_grid, text="Alerts Triggered:", style='DLP.TLabel').grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.alerts_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.alerts_var, style='DLP.Metric.TLabel').grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Uptime
        ttk.Label(stats_grid, text="Uptime:", style='DLP.TLabel').grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.uptime_var = tk.StringVar(value="00:00:00")
        ttk.Label(stats_grid, textvariable=self.uptime_var, style='DLP.Metric.TLabel').grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Rules loaded
        ttk.Label(stats_grid, text="Rules Loaded:", style='DLP.TLabel').grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.rules_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.rules_var, style='DLP.Metric.TLabel').grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
    
    def _create_alert_summary(self, parent):
        """Create alert summary widgets."""
        alert_grid = ttk.Frame(parent, style='DLP.TFrame')
        alert_grid.pack(fill=tk.X)
        
        # Critical alerts
        ttk.Label(alert_grid, text="Critical:", style='DLP.Alert.High.TLabel').grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.critical_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.critical_var, style='DLP.Alert.High.TLabel').grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # High alerts
        ttk.Label(alert_grid, text="High:", style='DLP.Alert.High.TLabel').grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.high_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.high_var, style='DLP.Alert.High.TLabel').grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Medium alerts
        ttk.Label(alert_grid, text="Medium:", style='DLP.Alert.Medium.TLabel').grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.medium_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.medium_var, style='DLP.Alert.Medium.TLabel').grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Low alerts
        ttk.Label(alert_grid, text="Low:", style='DLP.Alert.Low.TLabel').grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.low_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.low_var, style='DLP.Alert.Low.TLabel').grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Last alert
        ttk.Label(alert_grid, text="Last Alert:", style='DLP.TLabel').grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        self.last_alert_var = tk.StringVar(value="Never")
        ttk.Label(alert_grid, textvariable=self.last_alert_var, style='DLP.TLabel').grid(row=2, column=2, columnspan=2, sticky=tk.W, padx=5, pady=2)
    
    def _create_rules_table(self, parent):
        """Create the rules table."""
        # Create treeview with scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollbars
        y_scroll = ttk.Scrollbar(tree_frame)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create treeview
        self.rules_tree = ttk.Treeview(
            tree_frame,
            yscrollcommand=y_scroll.set,
            xscrollcommand=x_scroll.set,
            columns=('id', 'name', 'severity', 'enabled', 'action'),
            show='headings',
            height=6
        )
        
        # Configure scrollbars
        y_scroll.config(command=self.rules_tree.yview)
        x_scroll.config(command=self.rules_tree.xview)
        
        # Define columns
        self.rules_tree.heading('id', text='ID', anchor=tk.W)
        self.rules_tree.heading('name', text='Rule Name', anchor=tk.W)
        self.rules_tree.heading('severity', text='Severity', anchor=tk.W)
        self.rules_tree.heading('enabled', text='Enabled', anchor=tk.W)
        self.rules_tree.heading('action', text='Action', anchor=tk.W)
        
        # Configure column widths
        self.rules_tree.column('id', width=80, minwidth=50, stretch=tk.NO)
        self.rules_tree.column('name', width=200, minwidth=150, stretch=tk.YES)
        self.rules_tree.column('severity', width=80, minwidth=70, stretch=tk.NO)
        self.rules_tree.column('enabled', width=70, minwidth=60, stretch=tk.NO)
        self.rules_tree.column('action', width=80, minwidth=70, stretch=tk.NO)
        
        self.rules_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add context menu for rules
        self._setup_rules_context_menu()
        
        # Load rules
        self._load_rules()
    
    def _setup_rules_context_menu(self):
        """Set up the context menu for rules."""
        self.rules_menu = tk.Menu(self.frame, tearoff=0)
        self.rules_menu.add_command(label="Enable/Disable", command=self._toggle_selected_rule)
        self.rules_menu.add_command(label="View Details", command=self._view_rule_details)
        
        # Bind right-click event
        self.rules_tree.bind("<Button-3>", self._show_rules_context_menu)
    
    def _show_rules_context_menu(self, event):
        """Show the context menu for rules."""
        item = self.rules_tree.identify_row(event.y)
        if item:
            self.rules_tree.selection_set(item)
            self.rules_menu.post(event.x_root, event.y_root)
    
    def _toggle_selected_rule(self):
        """Toggle the enabled state of the selected rule."""
        selection = self.rules_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.rules_tree.item(item, 'values')
        if not values:
            return
            
        rule_id = values[0]
        current_state = values[3].lower() == 'yes'
        
        # Toggle the rule state
        new_state = self.dlp.toggle_rule(rule_id, not current_state)
        
        # Update the UI
        if new_state is not None:
            self._load_rules()
    
    def _view_rule_details(self):
        """Show details for the selected rule."""
        selection = self.rules_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.rules_tree.item(item, 'values')
        if not values:
            return
            
        rule_id = values[0]
        rules = self.dlp.get_rules()
        rule = next((r for r in rules if r['id'] == rule_id), None)
        
        if not rule:
            return
        
        # Create a details window
        details_win = tk.Toplevel(self.frame)
        details_win.title(f"Rule Details: {rule['name']}")
        details_win.geometry("600x400")
        
        # Create a text widget to display rule details
        text = ScrolledText(details_win, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format rule details
        details = f"ID: {rule['id']}\n"
        details += f"Name: {rule['name']}\n"
        details += f"Description: {rule['description']}\n"
        details += f"Severity: {rule['severity'].capitalize()}\n"
        details += f"Status: {'Enabled' if rule['enabled'] else 'Disabled'}\n"
        details += f"Action: {rule['action'].capitalize()}\n"
        details += f"\nPatterns: {rule['pattern_count']}\n"
        details += f"Keywords: {rule['keyword_count']}\n"
        details += f"Minimum Confidence: {rule['min_confidence']*100:.1f}%"
        
        text.insert(tk.END, details)
        text.config(state='disabled')
        
        # Add close button
        btn_frame = ttk.Frame(details_win)
        btn_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        ttk.Button(
            btn_frame,
            text="Close",
            command=details_win.destroy
        ).pack(side=tk.RIGHT)
    
    def _add_directory(self):
        """Add a directory to monitor."""
        directory = filedialog.askdirectory(title="Select Directory to Monitor")
        if directory:
            self.dlp.add_watch_directory(directory, recursive=True)
            self._update_directory_list()
    
    def _remove_directory(self):
        """Remove the selected directory from monitoring."""
        selection = self.dir_list.curselection()
        if not selection:
            return
            
        directory = self.dir_list.get(selection[0])
        self.dlp.remove_watch_directory(directory)
        self._update_directory_list()
    
    def _update_directory_list(self):
        """Update the list of monitored directories."""
        self.dir_list.delete(0, tk.END)
        for directory in self.dlp.get_watch_directories():
            self.dir_list.insert(tk.END, directory)
    
    def _add_default_watch_dirs(self):
        """Add some default directories to monitor."""
        default_dirs = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
        ]
        
        for directory in default_dirs:
            if os.path.isdir(directory):
                self.dlp.add_watch_directory(directory, recursive=True)
        
        # Update the directory list in the UI
        self._update_directory_list()
    
    def _load_rules(self):
        """Load rules into the rules table."""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add rules from DLP manager
        rules = self.dlp.get_rules()
        for rule in rules:
            self.rules_tree.insert(
                '', 'end',
                values=(
                    rule['id'],
                    rule['name'],
                    rule['severity'].capitalize(),
                    'Yes' if rule['enabled'] else 'No',
                    rule['action'].capitalize()
                ),
                tags=('enabled' if rule['enabled'] else 'disabled',)
            )
        
        # Configure tag colors
        self.rules_tree.tag_configure('enabled', background='#e8f5e9')
        self.rules_tree.tag_configure('disabled', background='#ffebee')
        
        # Update rules count
        self.rules_var.set(str(len(rules)))
    
    def toggle_monitoring(self):
        """Toggle DLP monitoring on/off."""
        if not self.monitoring:
            # Start monitoring
            self.monitoring = True
            self.start_btn.config(text="Stop Monitoring")
            self.dlp.start()
            self.update_ui_loop()
        else:
            # Stop monitoring
            self.monitoring = False
            self.start_btn.config(text="Start Monitoring")
            self.dlp.stop()
    
    def process_queue(self):
        """Process messages from the update queue."""
        try:
            while True:
                try:
                    alert = self.update_queue.get_nowait()
                    self._handle_alert(alert)
                except queue.Empty:
                    break
        except Exception as e:
            print(f"Error processing queue: {e}")
        
        # Schedule the next check
        self.parent.after(100, self.process_queue)
    
    def _handle_alert(self, alert):
        """Handle a DLP alert."""
        # Update alert counts
        severity = alert.get('severity', 'low').lower()
        
        if severity == 'critical':
            self.critical_var.set(str(int(self.critical_var.get() or 0) + 1))
        elif severity == 'high':
            self.high_var.set(str(int(self.high_var.get() or 0) + 1))
        elif severity == 'medium':
            self.medium_var.set(str(int(self.medium_var.get() or 0) + 1))
        else:
            self.low_var.set(str(int(self.low_var.get() or 0) + 1))
        
        # Update last alert time
        self.last_alert_var = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log the alert
        self._log_alert(alert)
    
    def _log_alert(self, alert):
        """Log an alert to the alert log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        severity = alert.get('severity', 'info').upper()
        source = alert.get('source', 'Unknown')
        rule_name = alert.get('rule_name', 'Unknown Rule')
        
        log_entry = f"[{timestamp}] [{severity}] {rule_name} in {source}\n"
        
        self.alert_log.config(state='normal')
        self.alert_log.insert(tk.END, log_entry)
        self.alert_log.see(tk.END)
        self.alert_log.config(state='disabled')
    
    def update_ui_loop(self):
        """Update the UI with current DLP status."""
        if not self.monitoring:
            return
            
        try:
            # Get current status from DLP manager
            status = self.dlp.get_status()
            
            # Update UI elements
            self.files_var.set(f"{status.get('files_scanned', 0):,}")
            self.alerts_var.set(f"{status.get('alerts_triggered', 0):,}")
            
            # Update uptime
            uptime_sec = status.get('uptime_seconds', 0)
            hours, remainder = divmod(int(uptime_sec), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.uptime_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update rules count if changed
            current_rules = len(self.rules_tree.get_children())
            if current_rules != status.get('rules_loaded', 0):
                self._load_rules()
            
        except Exception as e:
            print(f"Error updating UI: {e}")
        
        # Schedule the next update
        if self.monitoring:
            self.parent.after(1000, self.update_ui_loop)
    
    def show(self):
        """Show the DLP view."""
        if not self.is_visible:
            self.frame.pack(fill=tk.BOTH, expand=True)
            self.is_visible = True
    
    def hide(self):
        """Hide the DLP view."""
        if self.is_visible:
            self.frame.pack_forget()
            self.is_visible = False
