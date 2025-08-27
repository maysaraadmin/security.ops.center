"""
NDR View - GUI for Network Detection and Response functionality.
"""
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from datetime import datetime
import threading
import queue
import json
from typing import Dict, List, Optional, Any, Callable
import psutil

from src.ndr.manager import NDRManager

class NDRView:
    """GUI for Network Detection and Response functionality."""
    
    def __init__(self, parent, ndr_manager: NDRManager):
        """
        Initialize the NDR view.
        
        Args:
            parent: Parent widget
            ndr_manager: NDRManager instance
        """
        self.ndr = ndr_manager
        self.parent = parent
        self.style = ttk.Style()
        
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
    
    def _configure_styles(self):
        """Configure custom styles for the NDR view."""
        self.style.configure(
            'NDR.TFrame',
            background='white'
        )
        self.style.configure(
            'NDR.Header.TLabel',
            font=('Arial', 14, 'bold'),
            background='white'
        )
        self.style.configure(
            'NDR.Metric.TLabel',
            font=('Arial', 18, 'bold'),
            background='white'
        )
        self.style.configure(
            'NDR.Alert.High.TLabel',
            background='#ffebee',
            foreground='#c62828',
            font=('Arial', 10, 'bold')
        )
        self.style.configure(
            'NDR.Alert.Medium.TLabel',
            background='#fff8e1',
            foreground='#ff8f00',
            font=('Arial', 10, 'bold')
        )
        self.style.configure(
            'NDR.Alert.Low.TLabel',
            background='#e8f5e9',
            foreground='#2e7d32',
            font=('Arial', 10)
        )
    
    def _create_widgets(self):
        """Create and arrange all GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.frame, style='NDR.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame, style='NDR.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            header_frame,
            text="Network Detection & Response",
            style='NDR.Header.TLabel'
        ).pack(side=tk.LEFT)
        
        # Control buttons
        btn_frame = ttk.Frame(header_frame, style='NDR.TFrame')
        btn_frame.pack(side=tk.RIGHT)
        
        self.start_btn = ttk.Button(
            btn_frame,
            text="Start Monitoring",
            command=self.toggle_monitoring
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        # Status indicators
        status_frame = ttk.Frame(main_frame, style='NDR.TFrame')
        status_frame.pack(fill=tk.X, pady=10)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(
            status_frame,
            text="Statistics",
            style='NDR.TFrame',
            padding=10
        )
        stats_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Stats grid
        self._create_stat_widgets(stats_frame)
        
        # Alert summary frame
        alert_frame = ttk.LabelFrame(
            status_frame,
            text="Alerts",
            style='NDR.TFrame',
            padding=10
        )
        alert_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Alert summary
        self._create_alert_summary(alert_frame)
        
        # Alert log
        log_frame = ttk.LabelFrame(
            main_frame,
            text="Alert Log",
            style='NDR.TFrame',
            padding=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.alert_log = ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=10,
            font=('Consolas', 9),
            state='disabled'
        )
        self.alert_log.pack(fill=tk.BOTH, expand=True)
        
        # Rules frame
        rules_frame = ttk.LabelFrame(
            main_frame,
            text="Detection Rules",
            style='NDR.TFrame',
            padding=10
        )
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self._create_rules_table(rules_frame)
    
    def _create_stat_widgets(self, parent):
        """Create statistic widgets."""
        # Stats grid
        stats_grid = ttk.Frame(parent, style='NDR.TFrame')
        stats_grid.pack(fill=tk.X)
        
        # Packets processed
        ttk.Label(
            stats_grid,
            text="Packets:",
            style='NDR.TLabel'
        ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.packets_var = tk.StringVar(value="0")
        ttk.Label(
            stats_grid,
            textvariable=self.packets_var,
            style='NDR.Metric.TLabel'
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Alerts triggered
        ttk.Label(
            stats_grid,
            text="Alerts:",
            style='NDR.TLabel'
        ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.alerts_var = tk.StringVar(value="0")
        ttk.Label(
            stats_grid,
            textvariable=self.alerts_var,
            style='NDR.Metric.TLabel'
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Uptime
        ttk.Label(
            stats_grid,
            text="Uptime:",
            style='NDR.TLabel'
        ).grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        
        self.uptime_var = tk.StringVar(value="00:00:00")
        ttk.Label(
            stats_grid,
            textvariable=self.uptime_var,
            style='NDR.Metric.TLabel'
        ).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Interface
        ttk.Label(
            stats_grid,
            text="Interface:",
            style='NDR.TLabel'
        ).grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        
        self.iface_var = tk.StringVar(value="Not monitoring")
        ttk.Label(
            stats_grid,
            textvariable=self.iface_var,
            style='NDR.Metric.TLabel'
        ).grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
    
    def _create_alert_summary(self, parent):
        """Create alert summary widgets."""
        alert_grid = ttk.Frame(parent, style='NDR.TFrame')
        alert_grid.pack(fill=tk.X)
        
        # Critical alerts
        ttk.Label(
            alert_grid,
            text="Critical:",
            style='NDR.Alert.High.TLabel'
        ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.critical_var = tk.StringVar(value="0")
        ttk.Label(
            alert_grid,
            textvariable=self.critical_var,
            style='NDR.Alert.High.TLabel'
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # High alerts
        ttk.Label(
            alert_grid,
            text="High:",
            style='NDR.Alert.High.TLabel'
        ).grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        
        self.high_var = tk.StringVar(value="0")
        ttk.Label(
            alert_grid,
            textvariable=self.high_var,
            style='NDR.Alert.High.TLabel'
        ).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Medium alerts
        ttk.Label(
            alert_grid,
            text="Medium:",
            style='NDR.Alert.Medium.TLabel'
        ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.medium_var = tk.StringVar(value="0")
        ttk.Label(
            alert_grid,
            textvariable=self.medium_var,
            style='NDR.Alert.Medium.TLabel'
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Low alerts
        ttk.Label(
            alert_grid,
            text="Low:",
            style='NDR.Alert.Low.TLabel'
        ).grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        
        self.low_var = tk.StringVar(value="0")
        ttk.Label(
            alert_grid,
            textvariable=self.low_var,
            style='NDR.Alert.Low.TLabel'
        ).grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Last alert
        ttk.Label(
            alert_grid,
            text="Last Alert:",
            style='NDR.TLabel'
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        self.last_alert_var = tk.StringVar(value="Never")
        ttk.Label(
            alert_grid,
            textvariable=self.last_alert_var,
            style='NDR.TLabel'
        ).grid(row=2, column=2, columnspan=2, sticky=tk.W, padx=5, pady=2)
    
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
            columns=('id', 'name', 'severity', 'enabled'),
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
        
        # Configure column widths
        self.rules_tree.column('id', width=80, minwidth=50, stretch=tk.NO)
        self.rules_tree.column('name', width=200, minwidth=150, stretch=tk.YES)
        self.rules_tree.column('severity', width=100, minwidth=80, stretch=tk.NO)
        self.rules_tree.column('enabled', width=80, minwidth=60, stretch=tk.NO)
        
        self.rules_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add sample rules (in a real app, these would come from the NDR manager)
        self._load_rules()
    
    def _load_rules(self):
        """Load rules into the rules table."""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add rules from NDR manager
        if hasattr(self.ndr, 'detection_engine') and hasattr(self.ndr.detection_engine, 'rules'):
            for rule_id, rule in self.ndr.detection_engine.rules.items():
                self.rules_tree.insert(
                    '', 'end',
                    values=(
                        rule.id,
                        rule.name,
                        rule.severity.capitalize(),
                        'Yes' if rule.enabled else 'No'
                    ),
                    tags=('enabled' if rule.enabled else 'disabled',)
                )
        
        # Configure tag colors
        self.rules_tree.tag_configure('enabled', background='#e8f5e9')
        self.rules_tree.tag_configure('disabled', background='#ffebee')
    
    def toggle_monitoring(self):
        """Toggle network monitoring on/off."""
        if not self.monitoring:
            # Start monitoring in a separate thread
            self.monitoring = True
            self.start_btn.config(text="Stop Monitoring")
            
            def start_ndr():
                try:
                    self.ndr.start()
                    self.update_queue.put(('status', 'Monitoring started'))
                    self.update_ui_loop()
                except Exception as e:
                    self.update_queue.put(('error', f"Failed to start monitoring: {str(e)}"))
                    self.monitoring = False
                    self.update_queue.put(('button', 'Start Monitoring'))
            
            thread = threading.Thread(target=start_ndr, daemon=True)
            thread.start()
        else:
            # Stop monitoring
            self.monitoring = False
            self.start_btn.config(text="Start Monitoring")
            
            def stop_ndr():
                try:
                    self.ndr.stop()
                    self.update_queue.put(('status', 'Monitoring stopped'))
                except Exception as e:
                    self.update_queue.put(('error', f"Error stopping monitoring: {str(e)}"))
            
            thread = threading.Thread(target=stop_ndr, daemon=True)
            thread.start()
    
    def process_queue(self):
        """Process messages from the update queue."""
        try:
            while True:
                try:
                    msg_type, *args = self.update_queue.get_nowait()
                    if msg_type == 'alert':
                        self._handle_alert(*args)
                    elif msg_type == 'status':
                        self._log_status(*args)
                    elif msg_type == 'error':
                        self._log_error(*args)
                    elif msg_type == 'button':
                        self.start_btn.config(text=args[0])
                except queue.Empty:
                    break
        except Exception as e:
            print(f"Error processing queue: {e}")
        
        # Schedule the next check
        self.parent.after(100, self.process_queue)
    
    def _handle_alert(self, alert):
        """Handle a new alert."""
        # Update alert counts
        severity = alert.get('severity', 'low').lower()
        
        # Update counters based on severity
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
        name = alert.get('name', 'Unknown Alert')
        description = alert.get('description', 'No description')
        
        log_entry = f"[{timestamp}] [{severity}] {name}: {description}\n"
        
        self.alert_log.config(state='normal')
        self.alert_log.insert(tk.END, log_entry)
        self.alert_log.see(tk.END)
        self.alert_log.config(state='disabled')
    
    def _log_status(self, message):
        """Log a status message."""
        self._log_alert({
            'severity': 'info',
            'name': 'Status',
            'description': message
        })
    
    def _log_error(self, message):
        """Log an error message."""
        self._log_alert({
            'severity': 'critical',
            'name': 'Error',
            'description': message
        })
    
    def update_ui_loop(self):
        """Update the UI with current NDR status."""
        if not self.monitoring:
            return
            
        try:
            # Get current status from NDR manager
            status = self.ndr.get_status()
            
            # Update UI elements
            self.packets_var.set(f"{status.get('packets_processed', 0):,}")
            self.alerts_var.set(f"{status.get('alerts_triggered', 0):,}")
            self.iface_var.set(status.get('interface', 'Unknown'))
            
            # Update uptime
            uptime_sec = status.get('uptime_seconds', 0)
            hours, remainder = divmod(int(uptime_sec), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.uptime_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update rules if count changed
            current_rule_count = len(self.rules_tree.get_children())
            if current_rule_count != status.get('detection_rules', 0):
                self._load_rules()
            
        except Exception as e:
            self._log_error(f"Error updating UI: {str(e)}")
        
        # Schedule the next update
        if self.monitoring:
            self.parent.after(1000, self.update_ui_loop)
    
    def show(self):
        """Show the NDR view."""
        if not self.is_visible:
            self.frame.pack(fill=tk.BOTH, expand=True)
            self.is_visible = True
    
    def hide(self):
        """Hide the NDR view."""
        if self.is_visible:
            self.frame.pack_forget()
            self.is_visible = False
