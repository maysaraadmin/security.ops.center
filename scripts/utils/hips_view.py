"""
HIPS View - GUI for the Host-based Intrusion Prevention System.
"""
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from tkinter.font import Font
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
import threading
import json

class HIPSView(ttk.Frame):
    """GUI view for the HIPS system."""
    
    def __init__(self, parent, hips_manager, *args, **kwargs):
        """Initialize the HIPS view."""
        super().__init__(parent, *args, **kwargs)
        
        self.hips_manager = hips_manager
        self.parent = parent
        
        # Set up the UI
        self._setup_ui()
        
        # Register for alerts
        self.hips_manager.add_alert_callback(self._on_alert)
        
        # Start with a status update
        self._update_status()
        
        # Start periodic updates
        self._schedule_update()
    
    def _toggle_hips(self):
        """Toggle HIPS protection on/off."""
        if not self.hips_manager.is_running():
            try:
                self.hips_manager.start()
                self.start_btn.config(text="Stop")
                self.status_var.set("Status: Running")
                self.status_indicator.config(foreground="green")
                messagebox.showinfo("HIPS", "HIPS protection has been enabled.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start HIPS: {str(e)}")
        else:
            self.hips_manager.stop()
            self.start_btn.config(text="Start")
            self.status_var.set("Status: Stopped")
            self.status_indicator.config(foreground="red")
            messagebox.showinfo("HIPS", "HIPS protection has been disabled.")
    
    def _setup_ui(self):
        """Set up the user interface."""
        # Configure grid weights
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Create header frame
        header_frame = ttk.Frame(self, padding="10")
        header_frame.grid(row=0, column=0, sticky="ew")
        
        # Title
        title_font = Font(size=12, weight='bold')
        ttk.Label(
            header_frame, 
            text="Host-based Intrusion Prevention System (HIPS)", 
            font=title_font
        ).grid(row=0, column=0, sticky="w")
        
        # Status indicator
        self.status_var = tk.StringVar(value="Status: Stopped")
        self.status_indicator = ttk.Label(
            header_frame, 
            textvariable=self.status_var,
            foreground="red"
        )
        self.status_indicator.grid(row=0, column=1, padx=10)
        
        # Control buttons
        btn_frame = ttk.Frame(header_frame)
        btn_frame.grid(row=0, column=2, sticky="e")
        
        self.start_btn = ttk.Button(
            btn_frame, 
            text="Start", 
            command=self._toggle_hips,
            width=10
        )
        self.start_btn.grid(row=0, column=0, padx=2)
        
        ttk.Button(
            btn_frame, 
            text="Settings", 
            command=self._show_settings,
            width=10
        ).grid(row=0, column=1, padx=2)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create tabs
        self._create_dashboard_tab()
        self._create_alerts_tab()
        self._create_rules_tab()
        self._create_whitelist_tab()
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Configure grid
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Status frame
        status_frame = ttk.LabelFrame(tab, text="Status", padding=10)
        status_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        # Status fields
        ttk.Label(status_frame, text="Uptime:").grid(row=0, column=0, sticky="w", pady=2)
        self.uptime_var = tk.StringVar(value="00:00:00")
        ttk.Label(status_frame, textvariable=self.uptime_var).grid(row=0, column=1, sticky="w", pady=2)
        
        ttk.Label(status_frame, text="Alerts (24h):").grid(row=1, column=0, sticky="w", pady=2)
        self.alerts_24h_var = tk.StringVar(value="0")
        ttk.Label(status_frame, textvariable=self.alerts_24h_var).grid(row=1, column=1, sticky="w", pady=2)
        
        ttk.Label(status_frame, text="Active Rules:").grid(row=2, column=0, sticky="w", pady=2)
        self.active_rules_var = tk.StringVar(value="0")
        ttk.Label(status_frame, textvariable=self.active_rules_var).grid(row=2, column=1, sticky="w", pady=2)
        
        # Monitoring status
        ttk.Label(status_frame, text="Monitoring:").grid(row=0, column=2, sticky="w", pady=2, padx=(20, 0))
        
        self.monitoring_vars = {}
        for i, (name, label) in enumerate([
            ('file_system', 'File System'),
            ('registry', 'Registry'),
            ('processes', 'Processes'),
            ('network', 'Network'),
            ('services', 'Services')
        ], start=1):
            var = tk.BooleanVar()
            self.monitoring_vars[name] = var
            cb = ttk.Checkbutton(
                status_frame, 
                text=label, 
                variable=var,
                command=lambda n=name: self._toggle_monitoring(n)
            )
            cb.grid(row=i, column=2, sticky="w", pady=2, padx=(20, 0))
            
            # Set initial state from manager
            var.set(getattr(self.hips_manager.detection_engine, f'monitor_{name}'))
        
        # Recent alerts frame
        alerts_frame = ttk.LabelFrame(tab, text="Recent Alerts", padding=5)
        alerts_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        alerts_frame.grid_columnconfigure(0, weight=1)
        alerts_frame.grid_rowconfigure(0, weight=1)
        
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=('time', 'severity', 'description'),
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.alerts_tree.heading('time', text='Time', anchor='w')
        self.alerts_tree.heading('severity', text='Severity', anchor='w')
        self.alerts_tree.heading('description', text='Description', anchor='w')
        
        self.alerts_tree.column('time', width=150, stretch=False)
        self.alerts_tree.column('severity', width=100, stretch=False)
        self.alerts_tree.column('description', width=400, stretch=True)
        
        # Add scrollbar
        vsb = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=vsb.set)
        
        # Grid tree and scrollbar
        self.alerts_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        
        # Add double-click event
        self.alerts_tree.bind("<Double-1>", self._on_alert_double_click)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(tab, text="Statistics", padding=10)
        stats_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        # Stats will be populated by _update_status
        self.stats_vars = {}
        for i, (key, label) in enumerate([
            ('file_events', 'File System Events:'),
            ('process_events', 'Process Events:'),
            ('network_events', 'Network Events:'),
            ('service_events', 'Service Events:'),
            ('high_severity', 'High Severity Alerts:'),
            ('medium_severity', 'Medium Severity Alerts:'),
            ('low_severity', 'Low Severity Alerts:')
        ]):
            ttk.Label(stats_frame, text=label).grid(row=i, column=0, sticky="w", pady=2)
            self.stats_vars[key] = tk.StringVar(value="0")
            ttk.Label(stats_frame, textvariable=self.stats_vars[key]).grid(row=i, column=1, sticky="e", pady=2)
    
    def _create_alerts_tab(self):
        """Create the alerts tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Alerts")
        
        # Configure grid
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(tab)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Button(
            toolbar, 
            text="Refresh", 
            command=self._refresh_alerts,
            width=10
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Clear All", 
            command=self._clear_alerts,
            width=10
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Export...", 
            command=self._export_alerts,
            width=10
        ).pack(side="left", padx=2)
        
        # Filter frame
        filter_frame = ttk.Frame(tab)
        filter_frame.grid(row=1, column=0, sticky="new", pady=(0, 5))
        
        ttk.Label(filter_frame, text="Severity:").pack(side="left", padx=2)
        
        self.severity_var = tk.StringVar(value="all")
        for text, value in [
            ("All", "all"),
            ("High", "high"),
            ("Medium", "medium"),
            ("Low", "low")
        ]:
            rb = ttk.Radiobutton(
                filter_frame,
                text=text,
                variable=self.severity_var,
                value=value,
                command=self._filter_alerts
            )
            rb.pack(side="left", padx=2)
        
        # Alerts table
        self.alerts_table = ttk.Treeview(
            tab,
            columns=('time', 'severity', 'rule', 'description'),
            show='headings',
            selectmode='extended'
        )
        
        # Configure columns
        self.alerts_table.heading('time', text='Time', anchor='w', command=lambda: self._sort_alerts('time'))
        self.alerts_table.heading('severity', text='Severity', anchor='w', command=lambda: self._sort_alerts('severity'))
        self.alerts_table.heading('rule', text='Rule', anchor='w', command=lambda: self._sort_alerts('rule'))
        self.alerts_table.heading('description', text='Description', anchor='w', command=lambda: self._sort_alerts('description'))
        
        self.alerts_table.column('time', width=150, stretch=False)
        self.alerts_table.column('severity', width=100, stretch=False)
        self.alerts_table.column('rule', width=150, stretch=False)
        self.alerts_table.column('description', width=400, stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.alerts_table.yview)
        hsb = ttk.Scrollbar(tab, orient="horizontal", command=self.alerts_table.xview)
        self.alerts_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid table and scrollbars
        self.alerts_table.grid(row=2, column=0, sticky="nsew")
        vsb.grid(row=2, column=1, sticky="ns")
        hsb.grid(row=3, column=0, sticky="ew")
        
        # Add double-click event
        self.alerts_table.bind("<Double-1>", self._on_alert_double_click)
