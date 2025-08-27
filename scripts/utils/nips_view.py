"""
NIPS View - GUI for Network Intrusion Prevention System functionality.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from datetime import datetime
import threading
import queue
import json
import platform
import socket
import os
from typing import Dict, List, Any, Callable, Optional, Tuple
import psutil

from src.nips.manager import NIPSManager

class NIPSView:
    """GUI for Network Intrusion Prevention System functionality."""
    
    def __init__(self, parent, nips_manager: NIPSManager):
        """
        Initialize the NIPS view.
        
        Args:
            parent: Parent widget
            nips_manager: NIPSManager instance
        """
        self.nips = nips_manager
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
        
        # Register alert callback
        self.nips.add_alert_callback(self._on_alert)
        
        # Store alerts data
        self.alerts_data = []
        self.filtered_alerts = []
        
        # Load initial data
        self.refresh_data()
    
    def _configure_styles(self):
        """Configure custom styles for the NIPS view."""
        # Configure frame styles
        self.style.configure(
            'NIPS.TFrame',
            background='#f0f0f0',
            borderwidth=1,
            relief='sunken',
            padding=5
        )
        
        # Configure labelframe styles
        self.style.configure(
            'NIPS.TLabelframe',
            background='#f0f0f0',
            borderwidth=1,
            relief='sunken',
            padding=5
        )
        
        # Configure button styles
        self.style.configure(
            'NIPS.TButton',
            font=('Helvetica', 10, 'bold'),
            padding=5
        )
        
        # Configure button states
        self.style.map(
            'NIPS.TButton',
            background=[('active', '#e0e0e0')],
            foreground=[('active', 'black')]
        )
        
        # Configure notebook style
        self.style.configure(
            'NIPS.TNotebook',
            background='#f0f0f0',
            tabposition='n',
            tabmargins=[2, 5, 2, 0]
        )
        
        # Configure tab style
        self.style.configure(
            'NIPS.TNotebook.Tab',
            padding=[10, 5],
            font=('Helvetica', 9, 'bold')
        )
        
        # Configure tab states
        self.style.map(
            'NIPS.TNotebook.Tab',
            background=[('selected', '#f0f0f0'), ('!selected', '#e0e0e0')],
            foreground=[('selected', 'black'), ('!selected', 'gray40')]
        )
        
        # Configure treeview style
        self.style.configure(
            'NIPS.Treeview',
            font=('Consolas', 9),
            rowheight=25
        )
        
        # Configure treeview header style
        self.style.configure(
            'NIPS.Treeview.Heading',
            font=('Helvetica', 9, 'bold')
        )
        
        # Configure label styles
        self.style.configure(
            'NIPS.TLabel',
            background='#f0f0f0',
            font=('Helvetica', 9)
        )
        
        # Configure header label style
        self.style.configure(
            'NIPS.Header.TLabel',
            background='#f0f0f0',
            font=('Helvetica', 10, 'bold')
        )
        
        # Configure status label style
        self.style.configure(
            'NIPS.Status.TLabel',
            background='#f0f0f0',
            font=('Helvetica', 9, 'italic')
        )
        
        # Configure alert label style
        self.style.configure(
            'NIPS.Alert.TLabel',
            background='#f0f0f0',
            font=('Helvetica', 10, 'bold'),
            foreground='red'
        )
        
        # Configure block button style
        self.style.configure(
            'NIPS.Block.TButton',
            background='#ff6b6b',
            foreground='white',
            font=('Helvetica', 9, 'bold')
        )
        
        # Configure block button states
        self.style.map(
            'NIPS.Block.TButton',
            background=[('active', '#ff5252'), ('!disabled', '#ff6b6b')],
            foreground=[('active', 'white'), ('!disabled', 'white')]
        )
        
        # Configure allow button style
        self.style.configure(
            'NIPS.Allow.TButton',
            background='#51cf66',
            foreground='white',
            font=('Helvetica', 9, 'bold')
        )
        
        # Configure allow button states
        self.style.map(
            'NIPS.Allow.TButton',
            background=[('active', '#40c057'), ('!disabled', '#51cf66')],
            foreground=[('active', 'white'), ('!disabled', 'white')]
        )
    
    def _create_widgets(self):
        """Create and arrange the GUI widgets."""
        # Create main container with padding
        self.main_container = ttk.Frame(self.frame, style='NIPS.TFrame')
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create header
        self._create_header()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container, style='NIPS.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self._create_dashboard_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        self.status_bar = ttk.Label(
            self.main_container,
            textvariable=self.status_var,
            style='NIPS.Status.TLabel',
            anchor=tk.W,
            padding=(5, 2, 5, 2)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))
        
        # Update status periodically
        self._update_status()
    
    def _create_header(self):
        """Create the header section with status and controls."""
        header_frame = ttk.Frame(self.main_container, style='NIPS.TFrame')
        header_frame.pack(fill=tk.X, padx=5, pady=(5, 10))
        
        # Title
        title_label = ttk.Label(
            header_frame,
            text="Network Intrusion Prevention System",
            style='NIPS.Header.TLabel',
            font=('Helvetica', 14, 'bold')
        )
        title_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Status indicator
        self.status_indicator = ttk.Label(
            header_frame,
            text="STOPPED",
            foreground='white',
            background='#ff6b6b',
            font=('Helvetica', 10, 'bold'),
            padding=(10, 3)
        )
        self.status_indicator.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Control buttons frame
        btn_frame = ttk.Frame(header_frame, style='NIPS.TFrame')
        btn_frame.pack(side=tk.RIGHT, padx=10)
        
        # Start/Stop button
        self.toggle_btn = ttk.Button(
            btn_frame,
            text="Start Monitoring",
            command=self.toggle_monitoring,
            style='NIPS.TButton'
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=2)
        
        # Refresh button
        refresh_btn = ttk.Button(
            btn_frame,
            text="⟳",
            width=3,
            command=self.refresh_data,
            style='NIPS.TButton'
        )
        refresh_btn.pack(side=tk.LEFT, padx=2)
    
    def _create_blocked_ips_tab(self):
        """Create the blocked IPs tab for managing blocked IP addresses."""
        self.blocked_ips_tab = ttk.Frame(self.notebook, style='NIPS.TFrame')
        self.notebook.add(self.blocked_ips_tab, text="  Blocked IPs  ")
        
        # Top frame for controls
        controls_frame = ttk.Frame(self.blocked_ips_tab, style='NIPS.TFrame')
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Block IP button
        block_btn = ttk.Button(
            controls_frame,
            text="Block IP",
            command=self._show_block_ip_dialog,
            style='NIPS.TButton'
        )
        block_btn.pack(side=tk.LEFT, padx=2)
        
        # Unblock IP button
        self.unblock_btn = ttk.Button(
            controls_frame,
            text="Unblock IP",
            command=self._unblock_selected_ip,
            style='NIPS.TButton',
            state=tk.DISABLED
        )
        self.unblock_btn.pack(side=tk.LEFT, padx=2)
        
        # Refresh button
        refresh_btn = ttk.Button(
            controls_frame,
            text="⟳",
            width=3,
            command=self.refresh_blocked_ips,
            style='NIPS.TButton'
        )
        refresh_btn.pack(side=tk.RIGHT, padx=2)
        
        # Search frame
        search_frame = ttk.Frame(controls_frame, style='NIPS.TFrame')
        search_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(
            search_frame,
            text="Search:",
            style='NIPS.TLabel'
        ).pack(side=tk.LEFT, padx=(10, 2))
        
        self.ip_search_var = tk.StringVar()
        self.ip_search_var.trace('w', self._filter_blocked_ips)
        
        search_entry = ttk.Entry(
            search_frame,
            textvariable=self.ip_search_var,
            width=30
        )
        search_entry.pack(side=tk.LEFT, padx=2)
        
        # Blocked IPs treeview
        columns = ("ip_address", "blocked_at", "reason", "blocked_by")
        self.blocked_ips_tree = ttk.Treeview(
            self.blocked_ips_tab,
            columns=columns,
            show="headings",
            style='NIPS.Treeview',
            selectmode='browse'
        )
        
        # Configure columns
        self.blocked_ips_tree.heading("ip_address", text="IP Address")
        self.blocked_ips_tree.heading("blocked_at", text="Blocked At")
        self.blocked_ips_tree.heading("reason", text="Reason")
        self.blocked_ips_tree.heading("blocked_by", text="Blocked By")
        
        self.blocked_ips_tree.column("ip_address", width=150, anchor=tk.W)
        self.blocked_ips_tree.column("blocked_at", width=180, anchor=tk.W)
        self.blocked_ips_tree.column("reason", width=300, anchor=tk.W)
        self.blocked_ips_tree.column("blocked_by", width=120, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.blocked_ips_tab,
            orient=tk.VERTICAL,
            command=self.blocked_ips_tree.yview
        )
        self.blocked_ips_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.blocked_ips_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 10))
        
        # Bind selection event
        self.blocked_ips_tree.bind('<<TreeviewSelect>>', self._on_blocked_ip_select)
        
        # Load initial blocked IPs
        self.refresh_blocked_ips()
    
    def _create_settings_tab(self):
        """Create the settings tab for NIPS configuration."""
        self.settings_tab = ttk.Frame(self.notebook, style='NIPS.TFrame')
        self.notebook.add(self.settings_tab, text="  Settings  ")
        
        # Create notebook for settings categories
        settings_notebook = ttk.Notebook(self.settings_tab, style='NIPS.TNotebook')
        settings_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # General settings tab
        general_frame = ttk.Frame(settings_notebook, style='NIPS.TFrame')
        settings_notebook.add(general_frame, text="General")
        
        # Network settings tab
        network_frame = ttk.Frame(settings_notebook, style='NIPS.TFrame')
        settings_notebook.add(network_frame, text="Network")
        
        # Detection settings tab
        detection_frame = ttk.Frame(settings_notebook, style='NIPS.TFrame')
        settings_notebook.add(detection_frame, text="Detection")
        
        # Prevention settings tab
        prevention_frame = ttk.Frame(settings_notebook, style='NIPS.TFrame')
        settings_notebook.add(prevention_frame, text="Prevention")
        
        # Logging settings tab
        logging_frame = ttk.Frame(settings_notebook, style='NIPS.TFrame')
        settings_notebook.add(logging_frame, text="Logging")
        
        # Save button
        btn_frame = ttk.Frame(self.settings_tab, style='NIPS.TFrame')
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        save_btn = ttk.Button(
            btn_frame,
            text="Save Settings",
            command=self._save_settings,
            style='NIPS.TButton'
        )
        save_btn.pack(side=tk.RIGHT, padx=5)
    
    # ===== Helper Methods =====
    
    def _on_rule_select(self, event):
        """Handle rule selection in the rules treeview."""
        selected = self.rules_tree.selection()
        if selected:
            self.remove_rule_btn.config(state=tk.NORMAL)
            self.toggle_rule_btn.config(state=tk.NORMAL)
        else:
            self.remove_rule_btn.config(state=tk.DISABLED)
            self.toggle_rule_btn.config(state=tk.DISABLED)
    
    def _on_blocked_ip_select(self, event):
        """Handle blocked IP selection in the treeview."""
        selected = self.blocked_ips_tree.selection()
        self.unblock_btn.config(state=tk.NORMAL if selected else tk.DISABLED)
    
    def _filter_rules(self, *args):
        """Filter rules based on search query."""
        query = self.rule_search_var.get().lower()
        
        for item in self.rules_tree.get_children():
            values = self.rules_tree.item(item, 'values')
            if not query or any(query in str(v).lower() for v in values):
                self.rules_tree.reattach(item, '', 'end')
            else:
                self.rules_tree.detach(item)
    
    def _filter_blocked_ips(self, *args):
        """Filter blocked IPs based on search query."""
        query = self.ip_search_var.get().lower()
        
        for item in self.blocked_ips_tree.get_children():
            values = self.blocked_ips_tree.item(item, 'values')
            if not query or any(query in str(v).lower() for v in values):
                self.blocked_ips_tree.reattach(item, '', 'end')
            else:
                self.blocked_ips_tree.detach(item)
    
    def refresh_rules(self):
        """Refresh the rules list from the NIPS manager."""
        # Clear current items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add rules from NIPS manager
        for rule in self.nips.get_rules():
            self.rules_tree.insert('', 'end', values=(
                '✓' if rule.get('enabled', True) else '✗',
                rule.get('name', 'Unnamed'),
                rule.get('description', ''),
                rule.get('severity', 'medium').capitalize(),
                rule.get('protocol', 'any').upper(),
                rule.get('source', 'any'),
                rule.get('destination', 'any'),
                rule.get('action', 'alert').capitalize()
            ))
    
    def refresh_blocked_ips(self):
        """Refresh the blocked IPs list from the NIPS manager."""
        # Clear current items
        for item in self.blocked_ips_tree.get_children():
            self.blocked_ips_tree.delete(item)
        
        # Add blocked IPs from NIPS manager
        for ip_info in self.nips.get_blocked_ips():
            self.blocked_ips_tree.insert('', 'end', values=(
                ip_info.get('ip', ''),
                ip_info.get('blocked_at', ''),
                ip_info.get('reason', 'Manual block'),
                ip_info.get('blocked_by', 'system')
            ))
    
    def _show_block_ip_dialog(self):
        """Show dialog to block an IP address."""
        dialog = tk.Toplevel(self.frame)
        dialog.title("Block IP Address")
        dialog.transient(self.frame)
        dialog.grab_set()
        
        # Set window size and position
        dialog.geometry("400x200")
        dialog.minsize(300, 150)
        
        # IP address
        ttk.Label(
            dialog,
            text="IP Address:",
            style='NIPS.TLabel'
        ).pack(pady=(10, 0), padx=10, anchor=tk.W)
        
        ip_var = tk.StringVar()
        ip_entry = ttk.Entry(dialog, textvariable=ip_var, width=30)
        ip_entry.pack(padx=10, pady=5, fill=tk.X)
        
        # Reason
        ttk.Label(
            dialog,
            text="Reason (optional):",
            style='NIPS.TLabel'
        ).pack(pady=(10, 0), padx=10, anchor=tk.W)
        
        reason_var = tk.StringVar()
        reason_entry = ttk.Entry(dialog, textvariable=reason_var, width=30)
        reason_entry.pack(padx=10, pady=5, fill=tk.X)
        
        # Duration (minutes)
        ttk.Label(
            dialog,
            text="Block Duration (minutes, 0 for permanent):",
            style='NIPS.TLabel'
        ).pack(pady=(10, 0), padx=10, anchor=tk.W)
        
        duration_var = tk.StringVar(value="60")
        duration_spin = ttk.Spinbox(
            dialog,
            from_=0,
            to=525600,  # 1 year in minutes
            textvariable=duration_var,
            width=10
        )
        duration_spin.pack(padx=10, pady=5, anchor=tk.W)
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def block():
            ip = ip_var.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
            
            try:
                self.nips.block_ip(
                    ip=ip,
                    reason=reason_var.get().strip() or None,
                    duration=int(duration_var.get()) if duration_var.get() else 0
                )
                self.refresh_blocked_ips()
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to block IP: {str(e)}")
        
        ttk.Button(
            btn_frame,
            text="Block",
            command=block,
            style='NIPS.Block.TButton'
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            style='NIPS.TButton'
        ).pack(side=tk.RIGHT, padx=5)
        
        # Set focus to IP entry
        ip_entry.focus_set()
    
    def _unblock_selected_ip(self):
        """Unblock the selected IP address."""
        selected = self.blocked_ips_tree.selection()
        if not selected:
            return
        
        item = self.blocked_ips_tree.item(selected[0])
        ip = item['values'][0]  # First column is IP address
        
        if messagebox.askyesno(
            "Confirm Unblock",
            f"Are you sure you want to unblock {ip}?"
        ):
            try:
                self.nips.unblock_ip(ip)
                self.refresh_blocked_ips()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to unblock IP: {str(e)}")
    
    def _toggle_selected_rule(self):
        """Toggle the enabled/disabled state of the selected rule."""
        selected = self.rules_tree.selection()
        if not selected:
            return
        
        item = self.rules_tree.item(selected[0])
        rule_name = item['values'][1]  # Second column is rule name
        
        try:
            # Toggle rule state in NIPS manager
            if self.nips.toggle_rule(rule_name):
                # Refresh the rules list
                self.refresh_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle rule: {str(e)}")
    
    def _remove_selected_rule(self):
        """Remove the selected rule."""
        selected = self.rules_tree.selection()
        if not selected:
            return
        
        item = self.rules_tree.item(selected[0])
        rule_name = item['values'][1]  # Second column is rule name
        
        if messagebox.askyesno(
            "Confirm Removal",
            f"Are you sure you want to remove the rule '{rule_name}'?"
        ):
            try:
                if self.nips.remove_rule(rule_name):
                    # Refresh the rules list
                    self.refresh_rules()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove rule: {str(e)}")
    
    def _save_settings(self):
        """Save all settings from the settings tab."""
        try:
            # This would save all settings to a config file or database
            # For now, just show a success message
            messagebox.showinfo("Success", "Settings saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab with an overview of NIPS status."""
        self.dashboard_tab = ttk.Frame(self.notebook, style='NIPS.TFrame')
        self.notebook.add(self.dashboard_tab, text="  Dashboard  ")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(
            self.dashboard_tab,
            text="Statistics",
            style='NIPS.TLabelframe',
            padding=10
        )
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Stats grid
        stats_grid = ttk.Frame(stats_frame, style='NIPS.TFrame')
        stats_grid.pack(fill=tk.X, expand=True)
        
        # Packets processed
        self.packets_var = tk.StringVar(value="0")
        self._create_stat_widget(
            stats_grid, 0, 0, "Packets Processed", self.packets_var, "#4dabf7"
        )
        
        # Threats prevented
        self.threats_var = tk.StringVar(value="0")
        self._create_stat_widget(
            stats_grid, 0, 1, "Threats Prevented", self.threats_var, "#ff6b6b"
        )
        
        # Active rules
        self.rules_var = tk.StringVar(value="0")
        self._create_stat_widget(
            stats_grid, 0, 2, "Active Rules", self.rules_var, "#51cf66"
        )
        
        # Blocked IPs
        self.blocked_ips_var = tk.StringVar(value="0")
        self._create_stat_widget(
            stats_grid, 0, 3, "Blocked IPs", self.blocked_ips_var, "#ff922b"
        )
        
        # Alerts frame
        alerts_frame = ttk.LabelFrame(
            self.dashboard_tab,
            text="Recent Alerts",
            style='NIPS.TLabelframe',
            padding=10
        )
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Alerts treeview
        columns = ("time", "severity", "source", "destination", "threat", "action")
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=columns,
            show="headings",
            style='NIPS.Treeview',
            selectmode='browse'
        )
        
        # Configure columns
        self.alerts_tree.heading("time", text="Time")
        self.alerts_tree.heading("severity", text="Severity")
        self.alerts_tree.heading("source", text="Source")
        self.alerts_tree.heading("destination", text="Destination")
        self.alerts_tree.heading("threat", text="Threat Type")
        self.alerts_tree.heading("action", text="Action")
        
        self.alerts_tree.column("time", width=150, anchor=tk.W)
        self.alerts_tree.column("severity", width=80, anchor=tk.CENTER)
        self.alerts_tree.column("source", width=150, anchor=tk.W)
        self.alerts_tree.column("destination", width=150, anchor=tk.W)
        self.alerts_tree.column("threat", width=200, anchor=tk.W)
        self.alerts_tree.column("action", width=100, anchor=tk.CENTER)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            alerts_frame,
            orient=tk.VERTICAL,
            command=self.alerts_tree.yview
        )
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add context menu for alerts
        self._setup_alerts_context_menu()
    
    def _create_stat_widget(self, parent, row, col, title, value_var, color):
        """
        Create a statistics widget.
        
        Args:
            parent: Parent widget
            row: Grid row
            col: Grid column
            title: Widget title
            value_var: Variable to hold the value
            color: Color for the value
        """
        frame = ttk.Frame(parent, style='NIPS.TFrame')
        frame.grid(row=row, column=col, padx=10, pady=5, sticky='nsew')
        
        # Title
        ttk.Label(
            frame,
            text=title.upper(),
            style='NIPS.TLabel',
            font=('Helvetica', 8, 'bold'),
            foreground='gray50'
        ).pack()
        
        # Value
        ttk.Label(
            frame,
            textvariable=value_var,
            style='NIPS.Header.TLabel',
            font=('Helvetica', 24, 'bold'),
            foreground=color
        ).pack()
        
        return frame
    
    def _setup_alerts_context_menu(self):
        """Set up the context menu for the alerts treeview."""
        self.alerts_menu = tk.Menu(self.frame, tearoff=0)
        self.alerts_menu.add_command(
            label="View Details",
            command=self.view_alert_details
        )
        self.alerts_menu.add_separator()
        self.alerts_menu.add_command(
            label="Block Source IP",
            command=self.block_selected_alert_source
        )
        self.alerts_menu.add_command(
            label="Allow Source IP",
            command=self.allow_selected_alert_source
        )
        self.alerts_menu.add_separator()
        self.alerts_menu.add_command(
            label="Copy to Clipboard",
            command=self.copy_alert_to_clipboard
        )
        
        # Bind right-click event
        self.alerts_tree.bind(
            "<Button-3>",
            self._on_alerts_right_click
        )
    
    def _on_alerts_right_click(self, event):
        """Handle right-click on alerts treeview."""
        item = self.alerts_tree.identify_row(event.y)
        if item:
            self.alerts_tree.selection_set(item)
            self.alerts_menu.post(event.x_root, event.y_root)
    
    def toggle_monitoring(self):
        """Toggle NIPS monitoring on/off."""
        if self.monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start NIPS monitoring."""
        try:
            self.nips.start()
            self.monitoring = True
            self.toggle_btn.config(text="Stop Monitoring")
            self.status_indicator.config(
                text="RUNNING",
                background='#51cf66',
                foreground='white'
            )
            self.status_var.set("Monitoring started")
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to start monitoring: {str(e)}"
            )
    
    def stop_monitoring(self):
        """Stop NIPS monitoring."""
        try:
            self.nips.stop()
            self.monitoring = False
            self.toggle_btn.config(text="Start Monitoring")
            self.status_indicator.config(
                text="STOPPED",
                background='#ff6b6b',
                foreground='white'
            )
            self.status_var.set("Monitoring stopped")
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to stop monitoring: {str(e)}"
            )
    
    def refresh_data(self):
        """Refresh all data in the UI."""
        self._update_status()
        self._update_stats()
        self._update_alerts()
    
    def _update_status(self):
        """Update the status bar and other status indicators."""
        if hasattr(self, 'status_var'):
            if self.monitoring:
                self.status_var.set("Monitoring network traffic...")
            else:
                self.status_var.set("Ready")
        
        # Schedule next update
        self.parent.after(1000, self._update_status)
    
    def _update_stats(self):
        """Update the statistics display."""
        if hasattr(self, 'nips'):
            stats = self.nips.get_status()
            self.packets_var.set(str(stats.get('packets_processed', 0)))
            self.threats_var.set(str(stats.get('threats_prevented', 0)))
            self.rules_var.set(str(stats.get('active_rules', 0)))
            self.blocked_ips_var.set(str(len(stats.get('blocked_ips', []))))
    
    def _update_alerts(self):
        """Update the alerts display."""
        # This would be implemented to fetch and display alerts
        # For now, it's a placeholder
        pass
    
    def _on_alert(self, alert_info):
        """Handle a new alert."""
        # Add alert to the queue for thread-safe UI updates
        self.update_queue.put(('alert', alert_info))
    
    def process_queue(self):
        """Process items in the update queue."""
        try:
            while True:
                item = self.update_queue.get_nowait()
                if item[0] == 'alert':
                    self._process_alert(item[1])
        except queue.Empty:
            pass
        
        # Schedule next check
        self.parent.after(100, self.process_queue)
    
    def _process_alert(self, alert_info):
        """Process a new alert and update the UI."""
        # Add alert to alerts list
        self.alerts_data.append(alert_info)
        
        # Keep only the last 100 alerts
        if len(self.alerts_data) > 100:
            self.alerts_data = self.alerts_data[-100:]
        
        # Update alerts display
        self._update_alerts_display()
        
        # Show popup for critical alerts if enabled
        if alert_info.get('severity', '').lower() == 'critical':
            self._show_alert_popup(alert_info)
    
    def _update_alerts_display(self):
        """Update the alerts display with current alerts."""
        # Clear current items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Add alerts to treeview
        for alert in reversed(self.alerts_data[-20:]):  # Show last 20 alerts
            self.alerts_tree.insert('', 'end', values=(
                alert.get('timestamp', 'N/A'),
                alert.get('severity', 'N/A').capitalize(),
                alert.get('source_ip', 'N/A'),
                alert.get('destination_ip', 'N/A'),
                alert.get('threat_type', 'N/A'),
                alert.get('action', 'N/A').capitalize()
            ))
    
    def _show_alert_popup(self, alert_info):
        """Show a popup for a critical alert."""
        # This would be implemented to show a popup for critical alerts
        # For now, we'll just log it
        print(f"CRITICAL ALERT: {alert_info}")
    
    def view_alert_details(self):
        """View details of the selected alert."""
        selected = self.alerts_tree.selection()
        if not selected:
            return
        
        item = self.alerts_tree.item(selected[0])
        alert_index = len(self.alerts_data) - 1 - self.alerts_tree.index(selected[0])
        
        if 0 <= alert_index < len(self.alerts_data):
            alert = self.alerts_data[alert_index]
            self._show_alert_details_dialog(alert)
    
    def _show_alert_details_dialog(self, alert):
        """Show a dialog with alert details."""
        dialog = tk.Toplevel(self.frame)
        dialog.title("Alert Details")
        dialog.transient(self.frame)
        dialog.grab_set()
        
        # Set window size and position
        dialog.geometry("600x400")
        dialog.minsize(400, 300)
        
        # Create text widget for alert details
        text = ScrolledText(dialog, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format and insert alert details
        details = json.dumps(alert, indent=2, default=str)
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)
        
        # Add close button
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(
            btn_frame,
            text="Close",
            command=dialog.destroy
        ).pack(side=tk.RIGHT)
    
    def block_selected_alert_source(self):
        """Block the source IP of the selected alert."""
        selected = self.alerts_tree.selection()
        if not selected:
            return
        
        item = self.alerts_tree.item(selected[0])
        alert_index = len(self.alerts_data) - 1 - self.alerts_tree.index(selected[0])
        
        if 0 <= alert_index < len(self.alerts_data):
            alert = self.alerts_data[alert_index]
            source_ip = alert.get('source_ip')
            
            if source_ip and source_ip != 'N/A':
                self.block_ip(source_ip, "Manual block from alert")
    
    def allow_selected_alert_source(self):
        """Allow the source IP of the selected alert."""
        selected = self.alerts_tree.selection()
        if not selected:
            return
        
        item = self.alerts_tree.item(selected[0])
        alert_index = len(self.alerts_data) - 1 - self.alerts_tree.index(selected[0])
        
        if 0 <= alert_index < len(self.alerts_data):
            alert = self.alerts_data[alert_index]
            source_ip = alert.get('source_ip')
            
            if source_ip and source_ip != 'N/A':
                self.allow_ip(source_ip)
    
    def copy_alert_to_clipboard(self):
        """Copy the selected alert to the clipboard."""
        selected = self.alerts_tree.selection()
        if not selected:
            return
        
        item = self.alerts_tree.item(selected[0])
        alert_index = len(self.alerts_data) - 1 - self.alerts_tree.index(selected[0])
        
        if 0 <= alert_index < len(self.alerts_data):
            alert = self.alerts_data[alert_index]
            self.frame.clipboard_clear()
            self.frame.clipboard_append(json.dumps(alert, indent=2, default=str))
            self.status_var.set("Alert copied to clipboard")
    
    def block_ip(self, ip_address, reason=""):
        """
        Block an IP address.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
        """
        try:
            self.nips.block_ip(ip_address)
            self.status_var.set(f"Blocked IP: {ip_address}")
            self._update_stats()
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to block IP {ip_address}: {str(e)}"
            )
    
    def allow_ip(self, ip_address):
        """
        Allow a previously blocked IP address.
        
        Args:
            ip_address: IP address to allow
        """
        try:
            self.nips.unblock_ip(ip_address)
            self.status_var.set(f"Allowed IP: {ip_address}")
            self._update_stats()
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to allow IP {ip_address}: {str(e)}"
            )
    
    def show(self):
        """Show the NIPS view."""
        if not self.is_visible:
            self.frame.pack(fill=tk.BOTH, expand=True)
            self.is_visible = True
            self.refresh_data()
    
    def hide(self):
        """Hide the NIPS view."""
        if self.is_visible:
            self.frame.pack_forget()
            self.is_visible = False
    
    def destroy(self):
        """Clean up resources."""
        if hasattr(self, 'nips'):
            self.nips.stop()
        
        if hasattr(self, 'frame'):
            self.frame.destroy()
