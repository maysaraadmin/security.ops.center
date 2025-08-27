"""
FIM View - GUI for File Integrity Monitoring functionality.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from datetime import datetime
import threading
import queue
import os
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path

from src.fim.manager import FIMManager
from src.fim.integrity_checker import FileIntegrityRecord

class FIMView:
    """GUI for File Integrity Monitoring functionality."""
    
    def __init__(self, parent, event_model=None, rule_model=None, fim_manager: FIMManager = None):
        """
        Initialize the FIM view.
        
        Args:
            parent: Parent widget
            event_model: Optional EventModel instance for event handling
            rule_model: Optional RuleModel instance for rule processing
            fim_manager: Optional FIMManager instance (will create one if not provided)
        """
        self.parent = parent
        self.style = ttk.Style()
        
        # Store models
        self.event_model = event_model
        self.rule_model = rule_model
        
        # Create FIM manager if not provided
        self.fim = fim_manager or FIMManager(alert_callback=self._handle_alert)
        
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
        
        # Load any existing monitored files
        self._update_monitored_files_list()
    
    def _configure_styles(self):
        """Configure custom styles for the FIM view."""
        self.style.configure('FIM.TFrame', background='white')
        self.style.configure('FIM.Header.TLabel', font=('Arial', 14, 'bold'), background='white')
        self.style.configure('FIM.Metric.TLabel', font=('Arial', 18, 'bold'), background='white')
        self.style.configure('FIM.Alert.High.TLabel', background='#ffebee', foreground='#c62828', font=('Arial', 10, 'bold'))
        self.style.configure('FIM.Alert.Medium.TLabel', background='#fff8e1', foreground='#ff8f00', font=('Arial', 10, 'bold'))
        self.style.configure('FIM.Alert.Low.TLabel', background='#e8f5e9', foreground='#2e7d32', font=('Arial', 10))
    
    def _create_widgets(self):
        """Create and arrange all GUI widgets."""
        # Main container with scrollbar
        main_container = ttk.Frame(self.frame, style='FIM.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='FIM.TFrame')
        
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
        header_frame = ttk.Frame(scrollable_frame, style='FIM.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            header_frame,
            text="File Integrity Monitoring",
            style='FIM.Header.TLabel'
        ).pack(side=tk.LEFT)
        
        # Control buttons
        btn_frame = ttk.Frame(header_frame, style='FIM.TFrame')
        btn_frame.pack(side=tk.RIGHT)
        
        self.start_btn = ttk.Button(
            btn_frame,
            text="Start Monitoring",
            command=self.toggle_monitoring
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        # Status indicators
        status_frame = ttk.Frame(scrollable_frame, style='FIM.TFrame')
        status_frame.pack(fill=tk.X, pady=10)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(
            status_frame,
            text="Statistics",
            style='FIM.TFrame',
            padding=10
        )
        stats_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Stats grid
        self._create_stat_widgets(stats_frame)
        
        # Alert summary frame
        alert_frame = ttk.LabelFrame(
            status_frame,
            text="Alerts",
            style='FIM.TFrame',
            padding=10
        )
        alert_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Alert summary
        self._create_alert_summary(alert_frame)
        
        # Monitored files frame
        files_frame = ttk.LabelFrame(
            scrollable_frame,
            text="Monitored Files",
            style='FIM.TFrame',
            padding=10
        )
        files_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 5))
        
        # Monitored files list with scrollbar
        list_frame = ttk.Frame(files_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create Treeview for files
        self._create_files_treeview(list_frame)
        
        # File operations frame
        file_ops_frame = ttk.Frame(files_frame)
        file_ops_frame.pack(fill=tk.X, pady=5)
        
        # File operation buttons
        ttk.Button(
            file_ops_frame,
            text="Add Directory",
            command=self._add_directory
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            file_ops_frame,
            text="Add File",
            command=self._add_file
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            file_ops_frame,
            text="Remove Selected",
            command=self._remove_selected
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            file_ops_frame,
            text="Verify Now",
            command=self._verify_selected
        ).pack(side=tk.LEFT, padx=2)
        
        # Alert log frame
        log_frame = ttk.LabelFrame(
            scrollable_frame,
            text="Alert Log",
            style='FIM.TFrame',
            padding=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
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
        stats_grid = ttk.Frame(parent, style='FIM.TFrame')
        stats_grid.pack(fill=tk.X)
        
        # Monitored files
        ttk.Label(stats_grid, text="Monitored Files:", style='FIM.TLabel').grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.files_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.files_var, style='FIM.Metric.TLabel').grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Integrity violations
        ttk.Label(stats_grid, text="Integrity Violations:", style='FIM.TLabel').grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.violations_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.violations_var, style='FIM.Metric.TLabel').grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Uptime
        ttk.Label(stats_grid, text="Uptime:", style='FIM.TLabel').grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.uptime_var = tk.StringVar(value="00:00:00")
        ttk.Label(stats_grid, textvariable=self.uptime_var, style='FIM.Metric.TLabel').grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Last scan
        ttk.Label(stats_grid, text="Last Scan:", style='FIM.TLabel').grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.last_scan_var = tk.StringVar(value="Never")
        ttk.Label(stats_grid, textvariable=self.last_scan_var, style='FIM.Metric.TLabel').grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
    
    def _create_alert_summary(self, parent):
        """Create alert summary widgets."""
        alert_grid = ttk.Frame(parent, style='FIM.TFrame')
        alert_grid.pack(fill=tk.X)
        
        # Critical alerts
        ttk.Label(alert_grid, text="Critical:", style='FIM.Alert.High.TLabel').grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.critical_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.critical_var, style='FIM.Alert.High.TLabel').grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # High alerts
        ttk.Label(alert_grid, text="High:", style='FIM.Alert.High.TLabel').grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.high_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.high_var, style='FIM.Alert.High.TLabel').grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Medium alerts
        ttk.Label(alert_grid, text="Medium:", style='FIM.Alert.Medium.TLabel').grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.medium_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.medium_var, style='FIM.Alert.Medium.TLabel').grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Low alerts
        ttk.Label(alert_grid, text="Low:", style='FIM.Alert.Low.TLabel').grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.low_var = tk.StringVar(value="0")
        ttk.Label(alert_grid, textvariable=self.low_var, style='FIM.Alert.Low.TLabel').grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Last alert
        ttk.Label(alert_grid, text="Last Alert:", style='FIM.TLabel').grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        self.last_alert_var = tk.StringVar(value="Never")
        ttk.Label(alert_grid, textvariable=self.last_alert_var, style='FIM.TLabel').grid(row=2, column=2, columnspan=2, sticky=tk.W, padx=5, pady=2)
    
    def _create_files_treeview(self, parent):
        """Create the Treeview for displaying monitored files."""
        # Create scrollbars
        y_scroll = ttk.Scrollbar(parent)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        x_scroll = ttk.Scrollbar(parent, orient=tk.HORIZONTAL)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create treeview
        self.files_tree = ttk.Treeview(
            parent,
            yscrollcommand=y_scroll.set,
            xscrollcommand=x_scroll.set,
            columns=('path', 'size', 'modified', 'status'),
            show='headings',
            height=8
        )
        
        # Configure scrollbars
        y_scroll.config(command=self.files_tree.yview)
        x_scroll.config(command=self.files_tree.xview)
        
        # Define columns
        self.files_tree.heading('path', text='File Path', anchor=tk.W)
        self.files_tree.heading('size', text='Size', anchor=tk.W)
        self.files_tree.heading('modified', text='Last Modified', anchor=tk.W)
        self.files_tree.heading('status', text='Status', anchor=tk.W)
        
        # Configure column widths
        self.files_tree.column('path', width=400, minwidth=200, stretch=tk.YES)
        self.files_tree.column('size', width=100, minwidth=80, stretch=tk.NO)
        self.files_tree.column('modified', width=150, minwidth=120, stretch=tk.NO)
        self.files_tree.column('status', width=100, minwidth=80, stretch=tk.NO)
        
        # Add context menu
        self._setup_context_menu()
        
        # Pack the treeview
        self.files_tree.pack(fill=tk.BOTH, expand=True)
    
    def _setup_context_menu(self):
        """Set up the context menu for the files treeview."""
        self.context_menu = tk.Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="Verify Now", command=self._verify_selected)
        self.context_menu.add_command(label="Show Properties", command=self._show_file_properties)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Remove from Monitoring", command=self._remove_selected)
        
        # Bind right-click event
        self.files_tree.bind("<Button-3>", self._show_context_menu)
    
    def _show_context_menu(self, event):
        """Show the context menu on right-click."""
        item = self.files_tree.identify_row(event.y)
        if item:
            self.files_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def _add_directory(self):
        """Add a directory to monitor."""
        directory = filedialog.askdirectory(title="Select Directory to Monitor")
        if directory:
            # Show a dialog to configure monitoring options
            self._show_add_directory_dialog(directory)
    
    def _show_add_directory_dialog(self, directory):
        """Show a dialog to configure directory monitoring options."""
        dialog = tk.Toplevel(self.frame)
        dialog.title("Add Directory to Monitor")
        dialog.geometry("500x300")
        dialog.transient(self.frame)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Directory: {directory}", padding=5).pack(anchor=tk.W)
        
        # Recursive option
        recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            dialog,
            text="Monitor subdirectories",
            variable=recursive_var
        ).pack(anchor=tk.W, padx=5, pady=5)
        
        # File patterns frame
        patterns_frame = ttk.LabelFrame(dialog, text="File Patterns", padding=5)
        patterns_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(
            patterns_frame,
            text="Only monitor files matching these patterns (one per line):",
            wraplength=450
        ).pack(anchor=tk.W)
        
        patterns_text = ScrolledText(patterns_frame, height=5, width=50)
        patterns_text.pack(fill=tk.X, padx=5, pady=5)
        patterns_text.insert(tk.END, "*.*")  # Default: all files
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        
        def on_ok():
            # Get patterns
            patterns = [p.strip() for p in patterns_text.get("1.0", tk.END).split('\n') if p.strip()]
            
            # Add directory to monitoring
            self.fim.add_directory(
                directory=directory,
                file_patterns=patterns,
                recursive=recursive_var.get()
            )
            
            # Update the UI
            self._update_monitored_files_list()
            dialog.destroy()
        
        ttk.Button(
            btn_frame,
            text="OK",
            command=on_ok
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy
        ).pack(side=tk.RIGHT, padx=5)
    
    def _add_file(self):
        """Add a file to monitor."""
        files = filedialog.askopenfilenames(title="Select Files to Monitor")
        for file_path in files:
            self.fim.add_file(file_path)
        
        # Update the UI
        self._update_monitored_files_list()
    
    def _remove_selected(self):
        """Remove selected files from monitoring."""
        selected_items = self.files_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select one or more files to remove.")
            return
        
        # Confirm removal
        if not messagebox.askyesno(
            "Confirm Removal",
            f"Are you sure you want to remove {len(selected_items)} file(s) from monitoring?"
        ):
            return
        
        # Remove each selected file
        for item in selected_items:
            file_path = self.files_tree.item(item, 'values')[0]
            self.fim.remove_file(file_path)
        
        # Update the UI
        self._update_monitored_files_list()
    
    def _verify_selected(self):
        """Verify the integrity of selected files."""
        selected_items = self.files_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select one or more files to verify.")
            return
        
        # Verify each selected file
        for item in selected_items:
            file_path = self.files_tree.item(item, 'values')[0]
            # In a real implementation, we would trigger verification
            # and update the UI with the results
            self._log_alert(f"Verifying file: {file_path}")
        
        messagebox.showinfo("Verification Started", 
                          f"Started verification of {len(selected_items)} file(s).\n"
                          "Check the alert log for results.")
    
    def _show_file_properties(self):
        """Show properties of the selected file."""
        selected_items = self.files_tree.selection()
        if not selected_items:
            return
        
        # For simplicity, just show the first selected item
        file_path = self.files_tree.item(selected_items[0], 'values')[0]
        
        # In a real implementation, we would show detailed properties
        messagebox.showinfo(
            "File Properties",
            f"Path: {file_path}\n"
            "\nMore details would be shown here in a real implementation."
        )
    
    def _update_monitored_files_list(self):
        """Update the list of monitored files in the UI."""
        # Clear existing items
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        
        # Add files from FIM manager
        for file_info in self.fim.get_monitored_files():
            # Format size
            size = file_info['size']
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/(1024*1024):.1f} MB"
            
            # Format modification time
            mtime = file_info['modified']
            mtime_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            # Add to treeview
            self.files_tree.insert(
                '', 'end',
                values=(
                    file_info['path'],
                    size_str,
                    mtime_str,
                    "OK"  # Status would be updated after verification
                )
            )
        
        # Update files count
        self.files_var.set(str(len(self.files_tree.get_children())))
    
    def toggle_monitoring(self):
        """Toggle FIM monitoring on/off."""
        if not self.monitoring:
            # Start monitoring
            self.monitoring = True
            self.start_btn.config(text="Stop Monitoring")
            self.fim.start()
            self._log_alert("FIM monitoring started")
            self.update_ui_loop()
        else:
            # Stop monitoring
            self.monitoring = False
            self.start_btn.config(text="Start Monitoring")
            self.fim.stop()
            self._log_alert("FIM monitoring stopped")
    
    def process_queue(self):
        """Process messages from the update queue."""
        try:
            while True:
                try:
                    event = self.update_queue.get_nowait()
                    self._handle_alert(event)
                except queue.Empty:
                    break
        except Exception as e:
            print(f"Error processing queue: {e}")
        
        # Schedule the next check
        self.parent.after(100, self.process_queue)
    
    def _handle_alert(self, event):
        """Handle a FIM alert event."""
        # Update alert counts
        event_type = event.get('event_type', 'info')
        
        if event_type == 'integrity_violation':
            severity = event.get('details', {}).get('severity', 'medium')
            
            if severity == 'critical':
                self.critical_var.set(str(int(self.critical_var.get() or 0) + 1))
            elif severity == 'high':
                self.high_var.set(str(int(self.high_var.get() or 0) + 1))
            elif severity == 'medium':
                self.medium_var.set(str(int(self.medium_var.get() or 0) + 1))
            else:
                self.low_var.set(str(int(self.low_var.get() or 0) + 1))
            
            # Update last alert time
            self.last_alert_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Log the alert
        self._log_alert(f"{event_type.upper()}: {event.get('path', 'Unknown path')} - {event.get('details', {}).get('reason', '')}")
    
    def _log_alert(self, message: str):
        """Log a message to the alert log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.alert_log.config(state='normal')
        self.alert_log.insert(tk.END, log_entry)
        self.alert_log.see(tk.END)
        self.alert_log.config(state='disabled')
    
    def update_ui_loop(self):
        """Update the UI with current FIM status."""
        if not self.monitoring:
            return
            
        try:
            # Get current status from FIM manager
            status = self.fim.get_status()
            
            # Update UI elements
            self.files_var.set(f"{status.get('monitored_files', 0):,}")
            
            # Update uptime if monitoring is running
            if status.get('running', False):
                uptime_sec = time.time() - self.fim.start_time
                hours, remainder = divmod(int(uptime_sec), 3600)
                minutes, seconds = divmod(remainder, 60)
                self.uptime_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
        except Exception as e:
            print(f"Error updating UI: {e}")
        
        # Schedule the next update
        if self.monitoring:
            self.parent.after(1000, self.update_ui_loop)
    
    def show(self):
        """Show the FIM view."""
        if not self.is_visible:
            self.frame.pack(fill=tk.BOTH, expand=True)
            self.is_visible = True
    
    def hide(self):
        """Hide the FIM view."""
        if self.is_visible:
            self.frame.pack_forget()
            self.is_visible = False
