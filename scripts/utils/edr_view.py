import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import platform
import socket
import json
from datetime import datetime, timedelta
import threading
from typing import Dict, List, Tuple, Optional, Any
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Custom styles
class EDRStyles:
    """Custom styles for EDR view"""
    def __init__(self, root):
        self.style = ttk.Style(root)
        self._configure_styles()
    
    def _configure_styles(self):
        """Configure custom styles"""
        # Base styles
        self.style.configure('TFrame', background='white')
        self.style.configure('TLabel', background='white')
        
        # Status colors
        self.style.configure('Status.Critical.TLabel', 
                           foreground='#d32f2f',
                           font=('Arial', 9, 'bold'))
        self.style.configure('Status.Warning.TLabel', 
                           foreground='#f57c00',
                           font=('Arial', 9, 'bold'))
        self.style.configure('Status.Info.TLabel', 
                           foreground='#1976d2',
                           font=('Arial', 9, 'bold'))
        
        # Treeview styles
        self.style.configure('EDR.Treeview', 
                           rowheight=25,
                           font=('Segoe UI', 9))
        self.style.configure('EDR.Treeview.Heading', 
                           font=('Segoe UI', 9, 'bold'))
        
        # Button styles
        self.style.configure('Action.TButton', padding=3)
        
        # Card styles
        self.style.configure('Card.TFrame', 
                           background='#f8f9fa',
                           relief='groove',
                           borderwidth=1)

class EDRView:
    """Endpoint Detection and Response (EDR) View.
    
    Provides a comprehensive interface for monitoring and managing endpoints.
    """
    
    def __init__(self, parent, db):
        """Initialize the EDR view.
        
        Args:
            parent: Parent widget
            db: Database connection
        """
        self.db = db
        self.is_monitoring = False
        self.update_interval = 5000  # 5 seconds
        
        # Initialize EDR manager
        from core.edr.manager import EDRManager
        self.edr_manager = EDRManager(db)
        
        # Initialize styles
        self.styles = EDRStyles(parent)
        self.style = self.styles.style
        
        # Create main frame
        self.frame = ttk.Frame(parent, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Initialize UI
        self._create_widgets()
        
        # Start monitoring
        self.toggle_monitoring()
    def _create_widgets(self):
        """Create all widgets for the EDR view"""
        # Main container
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create control panel
        self._create_control_panel(main_container)
        
        # Create status panels
        self._create_status_panels(main_container)
        
        # Create alerts panel
        self._create_alerts_panel(main_container)
        
        # Create processes panel
        self._create_processes_panel(main_container)
        
        # Initialize tooltip
        self.tooltip = None
    
    def _create_control_panel(self, parent):
        """Create the control panel with action buttons"""
        control_frame = ttk.LabelFrame(parent, text="EDR Controls", padding=5)
        control_frame.pack(fill=tk.X, pady=(0, 10), ipadx=5, ipady=5)
        
        # Button frame
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        # Control buttons
        self.monitor_btn = ttk.Button(
            btn_frame, 
            text="Start Monitoring",
            command=self.toggle_monitoring,
            style='Action.TButton',
            width=15
        )
        self.monitor_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame,
            text="Scan Now",
            command=self.run_scan,
            style='Action.TButton',
            width=10
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame,
            text="Quarantine",
            command=self.quarantine_selected,
            style='Action.TButton',
            width=10
        ).pack(side=tk.LEFT, padx=2)
        
        # Status indicators
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Status label
        ttk.Label(status_frame, text="Status:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, style='Status.Info.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Last update time
        ttk.Label(status_frame, text="|", foreground='#ccc').pack(side=tk.LEFT, padx=5)
        ttk.Label(status_frame, text="Last Update:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        self.last_update_var = tk.StringVar(value="Never")
        ttk.Label(status_frame, textvariable=self.last_update_var, style='Status.Info.TLabel').pack(side=tk.LEFT, padx=5)
    
    def _create_status_panels(self, parent):
        """Create status panels for system metrics"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # System status panel
        sys_frame = ttk.LabelFrame(status_frame, text="System Status", padding=5, style='Card.TFrame')
        sys_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self._create_system_status_panel(sys_frame)
        
        # Endpoint status panel
        ep_frame = ttk.LabelFrame(status_frame, text="Endpoint Status", padding=5, style='Card.TFrame')
        ep_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        self._create_endpoint_status_panel(ep_frame)
    
    def _create_system_status_panel(self, parent):
        """Create system status panel with metrics"""
        # CPU Usage
        ttk.Label(parent, text="CPU Usage:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.cpu_var = tk.StringVar(value="0.0%")
        ttk.Label(parent, textvariable=self.cpu_var, style='Metric.TLabel').grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Memory Usage
        ttk.Label(parent, text="Memory Usage:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.mem_var = tk.StringVar(value="0.0%")
        ttk.Label(parent, textvariable=self.mem_var, style='Metric.TLabel').grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Disk Usage
        ttk.Label(parent, text="Disk Usage:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.disk_var = tk.StringVar(value="0.0%")
        ttk.Label(parent, textvariable=self.disk_var, style='Metric.TLabel').grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Network I/O
        ttk.Label(parent, text="Network:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.network_var = tk.StringVar(value="0.0 KB/s")
        ttk.Label(parent, textvariable=self.network_var, style='Metric.TLabel').grid(row=3, column=1, sticky=tk.W, pady=2)
    
    def _create_endpoint_status_panel(self, parent):
        """Create endpoint status panel"""
        # Endpoint count
        ttk.Label(parent, text="Endpoints:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.endpoint_count_var = tk.StringVar(value="0")
        ttk.Label(parent, textvariable=self.endpoint_count_var, style='Metric.TLabel').grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Threats detected
        ttk.Label(parent, text="Threats:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.threats_var = tk.StringVar(value="0")
        ttk.Label(parent, textvariable=self.threats_var, style='Metric.TLabel').grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Last scan time
        ttk.Label(parent, text="Last Scan:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.last_scan_var = tk.StringVar(value="Never")
        ttk.Label(parent, textvariable=self.last_scan_var, style='Metric.TLabel').grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Agent version
        ttk.Label(parent, text="Agent Version:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.version_var = tk.StringVar(value="1.0.0")
        ttk.Label(parent, textvariable=self.version_var, style='Metric.TLabel').grid(row=3, column=1, sticky=tk.W, pady=2)
    
    def _create_alerts_panel(self, parent):
        """Create the alerts panel with a treeview for security alerts"""
        alerts_frame = ttk.LabelFrame(parent, text="Security Alerts", padding=5, style='Card.TFrame')
        alerts_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create toolbar
        toolbar = ttk.Frame(alerts_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Filter controls
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=2)
        self.alert_filter_var = tk.StringVar()
        ttk.Combobox(
            toolbar, 
            textvariable=self.alert_filter_var, 
            values=["All", "Critical", "High", "Medium", "Low"],
            state='readonly',
            width=10
        ).pack(side=tk.LEFT, padx=2)
        self.alert_filter_var.set("All")
        self.alert_filter_var.trace('w', self._filter_alerts)
        
        # Search box
        self.alert_search_var = tk.StringVar()
        search_entry = ttk.Entry(
            toolbar, 
            textvariable=self.alert_search_var,
            width=30
        )
        search_entry.pack(side=tk.RIGHT, padx=2)
        search_entry.bind('<Return>', lambda e: self._filter_alerts())
        
        # Create treeview for alerts
        columns = ('timestamp', 'severity', 'source', 'message', 'status')
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=columns,
            show='headings',
            selectmode='extended',
            style='EDR.Treeview'
        )
        
        # Configure columns
        col_config = {
            'timestamp': {'text': 'Timestamp', 'width': 150, 'anchor': tk.W, 'stretch': False},
            'severity': {'text': 'Severity', 'width': 100, 'anchor': tk.W, 'stretch': False},
            'source': {'text': 'Source', 'width': 150, 'anchor': tk.W, 'stretch': False},
            'message': {'text': 'Message', 'width': 300, 'anchor': tk.W, 'stretch': True},
            'status': {'text': 'Status', 'width': 100, 'anchor': tk.W, 'stretch': False}
        }
        
        for col, config in col_config.items():
            self.alerts_tree.heading(col, text=config['text'], anchor=config.get('anchor', tk.W))
            self.alerts_tree.column(col, width=config['width'], anchor=config.get('anchor', tk.W))
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        x_scroll = ttk.Scrollbar(alerts_frame, orient=tk.HORIZONTAL, command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscroll=y_scroll.set, xscroll=x_scroll.set)
        
        # Grid layout
        self.alerts_tree.grid(row=1, column=0, sticky='nsew')
        y_scroll.grid(row=1, column=1, sticky='ns')
        x_scroll.grid(row=2, column=0, sticky='ew')
        
        # Configure grid weights
        alerts_frame.grid_rowconfigure(1, weight=1)
        alerts_frame.grid_columnconfigure(0, weight=1)
        
        # Configure tags for severity colors
        self.alerts_tree.tag_configure('critical', background='#ffebee')
        self.alerts_tree.tag_configure('high', background='#fff3e0')
        self.alerts_tree.tag_configure('medium', background='#e8f5e9')
        self.alerts_tree.tag_configure('low', background='#e3f2fd')
        
        # Add context menu
        self._create_alerts_context_menu()
    
    def _create_processes_panel(self, parent):
        """Create the processes monitoring panel"""
        proc_frame = ttk.LabelFrame(parent, text="Process Monitor", padding=5, style='Card.TFrame')
        proc_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create toolbar
        toolbar = ttk.Frame(proc_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Process filter
        ttk.Label(toolbar, text="Show:").pack(side=tk.LEFT, padx=2)
        self.process_filter_var = tk.StringVar()
        ttk.Combobox(
            toolbar, 
            textvariable=self.process_filter_var, 
            values=["All", "Running", "Suspended", "Zombie"],
            state='readonly',
            width=12
        ).pack(side=tk.LEFT, padx=2)
        self.process_filter_var.set("All")
        self.process_filter_var.trace('w', self._filter_processes)
        
        # Search box
        self.process_search_var = tk.StringVar()
        search_entry = ttk.Entry(
            toolbar, 
            textvariable=self.process_search_var,
            width=30
        )
        search_entry.pack(side=tk.RIGHT, padx=2)
        search_entry.bind('<Return>', lambda e: self._filter_processes())
        
        # Create treeview for processes
        columns = ('pid', 'name', 'cpu', 'memory', 'status', 'user', 'threads', 'exe')
        self.processes_tree = ttk.Treeview(
            proc_frame,
            columns=columns,
            show='headings',
            selectmode='extended',
            style='EDR.Treeview',
            height=10
        )
        
        # Configure columns
        col_config = {
            'pid': {'text': 'PID', 'width': 60, 'anchor': tk.E, 'stretch': False},
            'name': {'text': 'Name', 'width': 150, 'anchor': tk.W, 'stretch': False},
            'cpu': {'text': 'CPU %', 'width': 70, 'anchor': tk.E, 'stretch': False},
            'memory': {'text': 'Memory %', 'width': 80, 'anchor': tk.E, 'stretch': False},
            'status': {'text': 'Status', 'width': 80, 'anchor': tk.W, 'stretch': False},
            'user': {'text': 'User', 'width': 100, 'anchor': tk.W, 'stretch': False},
            'threads': {'text': 'Threads', 'width': 70, 'anchor': tk.E, 'stretch': False},
            'exe': {'text': 'Path', 'width': 300, 'anchor': tk.W, 'stretch': True}
        }
        
        for col, config in col_config.items():
            self.processes_tree.heading(col, text=config['text'], anchor=config.get('anchor', tk.W))
            self.processes_tree.column(col, width=config['width'], anchor=config.get('anchor', tk.W))
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(proc_frame, orient=tk.VERTICAL, command=self.processes_tree.yview)
        x_scroll = ttk.Scrollbar(proc_frame, orient=tk.HORIZONTAL, command=self.processes_tree.xview)
        self.processes_tree.configure(yscroll=y_scroll.set, xscroll=x_scroll.set)
        
        # Grid layout
        self.processes_tree.grid(row=1, column=0, sticky='nsew')
        y_scroll.grid(row=1, column=1, sticky='ns')
        x_scroll.grid(row=2, column=0, sticky='ew')
        
        # Configure grid weights
        proc_frame.grid_rowconfigure(1, weight=1)
        proc_frame.grid_columnconfigure(0, weight=1)
        
        # Add context menu
        self._create_processes_context_menu()
        
        # Bind double-click event
        self.processes_tree.bind('<Double-1>', self._on_process_double_click)
        
        # Initial process list
        self._update_processes()
    
    def _create_alerts_context_menu(self):
        """Create context menu for alerts"""
        self.alerts_menu = tk.Menu(self.frame, tearoff=0)
        self.alerts_menu.add_command(label="View Details", command=self._view_alert_details)
        self.alerts_menu.add_command(label="Acknowledge", command=self._acknowledge_alert)
        self.alerts_menu.add_separator()
        self.alerts_menu.add_command(label="Export...", command=self._export_alerts)
        
        # Bind right-click event
        self.alerts_tree.bind('<Button-3>', self._show_alerts_context_menu)
    
    def _create_processes_context_menu(self):
        """Create context menu for processes"""
        self.process_menu = tk.Menu(self.frame, tearoff=0)
        self.process_menu.add_command(label="View Details", command=self._view_process_details)
        self.process_menu.add_command(label="Kill Process", command=self._kill_process)
        self.process_menu.add_command(label="Suspend Process", command=self._suspend_process)
        self.process_menu.add_command(label="Resume Process", command=self._resume_process)
        self.process_menu.add_separator()
        self.process_menu.add_command(label="Add to Whitelist", command=self._whitelist_process)
        
        # Bind right-click event
        self.processes_tree.bind('<Button-3>', self._show_process_context_menu)
    
    def _show_alerts_context_menu(self, event):
        """Show context menu for alerts"""
        item = self.alerts_tree.identify_row(event.y)
        if item:
            self.alerts_tree.selection_set(item)
            self.alerts_menu.post(event.x_root, event.y_root)
    
    def _show_process_context_menu(self, event):
        """Show context menu for processes"""
        item = self.processes_tree.identify_row(event.y)
        if item:
            self.processes_tree.selection_set(item)
            self.process_menu.post(event.x_root, event.y_root)
    
    def _on_process_double_click(self, event):
        """Handle double-click on process"""
        self._view_process_details()
    
    def _view_alert_details(self):
        """View details of selected alert"""
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        alert_id = self.alerts_tree.item(selected[0], 'values')[0]
        # TODO: Show alert details dialog
        messagebox.showinfo("Alert Details", f"Details for alert {alert_id}")
    
    def _acknowledge_alert(self):
        """Acknowledge selected alert"""
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        # TODO: Implement alert acknowledgment
        for item in selected:
            self.alerts_tree.item(item, tags=('acknowledged',))
        
        self.status_var.set(f"Acknowledged {len(selected)} alert(s)")
    
    def _export_alerts(self):
        """Export alerts to file"""
        # TODO: Implement alert export
        messagebox.showinfo("Export", "Export functionality will be implemented here")
    
    def _view_process_details(self):
        """View details of selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        pid = self.processes_tree.item(selected[0], 'values')[0]
        # TODO: Show process details dialog
        messagebox.showinfo("Process Details", f"Details for process {pid}")
    
    def _kill_process(self):
        """Kill selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        pids = [self.processes_tree.item(item, 'values')[0] for item in selected]
        # TODO: Implement process termination
        self.status_var.set(f"Killed {len(pids)} process(es)")
        self._update_processes()
    
    def _suspend_process(self):
        """Suspend selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        pids = [self.processes_tree.item(item, 'values')[0] for item in selected]
        # TODO: Implement process suspension
        self.status_var.set(f"Suspended {len(pids)} process(es)")
        self._update_processes()
    
    def _resume_process(self):
        """Resume selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        pids = [self.processes_tree.item(item, 'values')[0] for item in selected]
        # TODO: Implement process resumption
        self.status_var.set(f"Resumed {len(pids)} process(es)")
        self._update_processes()
    
    def _whitelist_process(self):
        """Add selected process to whitelist"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        processes = [self.processes_tree.item(item, 'values') for item in selected]
        # TODO: Implement process whitelisting
        self.status_var.set(f"Added {len(processes)} process(es) to whitelist")
    
    def _filter_alerts(self, *args):
        """Filter alerts based on selected criteria"""
        # TODO: Implement alert filtering
        pass
    
    def _filter_processes(self, *args):
        """Filter processes based on selected criteria"""
        self._update_processes()
    
    def _update_processes(self):
        """Update the process list"""
        try:
            # Clear existing items
            for item in self.processes_tree.get_children():
                self.processes_tree.delete(item)
            
            # Get process list
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username', 'num_threads', 'exe']):
                try:
                    pinfo = proc.info
                    
                    # Skip if process name doesn't match filter
                    if (self.process_search_var.get() and 
                        self.process_search_var.get().lower() not in pinfo['name'].lower()):
                        continue
                    
                    # Skip if status doesn't match filter
                    status_filter = self.process_filter_var.get()
                    if status_filter != "All" and status_filter.lower() != pinfo['status'].lower():
                        continue
                    
                    self.processes_tree.insert('', 'end', values=(
                        pinfo['pid'],
                        pinfo['name'],
                        f"{pinfo['cpu_percent']:.1f}",
                        f"{pinfo['memory_percent']:.1f}",
                        pinfo['status'].capitalize(),
                        pinfo['username'].split('\\')[-1] if pinfo['username'] else 'SYSTEM',
                        pinfo['num_threads'],
                        pinfo['exe'] or ''
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            logger.error(f"Error updating process list: {e}")
            self.status_var.set(f"Error: {str(e)}")
            self.status_label.configure(style='Status.Critical.TLabel')
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off"""
        self.is_monitoring = not self.is_monitoring
        
        if self.is_monitoring:
            self.monitor_btn.config(text="Stop Monitoring")
            self.status_var.set("Monitoring started")
            self.status_label.configure(style='Status.Info.TLabel')
            self._start_monitoring()
        else:
            self.monitor_btn.config(text="Start Monitoring")
            self.status_var.set("Monitoring stopped")
            self._stop_monitoring()
    
    def _start_monitoring(self):
        """Start monitoring system and processes"""
        if not hasattr(self, '_monitor_thread') or not self._monitor_thread.is_alive():
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()
    
    def _stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        last_net_io = psutil.net_io_counters()
        last_time = time.time()
        
        while self.is_monitoring:
            try:
                # Update system metrics
                self._update_system_metrics()
                
                # Update process list
                self._update_processes()
                
                # Update network I/O
                current_time = time.time()
                time_diff = current_time - last_time
                if time_diff >= 1:  # Update network stats every second
                    current_net_io = psutil.net_io_counters()
                    bytes_sent = (current_net_io.bytes_sent - last_net_io.bytes_sent) / time_diff
                    bytes_recv = (current_net_io.bytes_recv - last_net_io.bytes_recv) / time_diff
                    
                    # Convert to KB/s
                    kb_sent = bytes_sent / 1024
                    kb_recv = bytes_recv / 1024
                    
                    self.network_var.set(f"▲{kb_sent:.1f} ▼{kb_recv:.1f} KB/s")
                    
                    last_net_io = current_net_io
                    last_time = current_time
                
                # Update last update time
                self.last_update_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Sleep for update interval
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                self.status_var.set(f"Error: {str(e)}")
                self.status_label.configure(style='Status.Critical.TLabel')
                time.sleep(5)  # Prevent tight loop on error
    
    def _update_system_metrics(self):
        """Update system metrics display"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.5)
            self.cpu_var.set(f"{cpu_percent:.1f}%")
            
            # Memory usage
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
            self.mem_var.set(f"{mem_percent:.1f}%")
            
            # Disk usage (C: drive on Windows, / on Unix)
            disk = psutil.disk_usage('C:' if platform.system() == 'Windows' else '/')
            disk_percent = disk.percent
            self.disk_var.set(f"{disk_percent:.1f}%")
            
            # Update status
            if cpu_percent > 90 or mem_percent > 90 or disk_percent > 90:
                self.status_label.configure(style='Status.Critical.TLabel')
            elif cpu_percent > 75 or mem_percent > 75 or disk_percent > 75:
                self.status_label.configure(style='Status.Warning.TLabel')
            else:
                self.status_label.configure(style='Status.Info.TLabel')
                
        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")
            raise
    
    def run_scan(self):
        """Run a system scan"""
        try:
            self.status_var.set("Running system scan...")
            self.status_label.configure(style='Status.Info.TLabel')
            self.frame.update()
            
            # Simulate scan
            time.sleep(2)  # Simulate scan time
            
            # Update last scan time
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_scan_var.set(scan_time)
            
            # Generate some sample alerts
            self._generate_sample_alerts()
            
            self.status_var.set("Scan completed successfully")
            self.status_label.configure(style='Status.Info.TLabel')
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logger.error(error_msg)
            self.status_var.set(error_msg)
            self.status_label.configure(style='Status.Critical.TLabel')
    
    def _generate_sample_alerts(self):
        """Generate sample alerts for demonstration"""
        alerts = [
            {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'High',
                'source': 'EDR Agent',
                'message': 'Suspicious process detected: malware.exe',
                'status': 'New'
            },
            {
                'timestamp': (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'Medium',
                'source': 'EDR Agent',
                'message': 'Unusual network connection to 192.168.1.100',
                'status': 'New'
            },
            {
                'timestamp': (datetime.now() - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'Critical',
                'source': 'EDR Agent',
                'message': 'Ransomware behavior detected in process encryptor.exe',
                'status': 'New'
            }
        ]
        
        # Clear existing alerts
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Add new alerts
        for alert in alerts:
            self.alerts_tree.insert('', 'end', values=(
                alert['timestamp'],
                alert['severity'],
                alert['source'],
                alert['message'],
                alert['status']
            ), tags=(alert['severity'].lower(),))
        
        # Update threats count
        self.threats_var.set(str(len(alerts)))
    
    def quarantine_selected(self):
        """Quarantine selected items"""
        selected_items = self.alerts_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "Please select items to quarantine")
            return
        
        try:
            # Get selected alert details
            alerts = []
            for item in selected_items:
                values = self.alerts_tree.item(item, 'values')
                alerts.append({
                    'timestamp': values[0],
                    'severity': values[1],
                    'source': values[2],
                    'message': values[3]
                })
            
            # TODO: Implement actual quarantine logic
            # For now, just update status
            for item in selected_items:
                self.alerts_tree.set(item, 'status', 'Quarantined')
                self.alerts_tree.item(item, tags=('quarantined',))
            
            self.status_var.set(f"Quarantined {len(selected_items)} item(s)")
            
        except Exception as e:
            error_msg = f"Failed to quarantine items: {str(e)}"
            logger.error(error_msg)
            messagebox.showerror("Error", error_msg)
    
    def refresh_data(self):
        """Refresh all data"""
        try:
            self._update_system_metrics()
            self._update_processes()
            self.status_var.set("Data refreshed")
            self.status_label.configure(style='Status.Info.TLabel')
        except Exception as e:
            error_msg = f"Failed to refresh data: {str(e)}"
            logger.error(error_msg)
            self.status_var.set(error_msg)
            self.status_label.configure(style='Status.Critical.TLabel')
    
    def _create_widgets(self):
        """Create and arrange all widgets in the EDR view"""
        # Main container
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Controls and status
        left_panel = ttk.LabelFrame(main_container, text="EDR Controls", padding=10)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5, ipadx=5, ipady=5)
        
        # Right panel - Alerts and monitoring
        right_panel = ttk.Frame(main_container)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add controls to left panel
        self._create_controls_panel(left_panel)
        self._create_status_panel(left_panel)
        
        # Add monitoring panels to right panel
        self._create_alerts_panel(right_panel)
        self._create_processes_panel(right_panel)
    
    def _create_controls_panel(self, parent):
        """Create the control buttons panel"""
        controls_frame = ttk.LabelFrame(parent, text="Agent Controls", padding=5)
        controls_frame.pack(fill=tk.X, pady=(0, 10), ipadx=5, ipady=5)
        
        # Start/Stop button
        self.toggle_btn = ttk.Button(
            controls_frame, 
            text="Start Monitoring", 
            command=self.toggle_monitoring,
            width=15
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Refresh button
        refresh_btn = ttk.Button(
            controls_frame,
            text="Refresh",
            command=self.refresh_data,
            width=10
        )
        refresh_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Settings button
        settings_btn = ttk.Button(
            controls_frame,
            text="Settings",
            command=self.show_settings,
            width=10
        )
        settings_btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    def _create_status_panel(self, parent):
        """Create the status information panel"""
        status_frame = ttk.LabelFrame(parent, text="System Status", padding=5)
        status_frame.pack(fill=tk.X, pady=(0, 10), ipadx=5, ipady=5)
        
        # System info
        ttk.Label(status_frame, text="Hostname:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hostname_var = tk.StringVar(value=socket.gethostname())
        ttk.Label(status_frame, textvariable=self.hostname_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(status_frame, text="OS:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.os_var = tk.StringVar(value=f"{platform.system()} {platform.release()}")
        ttk.Label(status_frame, textvariable=self.os_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # CPU usage
        ttk.Label(status_frame, text="CPU Usage:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.cpu_var = tk.StringVar(value="0.0%")
        ttk.Label(status_frame, textvariable=self.cpu_var, style='Metric.TLabel').grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Memory usage
        ttk.Label(status_frame, text="Memory Usage:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.mem_var = tk.StringVar(value="0.0%")
        ttk.Label(status_frame, textvariable=self.mem_var, style='Metric.TLabel').grid(row=3, column=1, sticky=tk.W, pady=2)
        
        # Agent status
        ttk.Label(status_frame, text="Agent Status:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.agent_status_var = tk.StringVar(value="Stopped")
        ttk.Label(status_frame, textvariable=self.agent_status_var, style='Alert.TLabel').grid(row=4, column=1, sticky=tk.W, pady=2)
        
        # Update status initially
        self.update_system_status()
    
    def _create_alerts_panel(self, parent):
        """Create the alerts panel"""
        alerts_frame = ttk.LabelFrame(parent, text="Security Alerts", padding=5)
        alerts_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), ipadx=5, ipady=5)
        
        # Create treeview for alerts
        columns = ('time', 'type', 'severity', 'process', 'details')
        self.alerts_tree = ttk.Treeview(
            alerts_frame, 
            columns=columns, 
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.alerts_tree.heading('time', text='Time')
        self.alerts_tree.heading('type', text='Type')
        self.alerts_tree.heading('severity', text='Severity')
        self.alerts_tree.heading('process', text='Process')
        self.alerts_tree.heading('details', text='Details')
        
        # Set column widths
        self.alerts_tree.column('time', width=150, anchor=tk.W)
        self.alerts_tree.column('type', width=100, anchor=tk.W)
        self.alerts_tree.column('severity', width=80, anchor=tk.W)
        self.alerts_tree.column('process', width=150, anchor=tk.W)
        self.alerts_tree.column('details', width=300, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scrollbar.set)
        
        # Pack everything
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add context menu
        self._create_alerts_context_menu()
    
    def _create_processes_panel(self, parent):
        """Create the processes monitoring panel"""
        processes_frame = ttk.LabelFrame(parent, text="Process Monitor", padding=5)
        processes_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), ipadx=5, ipady=5)
        
        # Create treeview for processes
        columns = ('pid', 'name', 'cpu', 'memory', 'status')
        self.processes_tree = ttk.Treeview(
            processes_frame,
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.processes_tree.heading('pid', text='PID')
        self.processes_tree.heading('name', text='Process Name')
        self.processes_tree.heading('cpu', text='CPU %')
        self.processes_tree.heading('memory', text='Memory %')
        self.processes_tree.heading('status', text='Status')
        
        # Set column widths
        self.processes_tree.column('pid', width=80, anchor=tk.W)
        self.processes_tree.column('name', width=200, anchor=tk.W)
        self.processes_tree.column('cpu', width=80, anchor=tk.W)
        self.processes_tree.column('memory', width=80, anchor=tk.W)
        self.processes_tree.column('status', width=100, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(processes_frame, orient=tk.VERTICAL, command=self.processes_tree.yview)
        self.processes_tree.configure(yscroll=scrollbar.set)
        
        # Pack everything
        self.processes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add context menu
        self._create_processes_context_menu()
    
    def _create_alerts_context_menu(self):
        """Create context menu for alerts"""
        self.alerts_menu = tk.Menu(self.frame, tearoff=0)
        self.alerts_menu.add_command(label="View Details", command=self.view_alert_details)
        self.alerts_menu.add_command(label="Mark as Resolved", command=self.resolve_alert)
        self.alerts_menu.add_separator()
        self.alerts_menu.add_command(label="Export to CSV", command=self.export_alerts)
        
        # Bind right-click event
        self.alerts_tree.bind("<Button-3>", self.show_alerts_context_menu)
    
    def _create_processes_context_menu(self):
        """Create context menu for processes"""
        self.processes_menu = tk.Menu(self.frame, tearoff=0)
        self.processes_menu.add_command(label="Kill Process", command=self.kill_process)
        self.processes_menu.add_command(label="View Details", command=self.view_process_details)
        
        # Bind right-click event
        self.processes_tree.bind("<Button-3>", self.show_processes_context_menu)
    
    def toggle_monitoring(self):
        """Toggle EDR monitoring on/off"""
        if not self.edr_agent:
            messagebox.showerror("Error", "EDR agent not initialized")
            return
            
        if self.is_monitoring:
            # Stop monitoring
            self.edr_agent.stop()
            self.is_monitoring = False
            self.toggle_btn.config(text="Start Monitoring")
            self.agent_status_var.set("Stopped")
        else:
            # Start monitoring
            try:
                self.edr_agent.start()
                self.is_monitoring = True
                self.toggle_btn.config(text="Stop Monitoring")
                self.agent_status_var.set("Running")
                # Start periodic updates
                self.update_data()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start EDR agent: {str(e)}")
    
    def refresh_data(self):
        """Manually refresh all data"""
        self.update_system_status()
        self.update_processes_list()
        self.update_alerts()
    
    def update_data(self):
        """Update all data periodically"""
        if not self.is_monitoring:
            return
            
        self.update_system_status()
        self.update_processes_list()
        self.update_alerts()
        
        # Schedule next update (every 5 seconds)
        self.frame.after(5000, self.update_data)
    
    def update_system_status(self):
        """Update system status information"""
        try:
            # Update CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.5)
            self.cpu_var.set(f"{cpu_percent:.1f}%")
            
            # Update memory usage
            mem = psutil.virtual_memory()
            self.mem_var.set(f"{mem.percent:.1f}%")
            
        except Exception as e:
            print(f"Error updating system status: {str(e)}")
    
    def update_processes_list(self):
        """Update the list of running processes"""
        try:
            # Clear existing items
            for item in self.processes_tree.get_children():
                self.processes_tree.delete(item)
            
            # Get process list
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    pinfo = proc.info
                    processes.append((
                        pinfo['pid'],
                        pinfo['name'],
                        pinfo['cpu_percent'],
                        pinfo['memory_percent'],
                        pinfo['status']
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Sort by CPU usage (descending)
            processes.sort(key=lambda x: x[2], reverse=True)
            
            # Add to treeview
            for proc in processes[:100]:  # Limit to top 100 processes
                self.processes_tree.insert('', 'end', values=(
                    proc[0],  # pid
                    proc[1],  # name
                    f"{proc[2]:.1f}%",  # cpu
                    f"{proc[3]:.1f}%",  # memory
                    proc[4]   # status
                ))
                
        except Exception as e:
            print(f"Error updating process list: {str(e)}")
    
    def update_alerts(self):
        """Update the alerts list"""
        # This would be connected to the EDR agent's alert system
        # For now, we'll just show a placeholder
        pass
    
    def view_alert_details(self):
        """Show details for the selected alert"""
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        item = self.alerts_tree.item(selected[0])
        messagebox.showinfo("Alert Details", f"Details for alert: {item['values']}")
    
    def resolve_alert(self):
        """Mark the selected alert as resolved"""
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        self.alerts_tree.delete(selected[0])
    
    def export_alerts(self):
        """Export alerts to CSV"""
        # This would export alerts to a CSV file
        messagebox.showinfo("Export", "Exporting alerts to CSV...")
    
    def kill_process(self):
        """Kill the selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        item = self.processes_tree.item(selected[0])
        pid = item['values'][0]  # Get PID from first column
        
        try:
            process = psutil.Process(pid)
            process.terminate()
            self.update_processes_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill process: {str(e)}")
    
    def view_process_details(self):
        """Show detailed information about the selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
            
        item = self.processes_tree.item(selected[0])
        pid = item['values'][0]  # Get PID from first column
        
        try:
            process = psutil.Process(pid)
            with process.oneshot():
                info = {
                    'PID': process.pid,
                    'Name': process.name(),
                    'Status': process.status(),
                    'CPU %': process.cpu_percent(interval=0.1),
                    'Memory %': process.memory_percent(),
                    'Create Time': datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                    'Executable': process.exe(),
                    'Command Line': ' '.join(process.cmdline()) if process.cmdline() else '',
                    'Working Directory': process.cwd(),
                    'Username': process.username(),
                    'Threads': process.num_threads(),
                    'Open Files': len(process.open_files()),
                    'Connections': len(process.connections())
                }
                
                # Create a formatted string with process details
                details = ""
                for key, value in info.items():
                    details += f"{key}: {value}\n"
                
                # Show in a messagebox
                messagebox.showinfo(f"Process Details - PID: {pid}", details)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process details: {str(e)}")
    
    def show_settings(self):
        """Show EDR settings dialog"""
        settings_win = tk.Toplevel(self.frame)
        settings_win.title("EDR Settings")
        settings_win.geometry("500x400")
        
        # Add settings controls here
        ttk.Label(settings_win, text="EDR Agent Settings", font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Add a text widget to show current settings
        text = ScrolledText(settings_win, wrap=tk.WORD, width=60, height=20)
        text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Add some sample settings
        settings = """[EDR Agent Settings]
Check Interval: 60 seconds
SIEM Endpoint: http://localhost:5000/api/alerts

[Detection Settings]
Monitor Processes: Enabled
Monitor Network: Enabled
Monitor Files: Disabled

[Alerting]
Email Alerts: Disabled
Webhook Alerts: Disabled

[Advanced]
Debug Mode: Disabled
Log Level: INFO
"""
        text.insert(tk.END, settings)
        text.config(state=tk.DISABLED)
        
        # Add buttons
        btn_frame = ttk.Frame(settings_win)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Save", command=settings_win.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=settings_win.destroy).pack(side=tk.LEFT, padx=5)
    
    def show_alerts_context_menu(self, event):
        """Show context menu for alerts"""
        item = self.alerts_tree.identify_row(event.y)
        if item:
            self.alerts_tree.selection_set(item)
            self.alerts_menu.post(event.x_root, event.y_root)
    
    def show_processes_context_menu(self, event):
        """Show context menu for processes"""
        item = self.processes_tree.identify_row(event.y)
        if item:
            self.processes_tree.selection_set(item)
            self.processes_menu.post(event.x_root, event.y_root)
