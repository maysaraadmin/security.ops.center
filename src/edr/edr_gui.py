import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import threading
import time
from datetime import datetime
import platform
import os
import json
import webbrowser
import logging
from collections import defaultdict

# Local imports
from src.edr.threat_detection import ThreatDetector
from src.edr.rule_manager import RuleManager
from src.edr.rule_editor import RuleManagerUI, RuleEditor

class EDRGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EDR - Endpoint Detection & Response")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Setup logging
        self.logger = logging.getLogger('EDRGUI')
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Create file handler which logs even debug messages
        fh = logging.FileHandler('logs/edr_gui.log')
        fh.setLevel(logging.DEBUG)
        
        # Create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        
        # Create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        # Add the handlers to the logger
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        # Initialize data structures
        self.processes = {}
        self.process_tree = {}
        self.suspicious_processes = {}
        self.alerts = []
        self.running = True
        self.update_interval = 5  # seconds
        
        # Initialize components
        self.rule_manager = RuleManager(os.path.join('edr', 'rules'))
        self.threat_detector = ThreatDetector(self.rule_manager)
        
        # Load configuration
        self.load_config()
        
        # Setup UI
        self.setup_ui()
        
        # Start process monitoring
        self.update_processes()
        self.update_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        self.update_thread.start()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def load_config(self):
        """Load configuration from file or use defaults."""
        self.config_file = 'edr_config.json'
        default_config = {
            "suspicious_processes": [
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"
            ],
            "suspicious_paths": [
                "temp", "appdata", "windows\\temp"
            ],
            "threat_detection": {
                "enabled": True,
                "scan_interval": 60,
                "auto_block_high": True,
                "auto_block_medium": False,
                "auto_block_low": False
            },
            "alerts": {
                "show_popup": True,
                "play_sound": False,
                "log_to_file": True
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = {**default_config, **json.load(f)}
            else:
                self.config = default_config
                self.save_config()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load config: {e}")
            self.config = default_config
    
    def save_config(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")
            return False
        
        # Load from config file if exists
        if os.path.exists("edr_config.json"):
            try:
                with open("edr_config.json", "r") as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
            except Exception as e:
                print(f"Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to file."""
        try:
            with open("edr_config.json", "w") as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
            return False
    
    def setup_ui(self):
        # Main container
        main_container = ttk.Frame(self.root, padding="5")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Top toolbar
        toolbar = ttk.Frame(main_container)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Buttons
        ttk.Button(toolbar, text="Refresh", command=self.update_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Kill Process", command=self.kill_selected_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Process Details", command=self.show_process_details).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Scan System", command=self.scan_system).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Settings", command=self.show_settings).pack(side=tk.LEFT, padx=2)
        
        # Search frame
        search_frame = ttk.Frame(main_container)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_processes)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        search_entry.focus()
        
        # Process tree
        tree_frame = ttk.LabelFrame(main_container, text="Processes", padding=5)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview with scrollbars
        self.tree = ttk.Treeview(tree_frame, columns=("PID", "Name", "Status", "CPU %", "Memory %", "Username", "Threat"), 
                                selectmode="extended", show="headings")
        
        # Configure scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        
        # Configure tree columns
        self.tree.heading("PID", text="PID", command=lambda: self.sort_column("PID", False))
        self.tree.heading("Name", text="Name", command=lambda: self.sort_column("Name", False))
        self.tree.heading("Status", text="Status", command=lambda: self.sort_column("Status", False))
        self.tree.heading("CPU %", text="CPU %", command=lambda: self.sort_column("CPU %", False))
        self.tree.heading("Memory %", text="Memory %", command=lambda: self.sort_column("Memory %", True))
        self.tree.heading("Username", text="Username", command=lambda: self.sort_column("Username", False))
        self.tree.heading("Threat", text="Threat", command=lambda: self.sort_column("Threat", False))
        
        # Configure column widths
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("PID", width=80, minwidth=60)
        self.tree.column("Name", width=200, minwidth=150)
        self.tree.column("Status", width=80, minwidth=60)
        self.tree.column("CPU %", width=80, minwidth=60, anchor=tk.E)
        self.tree.column("Memory %", width=80, minwidth=60, anchor=tk.E)
        self.tree.column("Username", width=150, minwidth=100)
        self.tree.column("Threat", width=100, minwidth=80)
        
        # Configure grid weights
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Bind double click event
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Delete>", lambda e: self.kill_selected_process())
    
    def setup_alerts_list(self):
        """Setup the alerts list."""
        # Alerts tree
        alerts_frame = ttk.LabelFrame(self.alerts_tab, text="Alerts", padding=5)
        alerts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview with scrollbars
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=("Timestamp", "Severity", "Type", "Message"), 
                                       selectmode="extended")
        
        # Configure scrollbars
        vsb = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        hsb = ttk.Scrollbar(alerts_frame, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.alerts_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        
        # Configure tree columns
        self.alerts_tree.heading("#0", text="")
        self.alerts_tree.heading("Timestamp", text="Timestamp", command=lambda: self.sort_column("Timestamp", False))
        self.alerts_tree.heading("Severity", text="Severity", command=lambda: self.sort_column("Severity", False))
        self.alerts_tree.heading("Type", text="Type", command=lambda: self.sort_column("Type", False))
        self.alerts_tree.heading("Message", text="Message", command=lambda: self.sort_column("Message", False))
        
        # Configure column widths
        self.alerts_tree.column("#0", width=0, stretch=tk.NO)
        self.alerts_tree.column("Timestamp", width=150, minwidth=100)
        self.alerts_tree.column("Severity", width=80, minwidth=60)
        self.alerts_tree.column("Type", width=100, minwidth=80)
        self.alerts_tree.column("Message", width=400, minwidth=300)
        
        # Configure grid weights
        alerts_frame.columnconfigure(0, weight=1)
        alerts_frame.rowconfigure(0, weight=1)
        
        # Bind double click event
        self.alerts_tree.bind("<Double-1>", self.on_alert_double_click)
    
    def setup_toolbar(self):
        """Setup the toolbar."""
        # Top toolbar
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Buttons
        ttk.Button(toolbar, text="Refresh", command=self.update_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Kill Process", command=self.kill_selected_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Process Details", command=self.show_process_details).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Scan System", command=self.scan_system).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Settings", command=self.show_settings).pack(side=tk.LEFT, padx=2)
        
        # Search frame
        search_frame = ttk.Frame(self.main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_processes)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        search_entry.focus()
    
    def _init_rules_ui(self):
        """Initialize the rules management UI."""
        self.rule_manager_ui = RuleManagerUI(self.rules_tab, self.rule_manager)
        self.rule_manager_ui.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add a frame for buttons at the bottom
        button_frame = ttk.Frame(self.rules_tab)
        button_frame.pack(fill=tk.X, pady=(0, 5), padx=5)
        
        ttk.Button(
            button_frame,
            text="Apply Rules",
            command=self._apply_rules,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            button_frame,
            text="Refresh",
            command=self._refresh_rules
        ).pack(side=tk.LEFT, padx=2)
    
    def _apply_rules(self):
        """Apply the current rules to the threat detector."""
        if not hasattr(self, 'threat_detector') or not self.threat_detector:
            self.logger.warning("Cannot apply rules: threat detector not initialized")
            return
            
        try:
            rules = self.rule_manager.get_rules()
            if hasattr(self.threat_detector, 'update_rules'):
                self.threat_detector.update_rules(rules)
            self.logger.info(f"Applied {len(rules)} rules to threat detector")
            self.update_status(f"Applied {len(rules)} detection rules")
        except Exception as e:
            self.logger.error(f"Failed to apply rules: {str(e)}", exc_info=True)
            messagebox.showerror("Error", f"Failed to apply rules: {str(e)}")
    
    def update_status(self, message: str):
        """Update the status bar with a message."""
        if hasattr(self, 'status_var'):
            self.status_var.set(message)
        self.logger.info(f"Status: {message}")
    
    def _refresh_rules(self):
        """Refresh the rules from disk."""
        try:
            # Reinitialize the rule manager to reload rules
            self.rule_manager = RuleManager(os.path.join('edr', 'rules'))
            self.rule_manager_ui.destroy()
            self._init_rules_ui()
            self.update_status("Rules refreshed from disk")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh rules: {e}")
    
    def init_threat_detection(self):
        """Initialize the threat detection system."""
        try:
            # Initialize threat detector
            self.threat_detector = ThreatDetector(rule_manager=self.rule_manager)
            if hasattr(self.threat_detector, 'start'):
                self.threat_detector.start()
            self.logger.info("Threat detection initialized")
        except Exception as e:
            self.logger.error(f"Threat detection initialization failed: {str(e)}", exc_info=True)
            messagebox.showerror("Error", f"Failed to initialize threat detection: {str(e)}")
    
    def handle_threat_alert(self, alert):
        """Handle threat detection alerts."""
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Add to alerts list
        self.alerts.append(alert)
        
        # Update UI in the main thread
        self.root.after(0, self._process_alert, alert)
    
    def _process_alert(self, alert):
        """Process an alert in the main thread."""
        try:
            # Update alerts display
            self.update_alerts_display()
            
            # Get the rule that triggered this alert
            rule = self.rule_manager.get_rule(alert.get('rule_id', ''))
            
            # Determine severity
            severity = alert.get('severity', 'medium')
            if rule and 'severity' in rule:
                severity = rule['severity']
            
            # Show popup if enabled
            if self.config['alerts']['show_popup']:
                message = alert.get('message', 'No details available')
                if rule and 'description' in rule:
                    message = f"{rule['description']}\n\n{message}"
                
                self.root.after(0, lambda: messagebox.showwarning(
                    f"Threat Detected - {severity.upper()}",
                    f"{message}\n\nType: {alert.get('type', 'Unknown')}"
                ))
            
            # Auto-block if configured
            should_block = False
            if severity == 'high' and self.config['threat_detection']['auto_block_high']:
                should_block = True
            elif severity == 'medium' and self.config['threat_detection']['auto_block_medium']:
                should_block = True
            elif severity == 'low' and self.config['threat_detection']['auto_block_low']:
                should_block = True
            
            if should_block:
                self.block_threat(alert)
                
            # Log the alert
            self._log_alert(alert, severity)
            
        except Exception as e:
            logging.error(f"Error processing alert: {e}", exc_info=True)
    
    def _log_alert(self, alert, severity):
        """Log an alert to file if enabled."""
        if not self.config['alerts']['log_to_file']:
            return
            
        log_entry = {
            'timestamp': alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'severity': severity,
            'type': alert.get('type', 'unknown'),
            'message': alert.get('message', ''),
            'rule_id': alert.get('rule_id', ''),
            'process': alert.get('process', {})
        }
        
        log_dir = os.path.join('logs', 'alerts')
        os.makedirs(log_dir, exist_ok=True)
        
        try:
            log_file = os.path.join(log_dir, f"alerts_{datetime.now().strftime('%Y%m%d')}.log")
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logging.error(f"Failed to write alert to log: {e}")
    
    def block_threat(self, alert):
        """Take action to block a detected threat."""
        try:
            process_info = alert.get('process', {})
            pid = process_info.get('pid')
            
            if not pid:
                return False
            
            # Get the rule to determine the action
            rule = self.rule_manager.get_rule(alert.get('rule_id', ''))
            action = 'terminate'  # Default action
            
            if rule and 'action' in rule:
                action = rule['action'].lower()
            
            success = False
            
            if action == 'terminate':
                # Terminate the process
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                    success = True
                    self.update_status(f"Terminated process {pid} ({process_info.get('name', '')})")
                except psutil.NoSuchProcess:
                    self.update_status(f"Process {pid} not found (already terminated?)")
                    success = True
                except psutil.AccessDenied:
                    self.update_status(f"Access denied when trying to terminate process {pid}")
            
            elif action == 'quarantine':
                # Quarantine the process (placeholder implementation)
                try:
                    process = psutil.Process(pid)
                    exe_path = process.exe()
                    
                    # Create quarantine directory if it doesn't exist
                    quarantine_dir = os.path.join('quarantine')
                    os.makedirs(quarantine_dir, exist_ok=True)
                    
                    # Generate a unique filename
                    import hashlib
                    file_hash = hashlib.md5(open(exe_path, 'rb').read()).hexdigest()
                    target_path = os.path.join(quarantine_dir, f"{file_hash}_{os.path.basename(exe_path)}")
                    
                    # Move the file to quarantine
                    import shutil
                    shutil.move(exe_path, target_path)
                    
                    # Terminate the process
                    process.terminate()
                    
                    success = True
                    self.update_status(f"Quarantined and terminated process {pid} ({exe_path})")
                    
                except Exception as e:
                    self.update_status(f"Failed to quarantine process {pid}: {e}")
            
            # Log the action
            self._log_action(
                action=action,
                target_type='process',
                target_id=str(pid),
                rule_id=alert.get('rule_id', ''),
                success=success,
                details={
                    'process_name': process_info.get('name', ''),
                    'command_line': process_info.get('cmdline', '')
                }
            )
            
            return success
            
        except Exception as e:
            self.update_status(f"Error blocking threat: {e}")
            logging.error(f"Error blocking threat: {e}", exc_info=True)
            return False
    
    def _log_action(self, action, target_type, target_id, rule_id='', success=True, details=None):
        """Log a response action to the audit log."""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action': action,
            'target_type': target_type,
            'target_id': target_id,
            'rule_id': rule_id,
            'success': success,
            'details': details or {}
        }
        
        log_dir = os.path.join('logs', 'audit')
        os.makedirs(log_dir, exist_ok=True)
        
        try:
            log_file = os.path.join(log_dir, f"audit_{datetime.now().strftime('%Y%m%d')}.log")
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logging.error(f"Failed to write to audit log: {e}")
    
    def update_processes(self):
        """Update the process list."""
        # Save selection
        selected = self.tree.selection()
        selected_pid = self.tree.item(selected[0])['values'][0] if selected else None
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get process information
        self.processes = {}
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'username', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                self.processes[pid] = info
                
                # Check if process is suspicious
                is_suspicious = any(
                    proc_name.lower() in info['name'].lower() 
                    for proc_name in self.config['suspicious_processes']
                )
                
                # Check if process is in suspicious_processes dictionary
                threat_level = self.suspicious_processes.get(pid, '')
                
                # Add to treeview
                item = self.tree.insert('', 'end', values=(
                    pid,
                    info['name'],
                    info['status'],
                    f"{info['cpu_percent']:.1f}",
                    f"{info['memory_percent']:.1f}",
                    info['username'],
                    threat_level if threat_level else ("Suspicious" if is_suspicious else "")
                ))
                
                # Highlight suspicious processes
                if threat_level:
                    self.tree.item(item, tags=('threat',))
                    self.tree.tag_configure('threat', background='#ffdddd')
                elif is_suspicious:
                    self.tree.item(item, tags=('suspicious',))
                    self.tree.tag_configure('suspicious', background='#ffffcc')
                
                # Restore selection
                if selected_pid and pid == selected_pid:
                    self.tree.selection_set(item)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                continue
        
        # Update status
        self.update_status(f"Processes updated: {len(self.processes)} running")
    
    def update_alerts_display(self):
        """Update the alerts list display."""
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Add alerts to treeview
        for alert in reversed(self.alerts[-100:]):  # Show last 100 alerts
            self.alerts_tree.insert('', 'end', values=(
                alert.get('timestamp', ''),
                alert.get('severity', '').capitalize(),
                alert.get('type', ''),
                alert.get('message', '')[:200]  # Truncate long messages
            ))
            
            # Color code by severity
            severity = alert.get('severity', '').lower()
            if severity == 'high':
                self.alerts_tree.item(self.alerts_tree.get_children()[-1], tags=('high',))
                self.alerts_tree.tag_configure('high', background='#ffdddd')
            elif severity == 'medium':
                self.alerts_tree.item(self.alerts_tree.get_children()[-1], tags=('medium',))
                self.alerts_tree.tag_configure('medium', background='#fff3cd')
        
        # Update tab title
        self.notebook.tab(1, text=f"Alerts ({len(self.alerts)})")
    
    def sort_column(self, col, reverse):
        """Sort tree contents when a column header is clicked."""
        # Get all items and their values
        items = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        
        # Sort the items
        try:
            # Try to sort as numbers
            items.sort(key=lambda x: float(x[0].rstrip('%') if x[0] else 0), reverse=reverse)
        except ValueError:
            # Sort as strings if not numbers
            items.sort(reverse=reverse)
        
        # Rearrange items in sorted positions
        for index, (val, child) in enumerate(items):
            self.tree.move(child, '', index)
        
        # Reverse sort next time
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))
    
    def filter_processes(self, *args):
        """Filter processes based on search text."""
        search_text = self.search_var.get().lower()
        
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if not values:
                continue
                
            # Check if search text matches any column
            text_found = any(search_text in str(val).lower() for val in values)
            self.tree.item(item, open=True)
            
            if search_text == '':
                self.tree.attach(item, '', 'end')
            elif text_found:
                self.tree.attach(item, '', 'end')
            else:
                self.tree.detach(item)
    
    def kill_selected_process(self):
        """Kill the selected process."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a process to kill.")
            return
            
        if not messagebox.askyesno("Confirm Kill", 
                                 f"Are you sure you want to kill {len(selected)} process(es)?"):
            return
            
        killed = 0
        for item in selected:
            try:
                pid = int(self.tree.item(item, 'values')[0])
                p = psutil.Process(pid)
                p.terminate()
                killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Failed to kill process {pid}: {e}")
            except Exception as e:
                messagebox.showerror("Error", f"Unexpected error: {e}")
        
        if killed > 0:
            self.status_var.set(f"Successfully killed {killed} process(es).")
            self.update_processes()
    
    def show_process_details(self):
        """Show detailed information about the selected process."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a process to view details.")
            return
            
        pid = int(self.tree.item(selected[0], 'values')[0])
        
        try:
            proc = psutil.Process(pid)
            
            # Create details window
            details_win = tk.Toplevel(self.root)
            details_win.title(f"Process Details - PID: {pid}")
            details_win.geometry("600x500")
            
            # Create notebook for tabs
            notebook = ttk.Notebook(details_win)
            notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # General Tab
            general_frame = ttk.Frame(notebook)
            notebook.add(general_frame, text="General")
            
            # Process info
            info_frame = ttk.LabelFrame(general_frame, text="Process Information", padding=10)
            info_frame.pack(fill=tk.X, padx=5, pady=5)
            
            info_text = tk.Text(info_frame, wrap=tk.WORD, height=15, font=('Consolas', 10))
            info_text.pack(fill=tk.BOTH, expand=True)
            
            # Add process info
            info_text.insert(tk.END, f"{'PID:':<15} {pid}\n")
            info_text.insert(tk.END, f"{'Name:':<15} {proc.name()}\n")
            info_text.insert(tk.END, f"{'Status:':<15} {proc.status()}\n")
            info_text.insert(tk.END, f"{'Username:':<15} {proc.username()}\n")
            info_text.insert(tk.END, f"{'CPU %:':<15} {proc.cpu_percent():.1f}%\n")
            info_text.insert(tk.END, f"{'Memory %:':<15} {proc.memory_percent():.1f}%\n")
            
            try:
                info_text.insert(tk.END, f"{'Exe:':<15} {proc.exe()}\n")
                info_text.insert(tk.END, f"{'CWD:':<15} {proc.cwd()}\n")
                info_text.insert(tk.END, f"{'Cmdline:':<15} {' '.join(proc.cmdline())}\n")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info_text.insert(tk.END, "[Access denied to some process information]\n")
            
            info_text.config(state=tk.DISABLED)
            
            # Buttons
            btn_frame = ttk.Frame(general_frame)
            btn_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Button(btn_frame, text="Kill Process", 
                      command=lambda: self.kill_process(pid, details_win)).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="Refresh", 
                      command=lambda: self.refresh_process_details(details_win, pid)).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="Close", 
                      command=details_win.destroy).pack(side=tk.RIGHT, padx=2)
            
            # Memory Tab
            memory_frame = ttk.Frame(notebook)
            notebook.add(memory_frame, text="Memory")
            
            memory_text = tk.Text(memory_frame, wrap=tk.WORD, font=('Consolas', 10))
            memory_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            try:
                memory_info = proc.memory_info()
                memory_text.insert(tk.END, f"{'RSS:':<20} {memory_info.rss / (1024*1024):.2f} MB\n")
                memory_text.insert(tk.END, f"{'VMS:':<20} {memory_info.vms / (1024*1024):.2f} MB\n")
                memory_text.config(state=tk.DISABLED)
                
                # Network Tab
                network_frame = ttk.Frame(notebook)
                notebook.add(network_frame, text="Network")
                
                conn_text = tk.Text(network_frame, wrap=tk.WORD, font=('Consolas', 10))
                conn_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                try:
                    connections = proc.connections()
                    if connections:
                        for conn in connections:
                            conn_text.insert(tk.END, f"{conn.laddr} -> {conn.raddr if conn.raddr else ''} ({conn.status})\n")
                    else:
                        conn_text.insert(tk.END, "No network connections found.")
                except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                    conn_text.insert(tk.END, f"Error: {e}")
                
                conn_text.config(state=tk.DISABLED)
                
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                memory_text.insert(tk.END, f"Error: {e}")
                memory_text.config(state=tk.DISABLED)
            
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", "The selected process no longer exists.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process details: {e}")
    
    def kill_process(self, pid, window):
        """Kill a process and close the details window."""
        if messagebox.askyesno("Confirm Kill", f"Are you sure you want to kill process {pid}?"):
            try:
                p = psutil.Process(pid)
                p.terminate()
                messagebox.showinfo("Success", f"Process {pid} has been terminated.")
                window.destroy()
                self.update_processes()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to kill process: {e}")
    
    def refresh_process_details(self, window, pid):
        """Refresh process details window."""
        window.destroy()
        self.show_process_details()
    
    def scan_system(self):
        """Perform a system scan for suspicious processes."""
        self.status_var.set("Scanning system for suspicious processes...")
        self.root.update()
        
        suspicious = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            if self.is_suspicious(proc):
                suspicious.append(proc)
        
        if suspicious:
            msg = f"Found {len(suspicious)} suspicious processes:\n\n"
            for proc in suspicious:
                msg += f"PID: {proc.info['pid']} | {proc.info['name']} | {proc.info['username']}\n"
            
            messagebox.showwarning("Suspicious Processes Found", msg)
        else:
            messagebox.showinfo("Scan Complete", "No suspicious processes found.")
        
        self.status_var.set("System scan completed.")
    
    def show_settings(self):
        """Show settings dialog."""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("EDR Settings")
        settings_win.geometry("600x400")
        
        # Create notebook for settings tabs
        notebook = ttk.Notebook(settings_win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # General Settings Tab
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        # Update interval
        ttk.Label(general_frame, text="Update Interval (seconds):").grid(row=0, column=0, sticky=tk.W, pady=2)
        update_interval = tk.StringVar(value=str(self.update_interval))
        ttk.Entry(general_frame, textvariable=update_interval, width=10).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Suspicious Processes Tab
        suspicious_frame = ttk.Frame(notebook)
        notebook.add(suspicious_frame, text="Suspicious Processes")
        
        # Suspicious processes list
        ttk.Label(suspicious_frame, text="Suspicious process names (one per line):").pack(anchor=tk.W, pady=(0, 5))
        
        suspicious_text = tk.Text(suspicious_frame, width=60, height=10)
        suspicious_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        suspicious_text.insert(tk.END, '\n'.join(self.config['suspicious_processes']))
        
        # Suspicious paths
        ttk.Label(suspicious_frame, text="Suspicious paths (one per line, case insensitive):").pack(anchor=tk.W, pady=(10, 5))
        
        paths_text = tk.Text(suspicious_frame, width=60, height=5)
        paths_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        paths_text.insert(tk.END, '\n'.join(self.config['suspicious_paths']))
        
        # Buttons
        btn_frame = ttk.Frame(settings_win)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        def save_settings():
            try:
                # Update update interval
                self.update_interval = max(1, int(update_interval.get()))
                
                # Update suspicious processes
                suspicious = [line.strip() for line in suspicious_text.get('1.0', tk.END).split('\n') if line.strip()]
                self.config['suspicious_processes'] = suspicious
                
                # Update suspicious paths
                paths = [line.strip().lower() for line in paths_text.get('1.0', tk.END).split('\n') if line.strip()]
                self.config['suspicious_paths'] = paths
                
                # Save to file
                if self.save_config():
                    messagebox.showinfo("Success", "Settings saved successfully.")
                    settings_win.destroy()
                    
                    # Rescan processes with new settings
                    self.suspicious_processes.clear()
                    self.update_processes()
                
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number for update interval.")
        
        ttk.Button(btn_frame, text="Save", command=save_settings).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Cancel", command=settings_win.destroy).pack(side=tk.LEFT, padx=2)
    
    def is_suspicious(self, proc):
        """Check if a process is suspicious."""
        try:
            # Check process name against suspicious list
            if any(suspicious.lower() in proc.info['name'].lower() 
                  for suspicious in self.config['suspicious_processes']):
                return True
                
            # Check process path
            try:
                exe = proc.exe().lower()
                if any(path in exe for path in self.config['suspicious_paths']):
                    return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        except Exception:
            pass
            
        return False
    
    def alert_suspicious_process(self, proc):
        """Show alert for suspicious process."""
        msg = f"Suspicious process detected!\n\n" \
              f"PID: {proc.info['pid']}\n" \
              f"Name: {proc.info['name']}\n" \
              f"Status: {proc.info['status']}"
        
        # Show in status bar
        self.root.after(0, lambda: self.status_var.set(f"ALERT: {msg}"))
        
        # Show popup (non-blocking)
        self.root.after(100, lambda: messagebox.showwarning("Suspicious Process Detected", msg))
    
    def monitor_processes(self):
        """Background thread to monitor processes."""
        while self.running:
            try:
                self.root.after(0, self.update_processes)
                time.sleep(self.update_interval)
            except Exception as e:
                print(f"Error in monitor thread: {e}")
                time.sleep(5)  # Prevent tight loop on error
    
    def on_closing(self):
        """Handle window close event."""
        self.running = False
        if hasattr(self, 'update_thread'):
            self.update_thread.join(timeout=2)
        if hasattr(self, 'threat_detector'):
            self.threat_detector.stop()
        self.root.destroy()
    
    def on_double_click(self, event):
        """Handle double-click on process."""
        self.show_process_details()
    
    def on_alert_double_click(self, event):
        """Handle double-click on alert."""
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        item = self.alerts_tree.item(selected[0])
        alert_index = len(self.alerts) - 1 - int(selected[0][1:])  # Convert tkinter item ID to index
        
        if 0 <= alert_index < len(self.alerts):
            alert = self.alerts[alert_index]
            self.show_alert_details(alert)
    
    def show_alert_details(self, alert):
        """Show detailed information about an alert."""
        details = f"""
        Alert Details:
        --------------
        Time: {alert.get('timestamp', 'N/A')}
        Type: {alert.get('type', 'N/A')}
        Severity: {alert.get('severity', 'N/A')}
        Message: {alert.get('message', 'N/A')}
        """
        
        if 'process' in alert:
            details += f"\nProcess Information:"
            for key, value in alert['process'].items():
                details += f"\n  {key}: {value}"
        
        if 'connection' in alert:
            details += f"\n\nConnection Information:"
            for key, value in alert['connection'].items():
                details += f"\n  {key}: {value}"
        
        # Show in a new window
        top = tk.Toplevel(self.root)
        top.title(f"Alert Details - {alert.get('type', 'Alert')}")
        
        text = tk.Text(top, wrap=tk.WORD, width=80, height=20)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, details.strip())
        text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(top)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(button_frame, text="Close", command=top.destroy).pack(side=tk.RIGHT)
        
        if 'process' in alert and 'pid' in alert['process']:
            ttk.Button(
                button_frame, 
                text="View Process", 
                command=lambda p=alert['process']['pid']: self.focus_process(p)
            ).pack(side=tk.LEFT)
    
    def focus_process(self, pid):
        """Focus on a specific process in the process list."""
        # Switch to processes tab
        self.notebook.select(0)
        
        # Find and select the process
        for item in self.tree.get_children():
            if self.tree.item(item, 'values')[0] == pid:
                self.tree.selection_set(item)
                self.tree.see(item)
                self.show_process_details()
                break

def setup_logging():
    """Configure logging for the application."""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join('logs', 'edr_gui.log')),
            logging.StreamHandler()
        ]
    )
    
    # Set log level for specific modules
    logging.getLogger('PIL').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)

def main():
    # Set up logging
    setup_logging()
    
    # Create and run the application
    root = tk.Tk()
    try:
        app = EDRGUI(root)
        root.mainloop()
    except Exception as e:
        logging.exception("Fatal error in EDR GUI")
        messagebox.showerror(
            "Fatal Error",
            f"An error occurred: {str(e)}\n\n"
            "Please check the logs for more details.\n\n"
            f"Log file: {os.path.abspath('logs/edr_gui.log')}"
        )
        raise

if __name__ == "__main__":
    main()
