import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import threading
import time

class SysmonView:
    def __init__(self, parent, event_model):
        self.parent = parent
        self.event_model = event_model
        self.frame = ttk.Frame(parent)
        self._create_widgets()
        self.running = False
        
    def _create_widgets(self):
        """Create the Sysmon view widgets"""
        # Main container
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Sysmon controls frame
        controls_frame = ttk.LabelFrame(main_container, text="Sysmon Controls", padding=10)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons
        self.start_btn = ttk.Button(controls_frame, text="Start Sysmon", command=self.start_sysmon_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(controls_frame, text="Stop Sysmon", command=self.stop_sysmon_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Status: Not monitoring")
        status_label = ttk.Label(controls_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT, padx=20)
        
        # Sysmon events frame
        events_frame = ttk.LabelFrame(main_container, text="Sysmon Events", padding=10)
        events_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for events
        columns = ("timestamp", "event_id", "process", "user", "details")
        self.tree = ttk.Treeview(events_frame, columns=columns, show="headings")
        
        # Configure columns
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("event_id", text="Event ID")
        self.tree.heading("process", text="Process")
        self.tree.heading("user", text="User")
        self.tree.heading("details", text="Details")
        
        # Set column widths
        self.tree.column("timestamp", width=150)
        self.tree.column("event_id", width=80, anchor=tk.CENTER)
        self.tree.column("process", width=200)
        self.tree.column("user", width=150)
        self.tree.column("details", width=400)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(events_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(events_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        events_frame.grid_rowconfigure(0, weight=1)
        events_frame.grid_columnconfigure(0, weight=1)
        
        # Event details frame
        details_frame = ttk.LabelFrame(main_container, text="Event Details", padding=10)
        details_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=8)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind tree selection
        self.tree.bind("<<TreeviewSelect>>", self.on_event_select)
    
    def start_sysmon_monitoring(self):
        """Start monitoring Sysmon events"""
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Status: Monitoring...")
        
        # Clear previous events
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_sysmon_events, daemon=True)
        self.monitor_thread.start()
    
    def stop_sysmon_monitoring(self):
        """Stop monitoring Sysmon events"""
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Status: Monitoring stopped")
    
    def monitor_sysmon_events(self):
        """Monitor for new Sysmon events"""
        last_id = 0
        
        while self.running:
            try:
                # Get new events from the database
                events = self.event_model.get_events_by_source("Sysmon", limit=100)
                
                # Add new events to the treeview
                for event in events:
                    event_id = event[0]  # ID is the first element in the tuple
                    if event_id <= last_id:
                        continue
                        
                    # Extract relevant information from the event tuple
                    # Tuple order: (id, timestamp, source, event_type, severity, description, ip_address, status)
                    timestamp = event[1]
                    event_type = event[3]
                    description = event[5] or ""
                    
                    # Extract event ID from event_type (e.g., "Process Create (1)" -> "1")
                    event_id_str = ""
                    if "(" in event_type and ")" in event_type:
                        event_id_str = event_type.split("(")[-1].strip(")")
                    
                    # Extract process name from description
                    process = ""
                    if description:
                        for line in description.split('\n'):
                            if line.startswith('Process: '):
                                process = line.replace('Process: ', '')
                                break
                    
                    # Extract user from description
                    user = ""
                    if description:
                        for line in description.split('\n'):
                            if line.startswith('User: '):
                                user = line.replace('User: ', '')
                                break
                    
                    # Insert into treeview
                    self.tree.insert("", "end", values=(
                        timestamp, 
                        event_id_str,
                        process[:50] + '...' if len(process) > 50 else process,
                        user[:30] + '...' if len(user) > 30 else user,
                        description[:100] + '...' if len(description) > 100 else description
                    ))
                    
                    # Update last processed ID
                    last_id = max(last_id, event_id)
                
                # Auto-scroll to the bottom
                if self.tree.get_children():
                    self.tree.see(self.tree.get_children()[-1])
                
            except Exception as e:
                print(f"Error monitoring Sysmon events: {e}")
                import traceback
                traceback.print_exc()
            
            # Poll every second
            time.sleep(1)
    
    def on_event_select(self, event):
        """Handle event selection"""
        selected = self.tree.selection()
        if not selected:
            return
            
        # Get the selected item's values
        item = self.tree.item(selected[0])
        details = item['values'][4]  # Get the full details
        
        # Update the details text area
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.config(state=tk.DISABLED)
