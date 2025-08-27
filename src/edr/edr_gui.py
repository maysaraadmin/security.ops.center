"""
Enhanced EDR Agent GUI with real-time monitoring and visualization
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import json
import threading
import time
import os
import platform
import webbrowser
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from matplotlib.ticker import MaxNLocator
import numpy as np
from src.edr.agent.edr_agent import EDRAgent, EDREvent, EventSeverity, SystemMetrics

class EnhancedEDRGUI:
    def __init__(self, root):
        self.root = root
        self.setup_gui()
        
        # Initialize EDR Agent with default config
        self.agent = EDRAgent({
            'log_level': 'INFO',
            'log_file': 'logs/edr_agent.log',
            'max_history': 1000,
            'monitoring_interval': 2.0
        })
        
        # Register callbacks
        self.agent.register_callback('event_received', self.on_event_received)
        self.agent.register_callback('metrics_updated', self.on_metrics_updated)
        
        # Start with a clean state
        self.events = []
        self.filtered_events = []
        self.current_event = None
        self.metrics_data = []
        
        # Start the agent
        self.agent.start()
        
        # Start the update loop
        self.update_interval = 1000  # ms
        self.schedule_update()
    
    def setup_gui(self):
        """Set up the main GUI components."""
        self.root.title("Enhanced EDR Agent")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Create main container
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.grid(row=0, column=0, sticky="nsew")
        
        # Left panel - Event list and details
        left_panel = ttk.Frame(self.main_container, padding="5")
        self.main_container.add(left_panel, weight=40)
        
        # Right panel - Metrics and controls
        right_panel = ttk.Frame(self.main_container, padding="5")
        self.main_container.add(right_panel, weight=60)
        
        # Configure left panel
        self.setup_event_panel(left_panel)
        
        # Configure right panel
        self.setup_metrics_panel(right_panel)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        status_bar.grid(row=1, column=0, sticky="ew")
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_event_panel(self, parent):
        """Set up the event list and details panel."""
        # Event filter frame
        filter_frame = ttk.Frame(parent)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self.on_filter_changed)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Event list
        self.event_list = ttk.Treeview(
            parent,
            columns=('time', 'type', 'severity', 'source'),
            show='headings',
            selectmode='browse'
        )
        self.event_list.heading('time', text='Time', command=lambda: self.sort_column('time', False))
        self.event_list.heading('type', text='Type', command=lambda: self.sort_column('type', False))
        self.event_list.heading('severity', text='Severity', command=lambda: self.sort_column('severity', False))
        self.event_list.heading('source', text='Source', command=lambda: self.sort_column('source', False))
        
        # Set column widths
        self.event_list.column('time', width=150, anchor=tk.W)
        self.event_list.column('type', width=150, anchor=tk.W)
        self.event_list.column('severity', width=80, anchor=tk.W)
        self.event_list.column('source', width=150, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.event_list.yview)
        self.event_list.configure(yscrollcommand=scrollbar.set)
        
        # Pack event list and scrollbar
        self.event_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.event_list.bind('<<TreeviewSelect>>', self.on_event_selected)
        
        # Event details
        details_frame = ttk.LabelFrame(parent, text="Event Details", padding="5")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            state='disabled'
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_metrics_panel(self, parent):
        """Set up the metrics and controls panel."""
        # Notebook for different views
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # System metrics tab
        metrics_tab = ttk.Frame(self.notebook)
        self.notebook.add(metrics_tab, text='System Metrics')
        
        # Create figures and canvases for metrics
        self.figures = {}
        self.canvases = {}
        
        # CPU Usage
        fig_cpu = Figure(figsize=(8, 3), dpi=100)
        self.ax_cpu = fig_cpu.add_subplot(111)
        self.ax_cpu.set_title('CPU Usage (%)')
        self.ax_cpu.grid(True)
        self.figures['cpu'] = fig_cpu
        
        canvas_cpu = FigureCanvasTkAgg(fig_cpu, master=metrics_tab)
        canvas_cpu.draw()
        canvas_cpu.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.canvases['cpu'] = canvas_cpu
        
        # Memory Usage
        fig_mem = Figure(figsize=(8, 3), dpi=100)
        self.ax_mem = fig_mem.add_subplot(111)
        self.ax_mem.set_title('Memory Usage (%)')
        self.ax_mem.grid(True)
        self.figures['memory'] = fig_mem
        
        canvas_mem = FigureCanvasTkAgg(fig_mem, master=metrics_tab)
        canvas_mem.draw()
        canvas_mem.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.canvases['memory'] = canvas_mem
        
        # Controls frame
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=5)
        
        # Buttons
        ttk.Button(
            controls_frame, 
            text="Generate Test Event", 
            command=self.generate_test_event
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Agent Status",
            command=self.show_agent_status
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Export Events",
            command=self.export_events
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Exit",
            command=self.on_closing
        ).pack(side=tk.RIGHT, padx=5)
    
    def update_metrics_plots(self):
        """Update the metrics plots with latest data."""
        metrics = self.agent.get_metrics_history(60)  # Last 60 data points
        
        if not metrics:
            return
        
        # Prepare data
        timestamps = [datetime.fromtimestamp(m.timestamp) for m in metrics]
        cpu_data = [m.cpu_percent for m in metrics]
        mem_data = [m.memory_percent for m in metrics]
        
        # Update CPU plot
        self.ax_cpu.clear()
        self.ax_cpu.plot(timestamps, cpu_data, 'b-')
        self.ax_cpu.set_title('CPU Usage (%)')
        self.ax_cpu.grid(True)
        self.ax_cpu.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        self.figures['cpu'].autofmt_xdate()
        
        # Update Memory plot
        self.ax_mem.clear()
        self.ax_mem.plot(timestamps, mem_data, 'r-')
        self.ax_mem.set_title('Memory Usage (%)')
        self.ax_mem.grid(True)
        self.ax_mem.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        self.figures['memory'].autofmt_xdate()
        
        # Redraw canvases
        for canvas in self.canvases.values():
            canvas.draw()
    
    def on_event_received(self, event):
        """Handle new events from the agent."""
        # This runs in a separate thread, so we schedule the UI update
        self.root.after(0, self._add_event_to_ui, event)
    
    def _add_event_to_ui(self, event):
        """Add a new event to the UI (thread-safe)."""
        # Add to our local list
        self.events.append(event)
        
        # Apply current filter
        if self.matches_filter(event):
            self._add_to_event_list(event)
    
    def _add_to_event_list(self, event):
        """Add an event to the event list."""
        timestamp = event.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self.event_list.insert('', 'end', 
            values=(
                timestamp,
                event.event_type,
                event.severity.value,
                event.source
            ),
            tags=(event.severity.value.lower(),)
        )
        
        # Auto-scroll to the bottom
        self.event_list.yview_moveto(1.0)
    
    def on_metrics_updated(self, metrics):
        """Handle updated metrics from the agent."""
        # Just schedule a UI update, actual plotting happens in the main thread
        self.root.after(0, self.update_metrics_plots)
    
    def on_event_selected(self, event):
        """Handle event selection in the event list."""
        selection = self.event_list.selection()
        if not selection:
            return
            
        item = self.event_list.item(selection[0])
        event_id = item['values'][0]  # Use timestamp as a simple ID
        
        # Find the event in our list
        selected_event = next(
            (e for e in self.events 
             if e.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f').startswith(event_id)),
            None
        )
        
        if selected_event:
            self.show_event_details(selected_event)
    
    def show_event_details(self, event):
        """Show detailed information about the selected event."""
        self.current_event = event
        
        # Convert event to dict and format as JSON
        event_dict = event.to_dict()
        formatted_json = json.dumps(event_dict, indent=2)
        
        # Update the details text
        self.details_text.config(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, formatted_json)
        self.details_text.config(state='disabled')
    
    def on_filter_changed(self, *args):
        """Handle changes to the event filter."""
        filter_text = self.filter_var.get().lower()
        
        # Clear current view
        for item in self.event_list.get_children():
            self.event_list.delete(item)
        
        # Add events that match the filter
        for event in self.events:
            if self.matches_filter(event, filter_text):
                self._add_to_event_list(event)
    
    def matches_filter(self, event, filter_text=None):
        """Check if an event matches the current filter."""
        if filter_text is None:
            filter_text = self.filter_var.get().lower()
            
        if not filter_text:
            return True
            
        # Check if filter matches any field
        search_fields = [
            event.event_type.lower(),
            event.severity.value.lower(),
            event.source.lower(),
            json.dumps(event.data).lower()
        ]
        
        return any(filter_text in field for field in search_fields)
    
    def generate_test_event(self):
        """Generate a test event."""
        import random
        
        event_types = [
            "process_start", "process_stop", "network_connection",
            "file_access", "registry_change", "security_alert"
        ]
        
        severities = [s for s in EventSeverity]
        
        event = EDREvent(
            event_type=random.choice(event_types),
            data={
                "process_name": f"test_process_{random.randint(1, 1000)}",
                "pid": random.randint(1000, 9999),
                "user": "SYSTEM",
                "details": "This is a test event generated by the EDR agent."
            },
            severity=random.choice(severities),
            source=f"test-{platform.node()}",
            tags=["test"]
        )
        
        self.agent.submit_event(event)
    
    def show_agent_status(self):
        """Show the agent status dialog."""
        status = self.agent.get_status()
        
        # Format status for display
        status_text = ""
        for key, value in status.items():
            if isinstance(value, dict):
                status_text += f"{key}:\n"
                for k, v in value.items():
                    status_text += f"  {k}: {v}\n"
            else:
                status_text += f"{key}: {value}\n"
        
        messagebox.showinfo("Agent Status", status_text)
    
    def export_events(self):
        """Export events to a JSON file."""
        if not self.events:
            messagebox.showwarning("No Events", "No events to export.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Events"
        )
        
        if not filename:
            return
            
        try:
            with open(filename, 'w') as f:
                events_data = [e.to_dict() for e in self.events]
                json.dump(events_data, f, indent=2)
                
            messagebox.showinfo("Export Successful", f"Exported {len(events_data)} events to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Error exporting events: {e}")
    
    def sort_column(self, col, reverse):
        """Sort treeview contents when a column header is clicked."""
        # Get all items from the treeview
        items = [(self.event_list.set(item, col), item) for item in self.event_list.get_children('')]
        
        # Sort the items
        items.sort(reverse=reverse)
        
        # Reorder the items in the treeview
        for index, (val, item) in enumerate(items):
            self.event_list.move(item, '', index)
        
        # Reverse sort next time
        self.event_list.heading(col, command=lambda: self.sort_column(col, not reverse))
    
    def schedule_update(self):
        """Schedule the next update."""
        self.update_metrics_plots()
        self.root.after(self.update_interval, self.schedule_update)
    
    def on_closing(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Do you want to stop the EDR agent and quit?"):
            self.agent.stop()
            self.root.destroy()

def main():
    """Main entry point."""
    # Set up the root window
    root = tk.Tk()
    
    # Set the application icon and title
    root.title("Enhanced EDR Agent")
    
    try:
        # Create and run the application
        app = EnhancedEDRGUI(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        raise

if __name__ == "__main__":
    main()
