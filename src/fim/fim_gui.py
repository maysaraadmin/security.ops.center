"""
FIM GUI Module

Provides a graphical interface for the File Integrity Monitoring system.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import logging
from datetime import datetime
from typing import Dict, List, Optional
import os
import queue
import threading

# Local imports
from fim import FileEvent, EventType, DirectoryMonitor, FileMonitor

logger = logging.getLogger('fim.gui')

class FIMApp:
    """Main FIM GUI application."""
    
    def __init__(self, root):
        """Initialize the FIM GUI."""
        self.root = root
        self.root.title("File Integrity Monitor")
        self.root.geometry("1000x700")
        
        # Initialize FIM components
        self.watchers: Dict[str, DirectoryMonitor | FileMonitor] = {}
        self.events: List[FileEvent] = []
        self.event_queue = queue.Queue()
        self.running = False
        
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
        self.setup_monitor_tab()
        self.setup_events_tab()
        
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
    
    def setup_monitor_tab(self):
        """Setup the monitoring configuration tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Monitor")
        
        # Left panel - Watchers
        watcher_frame = ttk.LabelFrame(tab, text="Watchers", padding=10)
        watcher_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Watcher list
        self.watcher_tree = ttk.Treeview(
            watcher_frame,
            columns=("Status", "Path", "Type"),
            show="headings",
            selectmode="browse"
        )
        self.watcher_tree.heading("Status", text="Status")
        self.watcher_tree.heading("Path", text="Path")
        self.watcher_tree.heading("Type", text="Type")
        self.watcher_tree.column("Status", width=80, anchor=tk.CENTER)
        self.watcher_tree.column("Path", width=300, anchor=tk.W)
        self.watcher_tree.column("Type", width=100, anchor=tk.W)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(watcher_frame, orient="vertical", command=self.watcher_tree.yview)
        hsb = ttk.Scrollbar(watcher_frame, orient="horizontal", command=self.watcher_tree.xview)
        self.watcher_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.watcher_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Right panel - Controls
        control_frame = ttk.Frame(tab, padding=10)
        control_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        
        # Add watcher group
        add_group = ttk.LabelFrame(control_frame, text="Add Watcher", padding=10)
        add_group.pack(fill=tk.X, pady=(0, 10))
        
        # Path selection
        ttk.Label(add_group, text="Path:").pack(anchor=tk.W, pady=2)
        path_frame = ttk.Frame(add_group)
        path_frame.pack(fill=tk.X, pady=2)
        
        self.watch_path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.watch_path_var, width=30)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(
            path_frame, 
            text="Browse...", 
            command=self.browse_watch_path
        ).pack(side=tk.LEFT, padx=5)
        
        # Watch type
        ttk.Label(add_group, text="Type:").pack(anchor=tk.W, pady=2)
        self.watch_type_var = tk.StringVar(value="directory")
        ttk.Radiobutton(add_group, text="Directory", variable=self.watch_type_var, value="directory").pack(anchor=tk.W)
        ttk.Radiobutton(add_group, text="File", variable=self.watch_type_var, value="file").pack(anchor=tk.W)
        
        # Recursive option
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(add_group, text="Watch subdirectories", variable=self.recursive_var).pack(anchor=tk.W, pady=5)
        
        # Add button
        ttk.Button(
            add_group,
            text="Add Watcher",
            command=self.add_watcher,
            style="Accent.TButton"
        ).pack(fill=tk.X, pady=(10, 0))
        
        # Watcher actions
        action_group = ttk.LabelFrame(control_frame, text="Actions", padding=10)
        action_group.pack(fill=tk.X, pady=5)
        
        self.start_btn = ttk.Button(
            action_group,
            text="Start Monitoring",
            command=self.start_monitoring,
            style="Accent.TButton"
        )
        self.start_btn.pack(fill=tk.X, pady=2)
        
        self.stop_btn = ttk.Button(
            action_group,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            state=tk.DISABLED
        )
        self.stop_btn.pack(fill=tk.X, pady=2)
        
        ttk.Button(
            action_group,
            text="Remove Selected",
            command=self.remove_watcher
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            action_group,
            text="Clear All",
            command=self.clear_watchers
        ).pack(fill=tk.X, pady=2)
    
    def setup_events_tab(self):
        """Setup the events tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Events")
        
        # Events filter
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        
        self.event_filter_var = tk.StringVar()
        self.event_filter = ttk.Combobox(
            filter_frame,
            textvariable=self.event_filter_var,
            values=["All"] + [e.name for e in EventType],
            state="readonly"
        )
        self.event_filter.current(0)
        self.event_filter.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.event_filter.bind("<<ComboboxSelected>>", self.filter_events)
        
        # Events list
        columns = ("Time", "Type", "Path", "Details")
        self.events_tree = ttk.Treeview(
            tab,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {"Time": 150, "Type": 100, "Path": 300, "Details": 200}
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=col_widths.get(col, 100), stretch=True)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.events_tree.yview)
        hsb = ttk.Scrollbar(tab, orient="horizontal", command=self.events_tree.xview)
        self.events_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Context menu
        self.event_menu = tk.Menu(tab, tearoff=0)
        self.event_menu.add_command(label="View Details", command=self.view_event_details)
        self.event_menu.add_separator()
        self.event_menu.add_command(label="Copy Path", command=self.copy_event_path)
        self.event_menu.add_command(label="Open in Explorer", command=self.open_in_explorer)
        self.events_tree.bind("<Button-3>", self.show_event_menu)
        
        # Actions frame
        actions_frame = ttk.Frame(tab)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            actions_frame,
            text="Export Events",
            command=self.export_events
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            actions_frame,
            text="Clear Events",
            command=self.clear_events
        ).pack(side=tk.LEFT, padx=5)
    
    def browse_watch_path(self):
        """Open a file dialog to select a path to watch."""
        if self.watch_type_var.get() == "directory":
            path = filedialog.askdirectory()
        else:
            path = filedialog.askopenfilename()
        
        if path:
            self.watch_path_var.set(path)
    
    def add_watcher(self):
        """Add a new path to watch."""
        path = self.watch_path_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Please select a path to watch.")
            return
        
        if not os.path.exists(path):
            messagebox.showerror("Error", f"Path does not exist: {path}")
            return
        
        # Check if already watching this path
        for item in self.watcher_tree.get_children():
            if self.watcher_tree.item(item, "values")[1] == path:
                messagebox.showwarning("Warning", f"Already watching path: {path}")
                return
        
        # Add to treeview
        item_id = self.watcher_tree.insert(
            "", 
            tk.END, 
            values=("Stopped", path, self.watch_type_var.get().capitalize())
        )
        
        # Create watcher
        try:
            if self.watch_type_var.get() == "directory":
                watcher = DirectoryMonitor(
                    path=path,
                    recursive=self.recursive_var.get(),
                    event_handler=self.handle_file_event
                )
            else:
                watcher = FileMonitor(
                    path=path,
                    event_handler=self.handle_file_event
                )
            
            self.watchers[item_id] = watcher
            self.log(f"Added watcher for {path}")
            self.watch_path_var.set("")  # Clear the entry
            
        except Exception as e:
            self.watcher_tree.delete(item_id)
            messagebox.showerror("Error", f"Failed to add watcher: {e}")
            self.log(f"Error adding watcher: {e}", logging.ERROR)
    
    def remove_watcher(self):
        """Remove the selected watcher."""
        selected = self.watcher_tree.selection()
        if not selected:
            return
        
        for item_id in selected:
            # Stop the watcher if running
            if item_id in self.watchers and hasattr(self.watchers[item_id], 'is_running') and self.watchers[item_id].is_running():
                self.watchers[item_id].stop()
            
            # Remove from watchers dict
            if item_id in self.watchers:
                del self.watchers[item_id]
            
            # Remove from treeview
            self.watcher_tree.delete(item_id)
            self.log(f"Removed watcher: {item_id}")
    
    def clear_watchers(self):
        """Remove all watchers."""
        if not messagebox.askyesno("Confirm", "Remove all watchers?"):
            return
        
        # Stop all watchers
        for watcher in self.watchers.values():
            if hasattr(watcher, 'is_running') and watcher.is_running():
                watcher.stop()
        
        # Clear the watchers dict and treeview
        self.watchers.clear()
        self.watcher_tree.delete(*self.watcher_tree.get_children())
        self.log("Cleared all watchers")
    
    def start_monitoring(self):
        """Start all watchers."""
        if not self.watchers:
            messagebox.showwarning("Warning", "No watchers configured")
            return
        
        try:
            for item_id, watcher in self.watchers.items():
                if hasattr(watcher, 'is_running') and not watcher.is_running():
                    watcher.start()
                    # Update status in treeview
                    values = list(self.watcher_tree.item(item_id, "values"))
                    values[0] = "Running"
                    self.watcher_tree.item(item_id, values=values)
            
            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.update_status("Monitoring started")
            self.log("Monitoring started")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {e}")
            self.log(f"Error starting monitoring: {e}", logging.ERROR)
    
    def stop_monitoring(self):
        """Stop all watchers."""
        try:
            for item_id, watcher in self.watchers.items():
                if hasattr(watcher, 'is_running') and watcher.is_running():
                    watcher.stop()
                    # Update status in treeview
                    values = list(self.watcher_tree.item(item_id, "values"))
                    values[0] = "Stopped"
                    self.watcher_tree.item(item_id, values=values)
            
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_status("Monitoring stopped")
            self.log("Monitoring stopped")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop monitoring: {e}")
            self.log(f"Error stopping monitoring: {e}", logging.ERROR)
    
    def handle_file_event(self, event: FileEvent):
        """Handle file system events from watchers."""
        # Add to event queue for thread-safe UI updates
        self.event_queue.put(event)
    
    def process_events(self):
        """Process file system events from the queue."""
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
    
    def add_event_to_ui(self, event: FileEvent):
        """Add an event to the events treeview."""
        self.events_tree.insert(
            "", 
            0,  # Insert at the top
            values=(
                datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
                event.event_type.name,
                event.src_path,
                f"{event.event_type.name} - {os.path.basename(event.src_path)}"
            ),
            tags=(event.event_type.name.lower(),)
        )
        
        # Auto-scroll to show new events
        self.events_tree.see("")
    
    def filter_events(self, event=None):
        """Filter events based on the selected filter."""
        filter_type = self.event_filter_var.get()
        
        # Clear current items
        for item in self.events_tree.get_children():
            self.events_tree.detach(item)
        
        # Add filtered items
        for event in reversed(self.events):
            if filter_type == "All" or event.event_type.name == filter_type:
                self.add_event_to_ui(event)
    
    def view_event_details(self):
        """Show details of the selected event."""
        selected = self.events_tree.selection()
        if not selected:
            return
        
        # Get the selected event
        item = selected[0]
        values = self.events_tree.item(item, "values")
        
        # Create a details window
        details_win = tk.Toplevel(self.root)
        details_win.title("Event Details")
        details_win.geometry("600x400")
        
        # Create text widget for details
        text = scrolledtext.ScrolledText(details_win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add event details
        text.insert(tk.END, f"Time: {values[0]}\n")
        text.insert(tk.END, f"Type: {values[1]}\n")
        text.insert(tk.END, f"Path: {values[2]}\n")
        text.insert(tk.END, f"Details: {values[3]}\n")
        
        # Disable editing
        text.config(state=tk.DISABLED)
        
        # Add close button
        btn_frame = ttk.Frame(details_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(
            btn_frame,
            text="Close",
            command=details_win.destroy
        ).pack(side=tk.RIGHT)
    
    def copy_event_path(self):
        """Copy the selected event's path to clipboard."""
        selected = self.events_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        path = self.events_tree.item(item, "values")[2]
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self.update_status(f"Copied to clipboard: {path}")
    
    def open_in_explorer(self):
        """Open the selected event's path in file explorer."""
        selected = self.events_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        path = self.events_tree.item(item, "values")[2]
        
        try:
            if os.path.isfile(path):
                # Open the file's directory and select the file
                os.startfile(os.path.dirname(path))
            elif os.path.isdir(path):
                # Open the directory
                os.startfile(path)
            else:
                messagebox.showerror("Error", "File or directory not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open in explorer: {e}")
    
    def export_events(self):
        """Export events to a file."""
        if not self.events:
            messagebox.showinfo("Info", "No events to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write("Timestamp,Event Type,Path,Details\n")
                
                # Write events
                for event in self.events:
                    f.write(
                        f'"{datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S")}",'
                        f'"{event.event_type.name}",'
                        f'"{event.src_path}",'
                        f'"{event.event_type.name} - {os.path.basename(event.src_path)}"\n'
                    )
            
            messagebox.showinfo("Success", f"Exported {len(self.events)} events to {file_path}")
            self.log(f"Exported events to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export events: {e}")
            self.log(f"Error exporting events: {e}", logging.ERROR)
    
    def clear_events(self):
        """Clear all events."""
        if not self.events:
            return
        
        if messagebox.askyesno("Confirm", "Clear all events?"):
            self.events.clear()
            self.events_tree.delete(*self.events_tree.get_children())
            self.log("Cleared all events")
    
    def show_event_menu(self, event):
        """Show the context menu for events."""
        item = self.events_tree.identify_row(event.y)
        if item:
            self.events_tree.selection_set(item)
            self.event_menu.post(event.x_root, event.y)
    
    def update_status(self, message: str):
        """Update the status bar."""
        self.status_var.set(message)
        self.log(message)
    
    def log(self, message: str, level=logging.INFO):
        """Log a message to the console."""
        logger.log(level, message)
    
    def on_closing(self):
        """Handle window close event."""
        if self.running:
            if messagebox.askokcancel("Quit", "Monitoring is active. Are you sure you want to quit?"):
                self.stop_monitoring()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """Main entry point for the FIM GUI application."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and run the application
    root = tk.Tk()
    app = FIMApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
