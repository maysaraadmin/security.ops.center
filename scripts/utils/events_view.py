import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from tkinter.simpledialog import Dialog
from models.event import EventModel

class EventsView:
    def __init__(self, parent, event_model: EventModel):
        self.event_model = event_model
        self.frame = ttk.Frame(parent)
        
        # Filter state
        self.current_filters = {
            'source': 'All',
            'severity': 'All',
            'time_range': 'Last 24 hours',
            'search_term': '',
            'status': 'All'
        }
        
        self._create_widgets()
        self.update_events_table()

    def _create_widgets(self):
        """Create all widgets for the events view"""
        # Main container frame
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Filter controls frame
        filter_frame = ttk.LabelFrame(main_frame, text="Filters")
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Source filter
        ttk.Label(filter_frame, text="Source:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.source_filter = ttk.Combobox(
            filter_frame, 
            values=['All', 'System', 'Firewall', 'IDS', 'Application', 'Network', 'Database'],
            state='readonly'
        )
        self.source_filter.set('All')
        self.source_filter.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.source_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Severity filter
        ttk.Label(filter_frame, text="Severity:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.severity_filter = ttk.Combobox(
            filter_frame,
            values=['All', '1 - Low', '2 - Medium', '3 - High', '4 - Critical', '5 - Emergency'],
            state='readonly'
        )
        self.severity_filter.set('All')
        self.severity_filter.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)
        self.severity_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Time range filter
        ttk.Label(filter_frame, text="Time Range:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.time_filter = ttk.Combobox(
            filter_frame,
            values=['Last hour', 'Last 24 hours', 'Last 7 days', 'Last 30 days', 'All'],
            state='readonly'
        )
        self.time_filter.set('Last 24 hours')
        self.time_filter.grid(row=0, column=5, padx=5, pady=5, sticky=tk.EW)
        self.time_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Status filter
        ttk.Label(filter_frame, text="Status:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.status_filter = ttk.Combobox(
            filter_frame,
            values=['All', 'New', 'In Progress', 'Resolved', 'Ignored'],
            state='readonly'
        )
        self.status_filter.set('All')
        self.status_filter.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.status_filter.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Search box
        ttk.Label(filter_frame, text="Search:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.search_entry = ttk.Entry(filter_frame)
        self.search_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.EW)
        self.search_entry.bind('<Return>', lambda e: self.apply_filters())
        
        # Action buttons
        button_frame = ttk.Frame(filter_frame)
        button_frame.grid(row=1, column=4, columnspan=2, padx=5, pady=5, sticky=tk.E)
        
        search_btn = ttk.Button(button_frame, text="Search", command=self.apply_filters)
        search_btn.pack(side=tk.LEFT, padx=2)
        
        clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_filters)
        clear_btn.pack(side=tk.LEFT, padx=2)
        
        export_btn = ttk.Button(button_frame, text="Export", command=self.export_events)
        export_btn.pack(side=tk.LEFT, padx=2)
        
        # Configure grid weights
        filter_frame.grid_columnconfigure(1, weight=1)
        filter_frame.grid_columnconfigure(3, weight=1)
        filter_frame.grid_columnconfigure(5, weight=1)
        
        # Events treeview
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.events_tree = ttk.Treeview(
            tree_frame,
            columns=('id', 'timestamp', 'source', 'event_type', 'severity', 'description', 'ip_address', 'status'),
            show='headings',
            selectmode='extended'
        )
        
        # Define columns
        columns = [
            ('id', 'ID', 50),
            ('timestamp', 'Timestamp', 150),
            ('source', 'Source', 100),
            ('event_type', 'Event Type', 120),
            ('severity', 'Severity', 80),
            ('description', 'Description', 300),
            ('ip_address', 'IP Address', 120),
            ('status', 'Status', 100)
        ]
        
        for col_id, heading, width in columns:
            self.events_tree.heading(col_id, text=heading)
            self.events_tree.column(col_id, width=width, anchor=tk.W if col_id in ['description'] else tk.CENTER)
        
        # Hide ID column by default
        self.events_tree.column('id', width=0, stretch=tk.NO)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for severity coloring
        self.events_tree.tag_configure('critical', foreground='red')
        self.events_tree.tag_configure('high', foreground='orange')
        self.events_tree.tag_configure('medium', foreground='darkorange')
        self.events_tree.tag_configure('low', foreground='green')
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Create action buttons
        actions = [
            ('View Details', self.view_event_details),
            ('Mark as Resolved', self.mark_resolved),
            ('Add to Watchlist', self.add_to_watchlist),
            ('Ignore Event', self.ignore_event),
            ('Refresh', self.update_events_table)
        ]
        
        for text, command in actions:
            btn = ttk.Button(action_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Context menu
        self.context_menu = tk.Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_event_details)
        self.context_menu.add_command(label="Mark as Resolved", command=self.mark_resolved)
        self.context_menu.add_command(label="Add to Watchlist", command=self.add_to_watchlist)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Event Data", command=self.copy_event_data)
        
        # Bind right-click event
        self.events_tree.bind("<Button-3>", self.show_context_menu)
        
        # Bind double-click to view details
        self.events_tree.bind("<Double-1>", lambda e: self.view_event_details())

    def apply_filters(self):
        """Apply the current filters to the events table"""
        self.current_filters = {
            'source': self.source_filter.get(),
            'severity': self.severity_filter.get(),
            'time_range': self.time_filter.get(),
            'search_term': self.search_entry.get(),
            'status': self.status_filter.get()
        }
        self.update_events_table()

    def clear_filters(self):
        """Reset all filters to default values"""
        self.source_filter.set('All')
        self.severity_filter.set('All')
        self.time_filter.set('Last 24 hours')
        self.status_filter.set('All')
        self.search_entry.delete(0, tk.END)
        self.apply_filters()

    def update_events_table(self):
        """Update the events table with current data and filters"""
        # Clear existing data
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        # Get filtered events
        events = self._get_filtered_events()
        
        # Add events to treeview with appropriate tags
        for event in events:
            severity = event[4]
            
            # Determine tag based on severity
            if severity >= 5:
                tags = ('critical',)
            elif severity >= 4:
                tags = ('critical',)
            elif severity >= 3:
                tags = ('high',)
            elif severity >= 2:
                tags = ('medium',)
            else:
                tags = ('low',)
            
            # Add status to tags for potential styling
            if event[7] == 'Resolved':
                tags += ('resolved',)
            elif event[7] == 'Ignored':
                tags += ('ignored',)
            
            self.events_tree.insert('', tk.END, values=event, tags=tags)

    def _get_filtered_events(self) -> List[Tuple]:
        """Retrieve events based on current filters"""
        # Build base query
        query = """
            SELECT id, timestamp, source, event_type, severity, 
                   description, ip_address, status 
            FROM events 
            WHERE 1=1
        """
        params = []
        
        # Apply source filter
        if self.current_filters['source'] != 'All':
            query += " AND source = ?"
            params.append(self.current_filters['source'])
        
        # Apply severity filter
        if self.current_filters['severity'] != 'All':
            severity_level = int(self.current_filters['severity'].split(' ')[0])
            query += " AND severity >= ?"
            params.append(severity_level)
        
        # Apply time range filter
        if self.current_filters['time_range'] != 'All':
            time_range = self.current_filters['time_range']
            if time_range == 'Last hour':
                query += " AND timestamp >= datetime('now', '-1 hour')"
            elif time_range == 'Last 24 hours':
                query += " AND timestamp >= datetime('now', '-1 day')"
            elif time_range == 'Last 7 days':
                query += " AND timestamp >= datetime('now', '-7 days')"
            elif time_range == 'Last 30 days':
                query += " AND timestamp >= datetime('now', '-30 days')"
        
        # Apply status filter
        if self.current_filters['status'] != 'All':
            query += " AND status = ?"
            params.append(self.current_filters['status'])
        
        # Apply search term
        if self.current_filters['search_term']:
            search_term = f"%{self.current_filters['search_term']}%"
            query += " AND (description LIKE ? OR event_type LIKE ? OR ip_address LIKE ?)"
            params.extend([search_term, search_term, search_term])
        
        # Add sorting
        query += " ORDER BY timestamp DESC LIMIT 1000"
        
        # Execute query
        return self.event_model.get_events_with_query(query, tuple(params))

    def view_event_details(self):
        """Show detailed view of selected event(s)"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one event to view")
            return
        
        # For multiple selection, show summary dialog
        if len(selected) > 1:
            self._show_multiple_event_details(selected)
            return
        
        # For single selection, show detailed dialog
        item = self.events_tree.item(selected[0])
        event_id = item['values'][0]
        
        # Get full event details from model
        event = self.event_model.get_event_by_id(event_id)
        if not event:
            messagebox.showerror("Error", "Event not found")
            return
        
        # Create detail dialog
        dialog = EventDetailDialog(self.frame, event)
        dialog.show()

    def _show_multiple_event_details(self, selected_items):
        """Show summary information for multiple selected events"""
        # Collect basic info about selected events
        event_info = []
        for item_id in selected_items:
            item = self.events_tree.item(item_id)
            event_info.append((
                item['values'][1],  # timestamp
                item['values'][2],  # source
                item['values'][3],  # event_type
                item['values'][4]   # severity
            ))
        
        # Create summary dialog
        dialog = tk.Toplevel(self.frame)
        dialog.title(f"Summary of {len(selected_items)} Events")
        dialog.geometry("600x400")
        
        # Create treeview to display summary
        tree = ttk.Treeview(dialog, columns=('timestamp', 'source', 'event_type', 'severity'), show='headings')
        tree.heading('timestamp', text='Timestamp')
        tree.heading('source', text='Source')
        tree.heading('event_type', text='Event Type')
        tree.heading('severity', text='Severity')
        
        for col in tree['columns']:
            tree.column(col, width=150, anchor=tk.CENTER)
        
        # Add events to treeview
        for event in event_info:
            tree.insert('', tk.END, values=event)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add close button
        close_btn = ttk.Button(dialog, text="Close", command=dialog.destroy)
        close_btn.pack(pady=5)

    def mark_resolved(self):
        """Mark selected events as resolved"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one event to mark as resolved")
            return
        
        # Confirm action
        if not messagebox.askyesno(
            "Confirm",
            f"Mark {len(selected)} selected event(s) as resolved?"
        ):
            return
        
        # Update each selected event
        for item_id in selected:
            event_id = self.events_tree.item(item_id)['values'][0]
            self.event_model.update_event_status(event_id, 'Resolved')
        
        messagebox.showinfo("Success", f"{len(selected)} event(s) marked as resolved")
        self.update_events_table()

    def ignore_event(self):
        """Mark selected events as ignored"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one event to ignore")
            return
        
        # Confirm action
        if not messagebox.askyesno(
            "Confirm",
            f"Ignore {len(selected)} selected event(s)?"
        ):
            return
        
        # Update each selected event
        for item_id in selected:
            event_id = self.events_tree.item(item_id)['values'][0]
            self.event_model.update_event_status(event_id, 'Ignored')
        
        messagebox.showinfo("Success", f"{len(selected)} event(s) ignored")
        self.update_events_table()

    def add_to_watchlist(self):
        """Add IP addresses from selected events to watchlist"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one event to add to watchlist")
            return
        
        # Collect unique IPs from selected events
        ips = set()
        for item_id in selected:
            ip = self.events_tree.item(item_id)['values'][6]
            if ip and ip != 'N/A':
                ips.add(ip)
        
        if not ips:
            messagebox.showinfo("Info", "No valid IP addresses found in selected events")
            return
        
        # In a real implementation, this would call a watchlist service
        messagebox.showinfo(
            "Watchlist Update",
            f"Added {len(ips)} IP address(es) to watchlist:\n\n" + "\n".join(ips)
        )

    def export_events(self):
        """Export filtered events to CSV"""
        events = self._get_filtered_events()
        if not events:
            messagebox.showwarning("Warning", "No events to export with current filters")
            return
        
        # Get save location
        file_path = tk.filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Save Events As"
        )
        
        if not file_path:
            return  # User cancelled
        
        # Prepare data for CSV
        headers = [
            "ID", "Timestamp", "Source", "Event Type", "Severity",
            "Description", "IP Address", "Status"
        ]
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                # Write headers
                f.write(",".join(headers) + "\n")
                
                # Write data
                for event in events:
                    # Escape commas in description
                    desc = event[5].replace('"', '""')
                    if ',' in desc:
                        desc = f'"{desc}"'
                    
                    line = (
                        f"{event[0]},{event[1]},{event[2]},{event[3]},"
                        f"{event[4]},{desc},{event[6]},{event[7]}\n"
                    )
                    f.write(line)
            
            messagebox.showinfo("Success", f"Exported {len(events)} events to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export events: {str(e)}")

    def copy_event_data(self):
        """Copy selected event data to clipboard"""
        selected = self.events_tree.selection()
        if not selected:
            return
        
        # Get first selected item
        item = self.events_tree.item(selected[0])
        values = item['values']
        
        # Format as key: value pairs
        text = "\n".join([
            f"Timestamp: {values[1]}",
            f"Source: {values[2]}",
            f"Event Type: {values[3]}",
            f"Severity: {values[4]}",
            f"Description: {values[5]}",
            f"IP Address: {values[6]}",
            f"Status: {values[7]}"
        ])
        
        # Copy to clipboard
        self.frame.clipboard_clear()
        self.frame.clipboard_append(text)

    def show_context_menu(self, event):
        """Show context menu for events"""
        item = self.events_tree.identify_row(event.y)
        if item:
            self.events_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

class EventDetailDialog:
    """Dialog for displaying detailed event information"""
    def __init__(self, parent, event: Dict):
        self.parent = parent
        self.event = event
        self.dialog = None
    
    def show(self):
        """Show the dialog"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title(f"Event Details - {self.event['event_type']}")
        self.dialog.geometry("600x500")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Details tab
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="Details")
        self._create_details_tab(details_frame)
        
        # Raw Data tab
        raw_frame = ttk.Frame(notebook)
        notebook.add(raw_frame, text="Raw Data")
        self._create_raw_data_tab(raw_frame)
        
        # Action buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        close_btn = ttk.Button(button_frame, text="Close", command=self.dialog.destroy)
        close_btn.pack(side=tk.RIGHT)
        
        # Add action buttons based on event status
        if self.event['status'] != 'Resolved':
            resolve_btn = ttk.Button(
                button_frame, 
                text="Mark as Resolved", 
                command=lambda: self._update_status('Resolved')
            )
            resolve_btn.pack(side=tk.LEFT, padx=2)
        
        if self.event['status'] != 'Ignored':
            ignore_btn = ttk.Button(
                button_frame, 
                text="Ignore Event", 
                command=lambda: self._update_status('Ignored')
            )
            ignore_btn.pack(side=tk.LEFT, padx=2)
        
        watchlist_btn = ttk.Button(
            button_frame, 
            text="Add to Watchlist", 
            command=self._add_to_watchlist
        )
        watchlist_btn.pack(side=tk.LEFT, padx=2)
    
    def _create_details_tab(self, parent):
        """Create the details tab content"""
        # Create scrollable frame
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create details widgets
        fields = [
            ('ID', self.event['id']),
            ('Timestamp', self.event['timestamp']),
            ('Source', self.event['source']),
            ('Event Type', self.event['event_type']),
            ('Severity', self._get_severity_label(self.event['severity'])),
            ('Status', self.event['status']),
            ('IP Address', self.event['ip_address']),
            ('Description', self.event['description'])
        ]
        
        for i, (label, value) in enumerate(fields):
            ttk.Label(scrollable_frame, text=label + ":", font=('Arial', 10, 'bold'))\
                .grid(row=i, column=0, padx=5, pady=2, sticky=tk.W)
            
            # Special handling for description (multi-line)
            if label == 'Description':
                text = tk.Text(
                    scrollable_frame,
                    wrap=tk.WORD,
                    width=60,
                    height=10,
                    font=('Arial', 9)
                )
                text.insert(tk.END, value)
                text.config(state=tk.DISABLED)
                text.grid(row=i, column=1, padx=5, pady=2, sticky=tk.W)
            else:
                ttk.Label(scrollable_frame, text=value)\
                    .grid(row=i, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Configure grid weights
        scrollable_frame.grid_columnconfigure(1, weight=1)
    
    def _create_raw_data_tab(self, parent):
        """Create the raw data tab content"""
        text = tk.Text(
            parent,
            wrap=tk.NONE,
            font=('Consolas', 10)  # Monospace font for raw data
        )
        
        # Insert formatted JSON of the event data
        import json
        raw_data = json.dumps(self.event, indent=2)
        text.insert(tk.END, raw_data)
        text.config(state=tk.DISABLED)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=text.yview)
        x_scroll = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid layout
        text.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
    
    def _get_severity_label(self, severity: int) -> str:
        """Get human-readable severity label"""
        labels = {
            1: "1 - Low",
            2: "2 - Medium",
            3: "3 - High",
            4: "4 - Critical",
            5: "5 - Emergency"
        }
        return labels.get(severity, str(severity))
    
    def _update_status(self, new_status: str):
        """Update the event status"""
        # This would call the event model in a real implementation
        messagebox.showinfo(
            "Status Updated",
            f"Event status changed to '{new_status}'"
        )
        self.dialog.destroy()
    
    def _add_to_watchlist(self):
        """Add event IP to watchlist"""
        ip = self.event['ip_address']
        if ip and ip != 'N/A':
            # In a real implementation, this would call a watchlist service
            messagebox.showinfo(
                "Watchlist Update",
                f"IP address {ip} added to watchlist"
            )
        else:
            messagebox.showwarning(
                "No IP Address",
                "This event doesn't have an associated IP address"
            )