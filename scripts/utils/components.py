import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable, Dict, List, Tuple
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta

class SeverityMeter(ttk.Frame):
    """A visual meter showing severity levels with counts"""
    def __init__(self, parent, max_value: int = 100, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.max_value = max_value
        self.severity_labels = [
            ("1 - Low", "#4CAF50"),
            ("2 - Medium", "#FFC107"),
            ("3 - High", "#FF9800"),
            ("4 - Critical", "#F44336"),
            ("5 - Emergency", "#9C27B0")
        ]
        self._create_widgets()
        
    def _create_widgets(self):
        """Create the meter components"""
        self.meter_canvas = tk.Canvas(self, height=30, bg='white')
        self.meter_canvas.pack(fill=tk.X, pady=5)
        
        # Create labels for each severity level
        label_frame = ttk.Frame(self)
        label_frame.pack(fill=tk.X)
        
        for i, (text, color) in enumerate(self.severity_labels):
            lbl = ttk.Label(
                label_frame,
                text=text,
                foreground=color,
                font=('Arial', 8, 'bold')
            )
            lbl.pack(side=tk.LEFT, padx=5)
            
            # Add count label that we'll update later
            setattr(self, f'count_{i+1}', ttk.Label(
                label_frame,
                text="0",
                font=('Arial', 8)
            ))
            getattr(self, f'count_{i+1}').pack(side=tk.LEFT, padx=5)
            
            # Add separator if not last item
            if i < len(self.severity_labels) - 1:
                ttk.Separator(label_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)
    
    def update_counts(self, counts: Dict[int, int]):
        """Update the meter with new counts"""
        total = sum(counts.values())
        if total == 0:
            return
        
        # Clear previous meter
        self.meter_canvas.delete("all")
        
        # Draw the meter bars
        x = 0
        width = self.meter_canvas.winfo_width()
        
        for i in range(1, 6):
            count = counts.get(i, 0)
            percent = count / total if total > 0 else 0
            bar_width = int(width * percent)
            
            if bar_width > 0:
                self.meter_canvas.create_rectangle(
                    x, 0, x + bar_width, 30,
                    fill=self.severity_labels[i-1][1],
                    outline=""
                )
                x += bar_width
        
        # Update count labels
        for i in range(1, 6):
            getattr(self, f'count_{i}').config(text=str(counts.get(i, 0)))

class TimeRangeSelector(ttk.Frame):
    """A component for selecting time ranges with presets and custom range"""
    def __init__(self, parent, change_callback: Optional[Callable] = None, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.change_callback = change_callback
        self.presets = {
            'Last 1 hour': timedelta(hours=1),
            'Last 24 hours': timedelta(days=1),
            'Last 7 days': timedelta(days=7),
            'Last 30 days': timedelta(days=30),
            'Custom Range': None
        }
        self._create_widgets()
    
    def _create_widgets(self):
        """Create the time range selector components"""
        # Preset dropdown
        ttk.Label(self, text="Time Range:").pack(side=tk.LEFT, padx=5)
        
        self.preset_var = tk.StringVar(value='Last 24 hours')
        self.preset_combo = ttk.Combobox(
            self,
            textvariable=self.preset_var,
            values=list(self.presets.keys()),
            state='readonly',
            width=15
        )
        self.preset_combo.pack(side=tk.LEFT, padx=5)
        self.preset_combo.bind('<<ComboboxSelected>>', self._handle_preset_change)
        
        # Custom date range controls (initially hidden)
        self.custom_frame = ttk.Frame(self)
        
        ttk.Label(self.custom_frame, text="From:").pack(side=tk.LEFT, padx=5)
        self.from_date = ttk.Entry(self.custom_frame, width=10)
        self.from_date.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.custom_frame, text="To:").pack(side=tk.LEFT, padx=5)
        self.to_date = ttk.Entry(self.custom_frame, width=10)
        self.to_date.pack(side=tk.LEFT, padx=5)
        
        # Calendar buttons would be implemented here in a real app
        # self.from_cal_btn = ttk.Button(...)
        # self.to_cal_btn = ttk.Button(...)
    
    def _handle_preset_change(self, event=None):
        """Handle changes to the preset selection"""
        preset = self.preset_var.get()
        
        # Show/hide custom range controls
        if preset == 'Custom Range':
            self.custom_frame.pack(side=tk.LEFT, padx=5)
        else:
            self.custom_frame.pack_forget()
        
        # Invoke callback if provided
        if self.change_callback:
            self.change_callback(self.get_time_range())
    
    def get_time_range(self) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Get the selected time range as start and end datetimes"""
        preset = self.preset_var.get()
        
        if preset == 'Custom Range':
            # Parse custom dates (implementation would validate inputs)
            try:
                from_dt = datetime.strptime(self.from_date.get(), '%Y-%m-%d')
                to_dt = datetime.strptime(self.to_date.get(), '%Y-%m-%d')
                return from_dt, to_dt
            except ValueError:
                return None, None
        else:
            # Calculate from preset
            delta = self.presets[preset]
            end = datetime.now()
            start = end - delta
            return start, end
    
    def set_time_range(self, start: datetime, end: datetime):
        """Set a custom time range"""
        self.preset_var.set('Custom Range')
        self.from_date.delete(0, tk.END)
        self.from_date.insert(0, start.strftime('%Y-%m-%d'))
        self.to_date.delete(0, tk.END)
        self.to_date.insert(0, end.strftime('%Y-%m-%d'))
        self._handle_preset_change()

class EventTypeChart(ttk.Frame):
    """A chart showing distribution of event types"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self._create_widgets()
    
    def _create_widgets(self):
        """Create the chart components"""
        self.fig = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial empty chart
        self.ax.set_title('Event Types Distribution')
        self.ax.set_ylabel('Count')
        self.fig.tight_layout()
    
    def update_data(self, event_types: List[Tuple[str, int]]):
        """Update the chart with new data"""
        self.ax.clear()
        
        if event_types:
            # Prepare data
            labels = [et[0] for et in event_types]
            counts = [et[1] for et in event_types]
            
            # Create bar chart
            bars = self.ax.bar(labels, counts, color='steelblue')
            
            # Add count labels on bars
            for bar in bars:
                height = bar.get_height()
                self.ax.text(
                    bar.get_x() + bar.get_width() / 2., height,
                    f'{height}',
                    ha='center', va='bottom'
                )
            
            # Rotate labels for better readability
            plt.setp(self.ax.get_xticklabels(), rotation=45, ha='right')
            
            self.ax.set_title('Event Types Distribution')
            self.ax.set_ylabel('Count')
            self.fig.tight_layout()
        
        self.canvas.draw()

class IPAddressInput(ttk.Frame):
    """A specialized input for IP addresses with validation"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self._create_widgets()
    
    def _create_widgets(self):
        """Create the IP address input components"""
        self.entry = ttk.Entry(self, width=15)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add validation
        self.entry.configure(validate='key')
        self.entry.configure(
            validatecommand=(
                self.register(self._validate_ip),
                '%P'
            )
        )
        
        # Status indicator
        self.status_label = ttk.Label(self, text="", width=2)
        self.status_label.pack(side=tk.LEFT, padx=5)
    
    def _validate_ip(self, value: str) -> bool:
        """Validate IP address input"""
        if not value:
            self.status_label.config(text="")
            return True
        
        parts = value.split('.')
        if len(parts) > 4:
            return False
        
        # Validate each part
        for part in parts:
            if not part:  # Allow empty during input
                continue
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        # Update status indicator
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            self.status_label.config(text="✓", foreground="green")
        else:
            self.status_label.config(text="", foreground="black")
        
        return True
    
    def get_ip(self) -> Optional[str]:
        """Get the validated IP address"""
        ip = self.entry.get()
        parts = ip.split('.')
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return ip
        return None
    
    def set_ip(self, ip: str):
        """Set the IP address"""
        self.entry.delete(0, tk.END)
        self.entry.insert(0, ip)

class PaginationControls(ttk.Frame):
    """Pagination controls for tables/lists"""
    def __init__(self, parent, change_callback: Callable, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.current_page = 1
        self.total_pages = 1
        self.change_callback = change_callback
        self._create_widgets()
    
    def _create_widgets(self):
        """Create pagination controls"""
        # First page button
        self.first_btn = ttk.Button(
            self,
            text="<<",
            command=lambda: self.set_page(1),
            width=3
        )
        self.first_btn.pack(side=tk.LEFT, padx=2)
        
        # Previous page button
        self.prev_btn = ttk.Button(
            self,
            text="<",
            command=lambda: self.set_page(self.current_page - 1),
            width=3
        )
        self.prev_btn.pack(side=tk.LEFT, padx=2)
        
        # Page info
        self.page_label = ttk.Label(self, text="Page 1 of 1")
        self.page_label.pack(side=tk.LEFT, padx=5)
        
        # Next page button
        self.next_btn = ttk.Button(
            self,
            text=">",
            command=lambda: self.set_page(self.current_page + 1),
            width=3
        )
        self.next_btn.pack(side=tk.LEFT, padx=2)
        
        # Last page button
        self.last_btn = ttk.Button(
            self,
            text=">>",
            command=lambda: self.set_page(self.total_pages),
            width=3
        )
        self.last_btn.pack(side=tk.LEFT, padx=2)
        
        # Page size selector
        ttk.Label(self, text="Items per page:").pack(side=tk.LEFT, padx=(10, 2))
        self.page_size_var = tk.IntVar(value=50)
        page_size_combo = ttk.Combobox(
            self,
            textvariable=self.page_size_var,
            values=[10, 25, 50, 100, 250],
            state='readonly',
            width=5
        )
        page_size_combo.pack(side=tk.LEFT, padx=2)
        page_size_combo.bind('<<ComboboxSelected>>', self._handle_page_size_change)
    
    def set_page(self, page: int):
        """Set the current page"""
        if 1 <= page <= self.total_pages and page != self.current_page:
            self.current_page = page
            self._update_controls()
            self.change_callback(page, self.page_size_var.get())
    
    def set_total_items(self, total_items: int):
        """Update controls based on total items"""
        page_size = self.page_size_var.get()
        self.total_pages = max(1, (total_items + page_size - 1) // page_size)
        self.current_page = min(self.current_page, self.total_pages)
        self._update_controls()
    
    def _update_controls(self):
        """Update the state of pagination controls"""
        self.page_label.config(text=f"Page {self.current_page} of {self.total_pages}")
        
        # Enable/disable navigation buttons
        self.first_btn.state(['!disabled' if self.current_page > 1 else 'disabled'])
        self.prev_btn.state(['!disabled' if self.current_page > 1 else 'disabled'])
        self.next_btn.state(['!disabled' if self.current_page < self.total_pages else 'disabled'])
        self.last_btn.state(['!disabled' if self.current_page < self.total_pages else 'disabled'])
    
    def _handle_page_size_change(self, event=None):
        """Handle changes to page size"""
        self.set_total_items(self.total_pages * self.page_size_var.get())
        self.set_page(1)  # Reset to first page when page size changes

class StatusBadge(ttk.Label):
    """A styled badge for displaying statuses"""
    STATUS_COLORS = {
        'New': '#2196F3',       # Blue
        'In Progress': '#FFC107', # Amber
        'Resolved': '#4CAF50',   # Green
        'Ignored': '#9E9E9E',    # Grey
        'Critical': '#F44336',   # Red
        'High': '#FF9800',       # Orange
    }
    
    def __init__(self, parent, status: str, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.status = status
        self._style_badge()
    
    def _style_badge(self):
        """Apply styling based on status"""
        color = self.STATUS_COLORS.get(self.status, '#9E9E9E')
        
        self.config(
            text=self.status,
            foreground='white',
            background=color,
            font=('Arial', 8, 'bold'),
            padding=3,
            borderwidth=1,
            relief='solid',
            anchor='center'
        )

class ToolTip:
    """Create a tooltip for a given widget"""
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.x = self.y = 0
        
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)
    
    def show_tip(self, event=None):
        """Display the tooltip"""
        if self.tip_window or not self.text:
            return
        
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#ffffe0",
            relief=tk.SOLID,
            borderwidth=1,
            font=('Arial', 8)
        )
        label.pack(ipadx=1)
    
    def hide_tip(self, event=None):
        """Hide the tooltip"""
        if self.tip_window:
            self.tip_window.destroy()
        self.tip_window = None

class CollapsiblePane(ttk.Frame):
    """A collapsible pane that can be toggled open/closed"""
    def __init__(self, parent, title: str, initially_open: bool = True, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.title = title
        self.is_open = initially_open
        self._create_widgets()
    
    def _create_widgets(self):
        """Create the collapsible pane components"""
        # Header frame with toggle button
        self.header = ttk.Frame(self)
        self.header.pack(fill=tk.X)
        
        self.toggle_btn = ttk.Button(
            self.header,
            text=f"▼ {self.title}" if self.is_open else f"► {self.title}",
            command=self.toggle,
            style='Toolbutton'
        )
        self.toggle_btn.pack(side=tk.LEFT)
        
        # Content frame (initially shown or hidden)
        self.content = ttk.Frame(self)
        if self.is_open:
            self.content.pack(fill=tk.BOTH, expand=True)
    
    def toggle(self):
        """Toggle the pane open/closed"""
        self.is_open = not self.is_open
        
        if self.is_open:
            self.content.pack(fill=tk.BOTH, expand=True)
            self.toggle_btn.config(text=f"▼ {self.title}")
        else:
            self.content.pack_forget()
            self.toggle_btn.config(text=f"► {self.title}")

class StyledNotebook(ttk.Notebook):
    """A styled notebook with close buttons on tabs"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self._create_style()
        self.bind("<ButtonPress-1>", self.on_close_press)
        self.bind("<ButtonRelease-1>", self.on_close_release)
    
    def _create_style(self):
        """Create custom style for the notebook"""
        style = ttk.Style()
        style.configure('StyledNotebook.Tab', padding=[10, 2])
        
        # Create images for close buttons
        self.close_img = tk.PhotoImage(width=16, height=16)
        self.close_active_img = tk.PhotoImage(width=16, height=16)
        
        # Draw X symbols (simplified for example)
        self._draw_x(self.close_img, 'black')
        self._draw_x(self.close_active_img, 'red')
    
    def _draw_x(self, img, color):
        """Draw an X symbol on the image"""
        # This is a simplified implementation
        for i in range(16):
            img.put(color, (i, i))
            img.put(color, (15 - i, i))
    
    def add_tab(self, child, text: str):
        """Add a tab with a close button"""
        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Add close button
        close_btn = ttk.Label(frame)
        close_btn.config(image=self.close_img)
        close_btn.bind("<Button-1>", lambda e: self.forget(child))
        close_btn.pack(side=tk.RIGHT, padx=2, pady=2)
        
        # Add label
        label = ttk.Label(frame, text=text)
        label.pack(side=tk.LEFT, padx=2)
        
        super().add(child, text="", sticky=tk.NSEW)
        self.tab(child, window=frame)
    
    def on_close_press(self, event):
        """Handle mouse press on close button"""
        element = self.identify(event.x, event.y)
        
        if "close" in element:
            self.state = ['pressed']
            self.tk.call(self, "itemconfigure", "current", 
                        image=self.close_active_img)
    
    def on_close_release(self, event):
        """Handle mouse release on close button"""
        element = self.identify(event.x, event.y)
        
        if "close" in element:
            self.tk.call(self, "itemconfigure", "current", 
                        image=self.close_img)
            self.forget(self.select())