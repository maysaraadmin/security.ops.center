import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from models.event import EventModel

class AnalyticsView:
    def __init__(self, parent, event_model: EventModel):
        self.event_model = event_model
        self.frame = ttk.Frame(parent)
        
        # Time range options
        self.time_ranges = {
            'Last 24 hours': timedelta(hours=24),
            'Last 7 days': timedelta(days=7),
            'Last 30 days': timedelta(days=30),
            'Last 90 days': timedelta(days=90)
        }
        
        self._create_widgets()
        self.update_analytics()

    def _create_widgets(self):
        """Create all widgets for the analytics view"""
        # Main container frame
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Controls frame
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Time range selector
        ttk.Label(controls_frame, text="Time Range:").pack(side=tk.LEFT, padx=5)
        self.time_range_var = tk.StringVar(value='Last 7 days')
        time_range_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.time_range_var,
            values=list(self.time_ranges.keys()),
            state='readonly'
        )
        time_range_combo.pack(side=tk.LEFT, padx=5)
        time_range_combo.bind('<<ComboboxSelected>>', lambda e: self.update_analytics())
        
        # Refresh button
        refresh_btn = ttk.Button(controls_frame, text="Refresh", command=self.update_analytics)
        refresh_btn.pack(side=tk.LEFT, padx=10)
        
        # Export button
        export_btn = ttk.Button(controls_frame, text="Export Data", command=self.export_data)
        export_btn.pack(side=tk.RIGHT)
        
        # Charts container
        charts_frame = ttk.Frame(main_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create charts
        self._create_time_series_chart(charts_frame)
        self._create_event_source_chart(charts_frame)
        self._create_severity_trend_chart(charts_frame)
        
    def _create_time_series_chart(self, parent):
        """Create the events over time line chart"""
        frame = ttk.LabelFrame(parent, text="Events Over Time")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.time_fig = plt.Figure(figsize=(10, 4), dpi=100)
        self.time_ax = self.time_fig.add_subplot(111)
        self.time_canvas = FigureCanvasTkAgg(self.time_fig, master=frame)
        self.time_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def _create_event_source_chart(self, parent):
        """Create the event sources bar chart"""
        frame = ttk.LabelFrame(parent, text="Event Sources")
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.sources_fig = plt.Figure(figsize=(6, 4), dpi=100)
        self.sources_ax = self.sources_fig.add_subplot(111)
        self.sources_canvas = FigureCanvasTkAgg(self.sources_fig, master=frame)
        self.sources_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def _create_severity_trend_chart(self, parent):
        """Create the severity trend area chart"""
        frame = ttk.LabelFrame(parent, text="Severity Trend")
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.severity_fig = plt.Figure(figsize=(6, 4), dpi=100)
        self.severity_ax = self.severity_fig.add_subplot(111)
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, master=frame)
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def update_analytics(self):
        """Update all analytics charts with current data"""
        time_range = self.time_range_var.get()
        time_delta = self.time_ranges[time_range]
        
        # Update time series chart
        self._update_time_series_chart(time_delta)
        
        # Update event sources chart
        self._update_event_source_chart(time_delta)
        
        # Update severity trend chart
        self._update_severity_trend_chart(time_delta)
        
    def _update_time_series_chart(self, time_delta: timedelta):
        """Update the events over time chart"""
        time_data = self.event_model.get_events_over_time(time_delta)
        
        self.time_ax.clear()
        
        if time_data:
            df = pd.DataFrame(time_data, columns=['Time', 'Count'])
            df['Time'] = pd.to_datetime(df['Time'])
            
            if time_delta <= timedelta(days=1):
                df.plot(x='Time', y='Count', ax=self.time_ax, style='.-', legend=False)
                self.time_ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M'))
            elif time_delta <= timedelta(days=7):
                df.plot(x='Time', y='Count', ax=self.time_ax, legend=False)
                self.time_ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%a %d'))
            else:
                df.plot(x='Time', y='Count', ax=self.time_ax, legend=False)
                self.time_ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%b %d'))
            
            self.time_ax.set_title(f'Events Over Time (Last {self._format_timedelta(time_delta)})')
            self.time_ax.set_ylabel('Event Count')
            self.time_ax.grid(True, alpha=0.3)
            self.time_fig.tight_layout()
        
        self.time_canvas.draw()
        
    def _update_event_source_chart(self, time_delta: timedelta):
        """Update the event sources distribution chart"""
        source_data = self.event_model.get_event_sources(time_delta)
        
        self.sources_ax.clear()
        
        if source_data:
            df = pd.DataFrame(source_data, columns=['Source', 'Count'])
            df = df.sort_values('Count', ascending=False).head(10)
            df.plot(kind='barh', x='Source', y='Count', ax=self.sources_ax, legend=False, color='steelblue')
            self.sources_ax.set_title(f'Top Event Sources (Last {self._format_timedelta(time_delta)})')
            self.sources_ax.set_xlabel('Count')
            self.sources_ax.grid(True, axis='x', alpha=0.3)
            self.sources_fig.tight_layout()
        
        self.sources_canvas.draw()
        
    def _update_severity_trend_chart(self, time_delta: timedelta):
        """Update the severity trend chart"""
        severity_data = self.event_model.get_severity_trends(time_delta)
        
        self.severity_ax.clear()
        
        if severity_data:
            # Convert the list of tuples to a DataFrame with proper column names
            df = pd.DataFrame(severity_data, columns=['time_interval', 'severity', 'count'])
            df['time_interval'] = pd.to_datetime(df['time_interval'])
            pivot_df = df.pivot(index='time_interval', columns='severity', values='count').fillna(0)
            
            colors = ['#4CAF50', '#FFC107', '#FF9800', '#F44336', '#9C27B0']
            pivot_df.plot.area(ax=self.severity_ax, legend=True, color=colors, alpha=0.7)
            
            self.severity_ax.set_title(f'Severity Trends (Last {self._format_timedelta(time_delta)})')
            self.severity_ax.set_ylabel('Event Count')
            
            if time_delta <= timedelta(days=1):
                self.severity_ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M'))
            elif time_delta <= timedelta(days=7):
                self.severity_ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%a %d'))
            else:
                self.severity_ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%b %d'))
            
            self.severity_ax.legend(title='Severity', bbox_to_anchor=(1.05, 1), loc='upper left')
            self.severity_fig.tight_layout()
        
        self.severity_canvas.draw()
        
    def export_data(self):
        """Export the current analytics data to CSV"""
        time_range = self.time_range_var.get()
        time_delta = self.time_ranges[time_range]
        
        time_data = self.event_model.get_events_over_time(time_delta)
        source_data = self.event_model.get_event_sources(time_delta)
        severity_data = self.event_model.get_severity_trends(time_delta)
        
        time_df = pd.DataFrame(time_data, columns=['Time', 'Count'])
        source_df = pd.DataFrame(source_data, columns=['Source', 'Count'])
        severity_df = pd.DataFrame(severity_data, columns=['Time', 'Severity', 'Count'])
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"siem_analytics_{timestamp}.csv"
        
        with open(filename, 'w') as f:
            f.write("Events Over Time\n")
            time_df.to_csv(f, index=False)
            
            f.write("\n\nEvent Sources\n")
            source_df.to_csv(f, index=False)
            
            f.write("\n\nSeverity Trends\n")
            severity_df.to_csv(f, index=False)
        
        print(f"Data exported to {filename}")
        
    def _format_timedelta(self, td: timedelta) -> str:
        """Format timedelta for display in chart titles"""
        if td.days >= 1:
            if td.days == 1:
                return "24 hours"
            elif td.days == 7:
                return "7 days"
            elif td.days == 30:
                return "30 days"
            elif td.days == 90:
                return "90 days"
            return f"{td.days} days"
        else:
            hours = int(td.total_seconds() / 3600)
            return f"{hours} hours"