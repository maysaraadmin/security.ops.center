"""
DLP GUI Module

Provides a graphical interface for the Data Loss Prevention system.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import asyncio
import threading
import queue

# Local imports
from dlp.core import DataType, ClassificationResult, DLPScanner
from dlp.policies import PolicyEngine

logger = logging.getLogger('dlp.gui')

class DLPApp:
    """Main DLP GUI application."""
    
    def __init__(self, root):
        """Initialize the DLP GUI."""
        self.root = root
        self.root.title("Data Loss Prevention")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize DLP components
        self.scanner = DLPScanner()
        self.policy_engine = PolicyEngine()
        
        # Data storage
        self.scan_results = []
        self.scan_queue = queue.Queue()
        self.running = False
        
        # Setup logging
        self.setup_logging()
        
        # Setup UI
        self.setup_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_logging(self):
        """Configure logging for the DLP GUI."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_scan_tab()
        self.setup_policies_tab()
        self.setup_results_tab()
        self.setup_logs_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def setup_scan_tab(self):
        """Setup the scan configuration tab."""
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Scan")
        
        # Scan configuration frame
        config_frame = ttk.LabelFrame(self.scan_tab, text="Scan Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Target selection
        ttk.Label(config_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=50)
        self.target_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        browse_btn = ttk.Button(
            config_frame, 
            text="Browse...", 
            command=self.browse_target
        )
        browse_btn.grid(row=0, column=2, padx=5, pady=2)
        
        # Data types to scan for
        ttk.Label(config_frame, text="Data Types:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.data_types_frame = ttk.Frame(config_frame)
        self.data_types_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=2)
        
        self.data_type_vars = {}
        for i, dtype in enumerate(DataType):
            var = tk.BooleanVar(value=True)
            self.data_type_vars[dtype] = var
            cb = ttk.Checkbutton(
                self.data_types_frame,
                text=dtype.value.upper(),
                variable=var
            )
            cb.grid(row=i//4, column=i%4, sticky=tk.W, padx=5, pady=2)
        
        # Scan buttons
        btn_frame = ttk.Frame(self.scan_tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        scan_btn = ttk.Button(
            btn_frame,
            text="Start Scan",
            command=self.start_scan,
            style="Accent.TButton"
        )
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = ttk.Button(
            btn_frame,
            text="Stop Scan",
            command=self.stop_scan,
            state=tk.DISABLED
        )
        stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(self.scan_tab, text="Progress", padding=10)
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress.pack(fill=tk.X, pady=5)
        
        # Results preview
        self.results_text = tk.Text(
            progress_frame,
            height=15,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def setup_policies_tab(self):
        """Setup the policies configuration tab."""
        self.policies_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.policies_tab, text="Policies")
        
        # Policies list
        policies_frame = ttk.LabelFrame(self.policies_tab, text="DLP Policies", padding=10)
        policies_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add policy button
        btn_frame = ttk.Frame(policies_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        add_btn = ttk.Button(
            btn_frame,
            text="Add Policy",
            command=self.add_policy
        )
        add_btn.pack(side=tk.LEFT, padx=5)
        
        # Policies treeview
        columns = ("Name", "Data Type", "Action", "Status")
        self.policies_tree = ttk.Treeview(
            policies_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {"Name": 200, "Data Type": 150, "Action": 150, "Status": 100}
        for col in columns:
            self.policies_tree.heading(col, text=col)
            self.policies_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        vsb = ttk.Scrollbar(policies_frame, orient="vertical", command=self.policies_tree.yview)
        hsb = ttk.Scrollbar(policies_frame, orient="horizontal", command=self.policies_tree.xview)
        self.policies_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.policies_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_results_tab(self):
        """Setup the scan results tab."""
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Results")
        
        # Results treeview
        columns = ("Time", "Type", "Confidence", "Match", "Location", "Action")
        self.results_tree = ttk.Treeview(
            self.results_tab,
            columns=columns,
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Time": 150, 
            "Type": 100, 
            "Confidence": 100, 
            "Match": 250, 
            "Location": 200,
            "Action": 150
        }
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self.results_tab, orient="vertical", command=self.results_tree.yview)
        hsb = ttk.Scrollbar(self.results_tab, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Results actions
        actions_frame = ttk.Frame(self.results_tab)
        actions_frame.pack(fill=tk.X, pady=5)
        
        export_btn = ttk.Button(
            actions_frame,
            text="Export Results",
            command=self.export_results
        )
        export_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(
            actions_frame,
            text="Clear Results",
            command=self.clear_results
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
    
    def setup_logs_tab(self):
        """Setup the logs tab."""
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Logs text widget
        self.logs_text = tk.Text(
            self.logs_tab,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self.logs_tab, orient="vertical", command=self.logs_text.yview)
        hsb = ttk.Scrollbar(self.logs_tab, orient="horizontal", command=self.logs_text.xview)
        self.logs_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Log level filter
        log_frame = ttk.Frame(self.logs_tab)
        log_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(log_frame, text="Log Level:").pack(side=tk.LEFT, padx=5)
        
        self.log_level = tk.StringVar(value="INFO")
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        log_menu = ttk.OptionMenu(
            log_frame,
            self.log_level,
            "INFO",
            *log_levels,
            command=self.update_log_level
        )
        log_menu.pack(side=tk.LEFT, padx=5)
        
        # Log actions
        clear_btn = ttk.Button(
            log_frame,
            text="Clear Logs",
            command=self.clear_logs
        )
        clear_btn.pack(side=tk.RIGHT, padx=5)
        
        save_btn = ttk.Button(
            log_frame,
            text="Save Logs",
            command=self.save_logs
        )
        save_btn.pack(side=tk.RIGHT, padx=5)
    
    def browse_target(self):
        """Open a file dialog to select scan target."""
        target = filedialog.askdirectory()
        if target:
            self.target_var.set(target)
    
    def start_scan(self):
        """Start the DLP scan."""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please select a target directory to scan.")
            return
        
        # Get selected data types
        selected_types = [
            dtype for dtype, var in self.data_type_vars.items() 
            if var.get()
        ]
        
        if not selected_types:
            messagebox.showerror("Error", "Please select at least one data type to scan for.")
            return
        
        # Update UI
        self.update_status(f"Scanning {target}...")
        self.progress_var.set(0)
        self.update_results_text("Starting scan...\n")
        
        # Start scan in background thread
        self.running = True
        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, selected_types),
            daemon=True
        )
        scan_thread.start()
        
        # Start UI update loop
        self.update_ui()
    
    def run_scan(self, target: str, data_types: list):
        """Run the DLP scan in a background thread."""
        try:
            # TODO: Implement actual DLP scanning logic
            self.log("Starting DLP scan...")
            
            # Simulate scan progress
            for i in range(1, 101):
                if not self.running:
                    break
                    
                # Simulate finding results
                if i % 10 == 0:
                    result = ClassificationResult(
                        data_type=DataTypes.PII,
                        confidence=0.9,
                        match=f"Sample PII data {i}",
                        location=f"{target}/file_{i}.txt",
                        line_number=i
                    )
                    self.scan_queue.put(("result", result))
                
                # Update progress
                self.scan_queue.put(("progress", i))
                time.sleep(0.1)
                
            self.scan_queue.put(("status", "Scan completed" if self.running else "Scan stopped"))
            
        except Exception as e:
            self.scan_queue.put(("error", str(e)))
        finally:
            self.running = False
    
    def stop_scan(self):
        """Stop the current scan."""
        self.running = False
        self.update_status("Stopping scan...")
    
    def update_ui(self):
        """Update the UI with scan results and progress."""
        try:
            while True:
                try:
                    item_type, data = self.scan_queue.get_nowait()
                    
                    if item_type == "progress":
                        self.progress_var.set(data)
                    elif item_type == "result":
                        self.scan_results.append(data)
                        self.update_results_tree(data)
                    elif item_type == "status":
                        self.update_status(data)
                    elif item_type == "error":
                        self.log(f"Error: {data}", level=logging.ERROR)
                        self.update_status(f"Error: {data}")
                    
                except queue.Empty:
                    break
        except Exception as e:
            self.log(f"Error updating UI: {e}", level=logging.ERROR)
        
        # Schedule next update if scan is still running
        if self.running:
            self.root.after(100, self.update_ui)
    
    def update_results_text(self, text: str):
        """Update the results text widget."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def update_results_tree(self, result: ClassificationResult):
        """Update the results treeview with a new result."""
        self.results_tree.insert("", tk.END, values=(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result.data_type.value.upper(),
            f"{result.confidence.value * 100:.1f}%",
            result.match[:100] + ("..." if len(result.match) > 100 else ""),
            result.location,
            "Review"  # Default action
        ))
    
    def add_policy(self):
        """Add a new DLP policy."""
        # TODO: Implement policy creation dialog
        messagebox.showinfo("Add Policy", "Add policy functionality will be implemented here.")
    
    def export_results(self):
        """Export scan results to a file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                # TODO: Implement actual export logic
                with open(file_path, 'w') as f:
                    f.write("Time,Type,Confidence,Match,Location\n")
                    for result in self.scan_results:
                        f.write(
                            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},"
                            f"{result.data_type.value.upper()},"
                            f"{result.confidence.value * 100:.1f}%,"
                            f"\"{result.match}\","
                            f"{result.location}\n"
                        )
                
                self.log(f"Results exported to {file_path}")
                messagebox.showinfo("Export Complete", f"Results exported to {file_path}")
                
            except Exception as e:
                self.log(f"Error exporting results: {e}", level=logging.ERROR)
                messagebox.showerror("Export Error", f"Failed to export results: {e}")
    
    def clear_results(self):
        """Clear scan results."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all results?"):
            self.scan_results.clear()
            self.results_tree.delete(*self.results_tree.get_children())
            self.update_results_text("Results cleared.\n")
    
    def update_log_level(self, level: str):
        """Update the log level filter."""
        logging.getLogger().setLevel(level)
        self.log(f"Log level set to {level}")
    
    def clear_logs(self):
        """Clear the logs."""
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.config(state=tk.DISABLED)
    
    def save_logs(self):
        """Save logs to a file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                
                self.log(f"Logs saved to {file_path}")
                messagebox.showinfo("Save Complete", f"Logs saved to {file_path}")
                
            except Exception as e:
                self.log(f"Error saving logs: {e}", level=logging.ERROR)
                messagebox.showerror("Save Error", f"Failed to save logs: {e}")
    
    def log(self, message: str, level: int = logging.INFO):
        """Log a message to the log window and the console."""
        logger.log(level, message)
        
        # Update log text widget
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.insert(tk.END, f"[{logging.getLevelName(level)}] {message}\n")
        self.logs_text.see(tk.END)
        self.logs_text.config(state=tk.DISABLED)
    
    def update_status(self, message: str):
        """Update the status bar."""
        self.status_var.set(message)
        self.log(f"Status: {message}")
    
    def on_closing(self):
        """Handle window close event."""
        if self.running:
            if messagebox.askokcancel("Quit", "A scan is in progress. Are you sure you want to quit?"):
                self.running = False
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """Main entry point for the DLP GUI application."""
    root = tk.Tk()
    
    # Set application style
    style = ttk.Style()
    style.theme_use('clam')  # Use a modern theme
    
    # Configure colors
    style.configure("Accent.TButton", font=('Arial', 10, 'bold'))
    
    # Create and run the application
    app = DLPApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
