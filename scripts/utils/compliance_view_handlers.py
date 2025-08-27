"""
Compliance View - Event Handlers and Additional Functionality

This module contains the event handlers and additional functionality
for the Compliance View in the SIEM application.
"""

import os
import json
import threading
import webbrowser
from datetime import datetime
from tkinter import messagebox, filedialog
from typing import Dict, Any, Optional, List, Callable

# Configure logging
import logging
logger = logging.getLogger('siem.compliance_view')

def _on_compliance_check_complete(self, results: Optional[Dict], error: Optional[str] = None):
    """Handle completion of a compliance check.
    
    Args:
        results: Compliance check results, or None if an error occurred
        error: Error message if an error occurred, or None
    """
    try:
        if error:
            self._log_activity(f"Compliance check failed: {error}")
            messagebox.showerror("Compliance Check Failed", error)
            return
        
        if not results:
            self._log_activity("Compliance check completed with no results")
            messagebox.showinfo("Compliance Check", "Check completed with no results.")
            return
        
        # Update the UI with the results
        self._update_dashboard()
        
        # Update the selected standard if applicable
        if self.current_standard and 'standards' in results:
            std_result = results['standards'].get(self.current_standard)
            if std_result:
                self.detail_status.config(text=std_result.get('status', 'Unknown').title())
                self.detail_last_checked.config(text=std_result.get('last_checked', '-'))
        
        # Show success message
        self._log_activity("Compliance check completed successfully")
        
        # Generate report if auto-generate is enabled
        if self.auto_generate_report_var.get() and self.current_standard:
            self.generate_report()
            
    except Exception as e:
        error_msg = f"Error processing compliance check results: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)
    finally:
        # Re-enable buttons
        self.check_btn.config(state=tk.NORMAL)
        self.check_std_btn.config(state=tk.NORMAL)

def generate_report(self):
    """Generate a compliance report for the selected standard."""
    if not self.compliance_manager or not self.current_standard:
        messagebox.showwarning("Warning", "No standard selected")
        return
    
    report_format = self.report_format_var.get().lower()
    self._log_activity(f"Generating {report_format.upper()} report for {self.current_standard}...")
    
    try:
        # Disable buttons during report generation
        self.report_btn.config(state=tk.DISABLED)
        self.view_report_btn.config(state=tk.DISABLED)
        
        # Run report generation in a separate thread
        def run_report():
            try:
                report = self.compliance_manager.generate_report(
                    self.current_standard,
                    report_format
                )
                
                if not report or 'status' not in report or report['status'] != 'success':
                    error_msg = report.get('message', 'Unknown error') if report else 'No report data'
                    raise Exception(f"Failed to generate report: {error_msg}")
                
                # Update UI on the main thread
                self.frame.after(0, self._on_report_generated, report, None)
                
            except Exception as e:
                self.frame.after(0, self._on_report_generated, None, str(e))
        
        # Start the report generation in a separate thread
        threading.Thread(target=run_report, daemon=True).start()
        
    except Exception as e:
        error_msg = f"Error generating report: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)
        
        # Re-enable buttons
        self.report_btn.config(state=tk.NORMAL)
        self.view_report_btn.config(state=tk.NORMAL)

def _on_report_generated(self, report: Optional[Dict], error: Optional[str] = None):
    """Handle completion of report generation.
    
    Args:
        report: Generated report data, or None if an error occurred
        error: Error message if an error occurred, or None
    """
    try:
        if error:
            self._log_activity(f"Report generation failed: {error}")
            messagebox.showerror("Report Generation Failed", error)
            return
        
        if not report:
            self._log_activity("Report generation completed with no data")
            messagebox.showinfo("Report Generation", "Report generated with no data.")
            return
        
        # Show success message
        report_path = report.get('saved_path', 'unknown location')
        self._log_activity(f"Report generated successfully: {os.path.basename(report_path)}")
        
        # Ask if the user wants to open the report
        if messagebox.askyesno(
            "Report Generated", 
            f"Report generated successfully at:\n{report_path}\n\nWould you like to open it now?"
        ):
            self._open_report(report_path)
        
        # Refresh the reports list
        self.refresh_reports()
        
    except Exception as e:
        error_msg = f"Error processing generated report: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)
    finally:
        # Re-enable buttons
        self.report_btn.config(state=tk.NORMAL)
        self.view_report_btn.config(state=tk.NORMAL)

def _open_report(self, report_path: str):
    """Open the generated report using the default application.
    
    Args:
        report_path: Path to the report file
    """
    try:
        if not os.path.exists(report_path):
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        # Use the default application to open the file
        if os.name == 'nt':  # Windows
            os.startfile(report_path)
        else:  # macOS and Linux
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
            
    except Exception as e:
        error_msg = f"Error opening report: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def view_report(self):
    """View the selected report."""
    if not self.current_report:
        messagebox.showwarning("Warning", "No report selected")
        return
    
    try:
        report_path = os.path.join(
            self.report_dir_var.get(),
            self.current_report['name']
        )
        
        if not os.path.exists(report_path):
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        self._open_report(report_path)
        
    except Exception as e:
        error_msg = f"Error viewing report: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def export_report(self):
    """Export the selected report to a different location."""
    if not self.current_report:
        messagebox.showwarning("Warning", "No report selected")
        return
    
    try:
        # Get the source report path
        src_path = os.path.join(
            self.report_dir_var.get(),
            self.current_report['name']
        )
        
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Report file not found: {src_path}")
        
        # Ask for the destination path
        dest_path = filedialog.asksaveasfilename(
            title="Export Report As",
            defaultextension=os.path.splitext(src_path)[1],
            initialfile=os.path.basename(src_path),
            filetypes=[
                ("All Files", "*.*"),
                ("PDF Files", "*.pdf"),
                ("HTML Files", "*.html"),
                ("JSON Files", "*.json")
            ]
        )
        
        if not dest_path:
            return  # User cancelled
        
        # Copy the file to the new location
        import shutil
        shutil.copy2(src_path, dest_path)
        
        self._log_activity(f"Report exported to: {dest_path}")
        messagebox.showinfo("Export Successful", f"Report exported to:\n{dest_path}")
        
    except Exception as e:
        error_msg = f"Error exporting report: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def delete_report(self):
    """Delete the selected report."""
    if not self.current_report:
        messagebox.showwarning("Warning", "No report selected")
        return
    
    try:
        report_path = os.path.join(
            self.report_dir_var.get(),
            self.current_report['name']
        )
        
        if not os.path.exists(report_path):
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete this report?\n\n{self.current_report['name']}"
        ):
            return
        
        # Delete the file
        os.remove(report_path)
        
        # Clear the current report
        self.current_report = None
        
        # Update the UI
        self.refresh_reports()
        self.report_preview.config(state=tk.NORMAL)
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.config(state=tk.DISABLED)
        
        self._log_activity(f"Report deleted: {os.path.basename(report_path)}")
        messagebox.showinfo("Success", "Report deleted successfully.")
        
    except Exception as e:
        error_msg = f"Error deleting report: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def refresh_reports(self):
    """Refresh the list of available reports."""
    if not self.compliance_manager:
        return
    
    try:
        # Clear existing items
        for item in self.reports_tree.get_children():
            self.reports_tree.delete(item)
        
        # Get the reports directory
        reports_dir = self.report_dir_var.get()
        
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir, exist_ok=True)
            self._log_activity(f"Created reports directory: {reports_dir}")
        
        # List all report files in the directory
        report_files = [
            f for f in os.listdir(reports_dir)
            if os.path.isfile(os.path.join(reports_dir, f))
        ]
        
        # Add reports to the treeview
        for filename in report_files:
            # Parse report metadata from filename (format: standard_YYYYMMDD_HHMMSS.format)
            try:
                base_name = os.path.splitext(filename)[0]
                parts = base_name.split('_')
                
                if len(parts) >= 3:
                    standard = parts[0].upper()
                    date_str = f"{parts[1]} {parts[2].replace('-', ':')}"
                    
                    # Format the date for display
                    try:
                        dt = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
                        formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        formatted_date = date_str
                        
                    # Get file extension as format
                    file_format = os.path.splitext(filename)[1][1:].upper()
                    
                    # Add to treeview
                    self.reports_tree.insert('', 'end', values=(
                        filename,  # name
                        standard,  # standard
                        file_format,  # format
                        formatted_date,  # date
                        'Ready'  # status
                    ))
            
            except Exception as e:
                logger.warning(f"Error parsing report filename '{filename}': {str(e)}")
        
        # Sort by date (newest first)
        self.reports_tree.heading('date', command=lambda: self._sort_reports_by_date(False))
        self._sort_reports_by_date(True)
        
    except Exception as e:
        error_msg = f"Error refreshing reports: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def _sort_reports_by_date(self, reverse: bool):
    """Sort the reports treeview by date.
    
    Args:
        reverse: Whether to sort in reverse order (newest first)
    """
    # Get all items from the treeview
    items = [(self.reports_tree.set(item, 'date'), item) 
             for item in self.reports_tree.get_children('')]
    
    # Sort the items by date
    try:
        # Try to parse the dates for proper sorting
        items.sort(key=lambda x: datetime.strptime(x[0], "%Y-%m-%d %H:%M:%S"), reverse=reverse)
    except:
        # Fall back to string comparison if date parsing fails
        items.sort(reverse=reverse)
    
    # Rearrange items in sorted positions
    for index, (_, item) in enumerate(items):
        self.reports_tree.move(item, '', index)
    
    # Reverse sort next time
    self.reports_tree.heading('date', command=lambda: self._sort_reports_by_date(not reverse))

def save_settings(self):
    """Save the current settings to the configuration file."""
    try:
        # Create the config directory if it doesn't exist
        config_dir = os.path.dirname(self.config_file)
        os.makedirs(config_dir, exist_ok=True)
        
        # Prepare the settings
        settings = {
            'compliance': {
                'auto_checks': str(self.auto_check_var.get()),
                'auto_generate_report': str(self.auto_generate_report_var.get()),
                'default_report_format': self.report_format_var.get(),
                'report_dir': self.report_dir_var.get(),
                'email_notifications': str(self.email_enabled_var.get()),
                'email_recipient': self.email_recipient_var.get(),
                'smtp_server': self.smtp_server_var.get(),
                'smtp_port': self.smtp_port_var.get(),
                'smtp_user': self.smtp_user_var.get(),
                'smtp_use_tls': str(self.smtp_use_tls_var.get())
            }
        }
        
        # Write to the config file
        import configparser
        config = configparser.ConfigParser()
        
        # Read existing config if it exists
        if os.path.exists(self.config_file):
            config.read(self.config_file)
        
        # Update with new settings
        for section, options in settings.items():
            if section not in config:
                config[section] = {}
            for key, value in options.items():
                config[section][key] = value
        
        # Save to file
        with open(self.config_file, 'w') as f:
            config.write(f)
        
        self._log_activity("Settings saved successfully")
        messagebox.showinfo("Success", "Settings saved successfully.")
        
    except Exception as e:
        error_msg = f"Error saving settings: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def reset_settings(self):
    """Reset settings to default values."""
    if not messagebox.askyesno(
        "Confirm Reset",
        "Are you sure you want to reset all settings to their default values?"
    ):
        return
    
    try:
        # Reset to default values
        self.auto_check_var.set(True)
        self.auto_generate_report_var.set(True)
        self.report_format_var.set("pdf")
        self.report_dir_var.set(os.path.expanduser("~/compliance_reports"))
        
        # Email settings
        self.email_enabled_var.set(False)
        self.email_recipient_var.set("")
        self.smtp_server_var.set("")
        self.smtp_port_var.set("587")
        self.smtp_user_var.set("")
        self.smtp_use_tls_var.set(True)
        
        # Update UI
        self._toggle_email_fields()
        
        self._log_activity("Settings reset to default values")
        messagebox.showinfo("Success", "Settings have been reset to default values.")
        
    except Exception as e:
        error_msg = f"Error resetting settings: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def load_settings(self):
    """Load settings from the configuration file."""
    try:
        if not os.path.exists(self.config_file):
            self._log_activity("No settings file found, using default values")
            return
        
        import configparser
        config = configparser.ConfigParser()
        config.read(self.config_file)
        
        if 'compliance' in config:
            section = config['compliance']
            
            # General settings
            if 'auto_checks' in section:
                self.auto_check_var.set(section.getboolean('auto_checks', True))
            
            if 'auto_generate_report' in section:
                self.auto_generate_report_var.set(section.getboolean('auto_generate_report', True))
            
            if 'default_report_format' in section:
                self.report_format_var.set(section['default_report_format'])
            
            if 'report_dir' in section:
                self.report_dir_var.set(section['report_dir'])
            
            # Email settings
            if 'email_notifications' in section:
                self.email_enabled_var.set(section.getboolean('email_notifications', False))
            
            if 'email_recipient' in section:
                self.email_recipient_var.set(section['email_recipient'])
            
            if 'smtp_server' in section:
                self.smtp_server_var.set(section['smtp_server'])
            
            if 'smtp_port' in section:
                self.smtp_port_var.set(section['smtp_port'])
            
            if 'smtp_user' in section:
                self.smtp_user_var.set(section['smtp_user'])
            
            if 'smtp_use_tls' in section:
                self.smtp_use_tls_var.set(section.getboolean('smtp_use_tls', True))
            
            # Update UI
            self._toggle_email_fields()
            
            self._log_activity("Settings loaded successfully")
            
    except Exception as e:
        error_msg = f"Error loading settings: {str(e)}"
        logger.error(error_msg)
        self._log_activity(f"ERROR: {error_msg}")
        messagebox.showerror("Error", error_msg)

def generate_report_dialog(self):
    """Show the generate report dialog."""
    if not self.current_standard:
        messagebox.showwarning("Warning", "Please select a standard first")
        return
    
    # Create a dialog window
    dialog = tk.Toplevel(self.frame)
    dialog.title(f"Generate {self.current_standard} Report")
    dialog.transient(self.frame)
    dialog.grab_set()
    
    # Center the dialog
    dialog.geometry("400x250")
    dialog.resizable(False, False)
    
    # Add padding
    for i in range(4):
        dialog.grid_rowconfigure(i, weight=1)
    for i in range(2):
        dialog.grid_columnconfigure(i, weight=1)
    
    # Format selection
    ttk.Label(dialog, text="Report Format:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
    
    format_var = tk.StringVar(value=self.report_format_var.get())
    format_combo = ttk.Combobox(
        dialog,
        textvariable=format_var,
        values=["JSON", "HTML", "PDF"],
        state="readonly",
        width=10
    )
    format_combo.grid(row=0, column=1, padx=10, pady=10, sticky="w")
    
    # Include details option
    include_details = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        dialog,
        text="Include detailed findings",
        variable=include_details
    ).grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="w")
    
    # Auto-open option
    auto_open = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        dialog,
        text="Open report after generation",
        variable=auto_open
    ).grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")
    
    # Buttons
    btn_frame = ttk.Frame(dialog)
    btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
    
    ttk.Button(
        btn_frame,
        text="Generate",
        command=lambda: self._on_generate_report_clicked(
            dialog, format_var.get().lower(), 
            include_details.get(), auto_open.get()
        )
    ).pack(side=tk.LEFT, padx=5)
    
    ttk.Button(
        btn_frame,
        text="Cancel",
        command=dialog.destroy
    ).pack(side=tk.LEFT, padx=5)
    
    # Center the dialog on the screen
    dialog.update_idletasks()
    width = dialog.winfo_width()
    height = dialog.winfo_height()
    x = (dialog.winfo_screenwidth() // 2) - (width // 2)
    y = (dialog.winfo_screenheight() // 2) - (height // 2)
    dialog.geometry(f'{width}x{height}+{x}+{y}')
    
    # Set focus to the dialog
    dialog.focus_set()

def _on_generate_report_clicked(self, dialog, format: str, include_details: bool, auto_open: bool):
    """Handle the Generate button click in the report dialog."""
    dialog.destroy()
    
    # Save the selected format for next time
    self.report_format_var.set(format)
    
    # Generate the report
    self.generate_report()
    
    # Auto-open the report if requested
    if auto_open and self.current_report:
        report_path = os.path.join(
            self.report_dir_var.get(),
            self.current_report['name']
        )
        
        if os.path.exists(report_path):
            self._open_report(report_path)
