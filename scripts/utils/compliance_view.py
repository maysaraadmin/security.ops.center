"""
Compliance View

This module provides the GUI for the Compliance Module in the SIEM system.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import logging
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Tuple

# Import event handlers
from .compliance_view_handlers import (
    _on_compliance_check_complete,
    generate_report,
    _on_report_generated,
    _open_report,
    view_report,
    export_report,
    delete_report,
    refresh_reports,
    _sort_reports_by_date,
    save_settings,
    reset_settings,
    load_settings,
    generate_report_dialog,
    _on_generate_report_clicked
)

# Configure logging
logger = logging.getLogger('siem.compliance_view')

class ComplianceView:
    """
    A Tkinter-based view for the Compliance Module.
    
    This class provides a graphical user interface for managing compliance checks,
    viewing reports, and configuring settings.
    """
    """
    Compliance View for the SIEM application.
    Provides a user interface for managing compliance with various standards.
    """
    
    def __init__(self, parent, compliance_manager=None, config_file=None):
        """
        Initialize the ComplianceView.
        
        Args:
            parent: Parent widget
            compliance_manager: Instance of ComplianceManager
            config_file: Path to the configuration file
        """
        self.parent = parent
        self.compliance_manager = compliance_manager
        self.current_standard = None
        self.current_report = None
        
        # Set default config file if not provided
        if config_file is None:
            config_dir = os.path.join(os.path.expanduser("~"), ".siem", "config")
            os.makedirs(config_dir, exist_ok=True)
            self.config_file = os.path.join(config_dir, "compliance.ini")
        else:
            self.config_file = config_file
        
        # Create the main frame
        self.frame = ttk.Frame(parent, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(1, weight=1)
        
        # Create variables
        self.auto_check_var = tk.BooleanVar(value=True)
        self.auto_generate_report_var = tk.BooleanVar(value=True)
        self.report_format_var = tk.StringVar(value="pdf")
        self.report_dir_var = tk.StringVar(value=os.path.expanduser("~/compliance_reports"))
        
        # Email notification variables
        self.email_enabled_var = tk.BooleanVar(value=False)
        self.email_recipient_var = tk.StringVar()
        self.smtp_server_var = tk.StringVar()
        self.smtp_port_var = tk.StringVar(value="587")
        self.smtp_user_var = tk.StringVar()
        self.smtp_pass_var = tk.StringVar()
        self.smtp_use_tls_var = tk.BooleanVar(value=True)
        
        # Create the header
        self._create_header()
        
        # Create the notebook
        self._create_notebook()
        
        # Initialize UI components
        self._create_dashboard_tab()
        self._create_standards_tab()
        self._create_reports_tab()
        self._create_settings_tab()
        
        # Load settings
        self.load_settings()
        
        # Load initial data
        self._load_initial_data()
    
    # Bind event handlers to the class
    _on_compliance_check_complete = _on_compliance_check_complete
    generate_report = generate_report
    _on_report_generated = _on_report_generated
    _open_report = _open_report
    view_report = view_report
    export_report = export_report
    delete_report = delete_report
    refresh_reports = refresh_reports
    _sort_reports_by_date = _sort_reports_by_date
    save_settings = save_settings
    reset_settings = reset_settings
    load_settings = load_settings
    generate_report_dialog = generate_report_dialog
    _on_generate_report_clicked = _on_generate_report_clicked
    
    def _create_header(self):
        """Create the header with title and buttons."""
        header = ttk.Frame(self.frame)
        header.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Title
        title = ttk.Label(
            header,
            text="Compliance Module",
            font=('TkDefaultFont', 16, 'bold')
        )
        title.pack(side=tk.LEFT)
        
        # Buttons frame
        btn_frame = ttk.Frame(header)
        btn_frame.pack(side=tk.RIGHT)
        
        # Check button
        self.check_btn = ttk.Button(
            btn_frame,
            text="Check All",
            command=self.check_compliance,
            width=12
        )
        self.check_btn.pack(side=tk.LEFT, padx=2)
        
        # Refresh button
        refresh_btn = ttk.Button(
            btn_frame,
            text="Refresh",
            command=self.refresh_data,
            width=8
        )
        refresh_btn.pack(side=tk.LEFT, padx=2)
        
        # Report button
        self.report_btn = ttk.Button(
            btn_frame,
            text="Generate Report",
            command=self.generate_report_dialog,
            width=15
        )
        self.report_btn.pack(side=tk.LEFT, padx=2)
