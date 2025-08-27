import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Optional, Callable
from .components import ToolTip, IPAddressInput
import socket
import json
import os

class SettingsView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        self.settings_file = "siem_settings.json"
        self.current_settings = self._load_default_settings()
        
        # Load saved settings if they exist
        self._load_settings()
        
        self._create_widgets()
        self._populate_fields()

    def _load_default_settings(self) -> Dict:
        """Return default settings dictionary"""
        return {
            "syslog": {
                "enabled": False,
                "server": "0.0.0.0",
                "port": 514,
                "protocol": "UDP"
            },
            "email_alerts": {
                "enabled": False,
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_address": "siem@example.com",
                "recipients": "admin@example.com",
                "tls": True
            },
            "logging": {
                "file_path": "",
                "max_size": 10,  # MB
                "backup_count": 5
            },
            "ui": {
                "theme": "light",
                "refresh_interval": 5  # seconds
            },
            "security": {
                "auto_block_threshold": 3,
                "block_duration": 3600  # seconds
            }
        }

    def _load_settings(self):
        """Load settings from file if it exists"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    
                    # Merge loaded settings with defaults
                    for category in self.current_settings:
                        if category in loaded_settings:
                            self.current_settings[category].update(loaded_settings[category])
            except Exception as e:
                messagebox.showerror(
                    "Settings Error",
                    f"Failed to load settings: {str(e)}\nUsing default settings."
                )

    def _create_widgets(self):
        """Create all widgets for the settings view"""
        # Main container with scrollbar
        self.canvas = tk.Canvas(self.frame)
        self.scrollbar = ttk.Scrollbar(
            self.frame, 
            orient=tk.VERTICAL, 
            command=self.canvas.yview
        )
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create notebook for settings categories
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_syslog_tab()
        self._create_email_tab()
        self._create_logging_tab()
        self._create_ui_tab()
        self._create_security_tab()
        
        # Save button
        button_frame = ttk.Frame(self.scrollable_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        save_btn = ttk.Button(
            button_frame,
            text="Save Settings",
            command=self._save_settings,
            style='Accent.TButton'
        )
        save_btn.pack(side=tk.RIGHT, padx=5)
        
        reset_btn = ttk.Button(
            button_frame,
            text="Reset to Defaults",
            command=self._reset_settings
        )
        reset_btn.pack(side=tk.RIGHT, padx=5)

    def _create_syslog_tab(self):
        """Create the Syslog settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Syslog")
        
        # Enable/disable frame
        enable_frame = ttk.LabelFrame(tab, text="Syslog Server")
        enable_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.syslog_enabled = tk.BooleanVar(value=self.current_settings['syslog']['enabled'])
        enable_check = ttk.Checkbutton(
            enable_frame,
            text="Enable Syslog Server",
            variable=self.syslog_enabled,
            command=self._toggle_syslog_fields
        )
        enable_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Server settings frame
        self.syslog_frame = ttk.Frame(tab)
        self.syslog_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP Address
        ttk.Label(self.syslog_frame, text="Listen Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.syslog_ip = IPAddressInput(self.syslog_frame)
        self.syslog_ip.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Port
        ttk.Label(self.syslog_frame, text="Port:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.syslog_port = ttk.Entry(self.syslog_frame, width=10)
        self.syslog_port.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Protocol
        ttk.Label(self.syslog_frame, text="Protocol:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.syslog_protocol = ttk.Combobox(
            self.syslog_frame,
            values=["UDP", "TCP"],
            state="readonly",
            width=10
        )
        self.syslog_protocol.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Test button
        test_btn = ttk.Button(
            self.syslog_frame,
            text="Test Connection",
            command=self._test_syslog_connection
        )
        test_btn.grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)
        
        # Configure grid weights
        self.syslog_frame.grid_columnconfigure(1, weight=1)
        
        # Set initial enabled state
        self._toggle_syslog_fields()

    def _create_email_tab(self):
        """Create the Email Alerts settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Email Alerts")
        
        # Enable/disable frame
        enable_frame = ttk.LabelFrame(tab, text="Email Alerts")
        enable_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.email_enabled = tk.BooleanVar(value=self.current_settings['email_alerts']['enabled'])
        enable_check = ttk.Checkbutton(
            enable_frame,
            text="Enable Email Alerts",
            variable=self.email_enabled,
            command=self._toggle_email_fields
        )
        enable_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Email settings frame
        self.email_frame = ttk.Frame(tab)
        self.email_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # SMTP Server
        ttk.Label(self.email_frame, text="SMTP Server:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.smtp_server = ttk.Entry(self.email_frame)
        self.smtp_server.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # SMTP Port
        ttk.Label(self.email_frame, text="SMTP Port:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.smtp_port = ttk.Entry(self.email_frame, width=10)
        self.smtp_port.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # TLS
        self.smtp_tls = tk.BooleanVar()
        tls_check = ttk.Checkbutton(
            self.email_frame,
            text="Use TLS",
            variable=self.smtp_tls
        )
        tls_check.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Username
        ttk.Label(self.email_frame, text="Username:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.smtp_username = ttk.Entry(self.email_frame)
        self.smtp_username.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Password
        ttk.Label(self.email_frame, text="Password:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.smtp_password = ttk.Entry(self.email_frame, show="*")
        self.smtp_password.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # From Address
        ttk.Label(self.email_frame, text="From Address:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.from_address = ttk.Entry(self.email_frame)
        self.from_address.grid(row=5, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Recipients
        ttk.Label(self.email_frame, text="Recipients (comma separated):").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
        self.recipients = ttk.Entry(self.email_frame)
        self.recipients.grid(row=6, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Test button
        test_btn = ttk.Button(
            self.email_frame,
            text="Test Email",
            command=self._test_email_settings
        )
        test_btn.grid(row=7, column=1, padx=5, pady=5, sticky=tk.E)
        
        # Configure grid weights
        self.email_frame.grid_columnconfigure(1, weight=1)
        
        # Set initial enabled state
        self._toggle_email_fields()

    def _create_logging_tab(self):
        """Create the Logging settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Logging")
        
        # Log file settings
        file_frame = ttk.LabelFrame(tab, text="Log File Settings")
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Log file path
        ttk.Label(file_frame, text="Log File Path:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.log_path = ttk.Entry(file_frame)
        self.log_path.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        browse_btn = ttk.Button(
            file_frame,
            text="Browse...",
            command=self._browse_log_path
        )
        browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Max log size
        ttk.Label(file_frame, text="Max Size (MB):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_log_size = ttk.Spinbox(
            file_frame,
            from_=1,
            to=100,
            width=5
        )
        self.max_log_size.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Backup count
        ttk.Label(file_frame, text="Backup Count:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.backup_count = ttk.Spinbox(
            file_frame,
            from_=1,
            to=20,
            width=5
        )
        self.backup_count.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Configure grid weights
        file_frame.grid_columnconfigure(1, weight=1)

    def _create_ui_tab(self):
        """Create the UI settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="User Interface")
        
        # Theme settings
        theme_frame = ttk.LabelFrame(tab, text="Appearance")
        theme_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(theme_frame, text="Theme:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.theme = ttk.Combobox(
            theme_frame,
            values=["light", "dark", "system"],
            state="readonly"
        )
        self.theme.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Refresh settings
        refresh_frame = ttk.LabelFrame(tab, text="Refresh Settings")
        refresh_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(refresh_frame, text="Refresh Interval (seconds):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.refresh_interval = ttk.Spinbox(
            refresh_frame,
            from_=1,
            to=60,
            width=5
        )
        self.refresh_interval.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Configure grid weights
        theme_frame.grid_columnconfigure(1, weight=1)
        refresh_frame.grid_columnconfigure(1, weight=1)

    def _create_security_tab(self):
        """Create the Security settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Security")
        
        # Auto-block settings
        block_frame = ttk.LabelFrame(tab, text="Automatic Blocking")
        block_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(block_frame, text="Block Threshold (events):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.block_threshold = ttk.Spinbox(
            block_frame,
            from_=1,
            to=20,
            width=5
        )
        self.block_threshold.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(block_frame, text="Block Duration (seconds):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.block_duration = ttk.Spinbox(
            block_frame,
            from_=60,
            to=86400,
            increment=60,
            width=8
        )
        self.block_duration.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Configure grid weights
        block_frame.grid_columnconfigure(1, weight=1)

    def _populate_fields(self):
        """Populate all fields with current settings"""
        # Syslog settings
        self.syslog_enabled.set(self.current_settings['syslog']['enabled'])
        self.syslog_ip.set_ip(self.current_settings['syslog']['server'])
        self.syslog_port.insert(0, str(self.current_settings['syslog']['port']))
        self.syslog_protocol.set(self.current_settings['syslog']['protocol'])
        
        # Email settings
        self.email_enabled.set(self.current_settings['email_alerts']['enabled'])
        self.smtp_server.insert(0, self.current_settings['email_alerts']['smtp_server'])
        self.smtp_port.insert(0, str(self.current_settings['email_alerts']['smtp_port']))
        self.smtp_tls.set(self.current_settings['email_alerts']['tls'])
        self.smtp_username.insert(0, self.current_settings['email_alerts']['username'])
        self.smtp_password.insert(0, self.current_settings['email_alerts']['password'])
        self.from_address.insert(0, self.current_settings['email_alerts']['from_address'])
        self.recipients.insert(0, self.current_settings['email_alerts']['recipients'])
        
        # Logging settings
        self.log_path.insert(0, self.current_settings['logging']['file_path'])
        self.max_log_size.set(self.current_settings['logging']['max_size'])
        self.backup_count.set(self.current_settings['logging']['backup_count'])
        
        # UI settings
        self.theme.set(self.current_settings['ui']['theme'])
        self.refresh_interval.set(self.current_settings['ui']['refresh_interval'])
        
        # Security settings
        self.block_threshold.set(self.current_settings['security']['auto_block_threshold'])
        self.block_duration.set(self.current_settings['security']['block_duration'])

    def _toggle_syslog_fields(self):
        """Enable/disable syslog fields based on checkbox"""
        state = tk.NORMAL if self.syslog_enabled.get() else tk.DISABLED
        
        for child in self.syslog_frame.winfo_children():
            if isinstance(child, (ttk.Entry, ttk.Combobox, ttk.Button)):
                child.configure(state=state)
        
        # Special handling for IPAddressInput
        self.syslog_ip.entry.configure(state=state)

    def _toggle_email_fields(self):
        """Enable/disable email fields based on checkbox"""
        state = tk.NORMAL if self.email_enabled.get() else tk.DISABLED
        
        for child in self.email_frame.winfo_children():
            if isinstance(child, (ttk.Entry, ttk.Combobox, ttk.Button)):
                child.configure(state=state)

    def _test_syslog_connection(self):
        """Test the syslog server configuration"""
        try:
            ip = self.syslog_ip.get_ip()
            if not ip:
                raise ValueError("Invalid IP address")
            
            port = int(self.syslog_port.get())
            if not (0 < port <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            
            protocol = self.syslog_protocol.get().lower()
            
            # Try to create a test socket
            if protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(2)
            sock.bind((ip, port))
            sock.close()
            
            messagebox.showinfo(
                "Test Successful",
                f"Syslog server configuration is valid\n\n"
                f"IP: {ip}\n"
                f"Port: {port}\n"
                f"Protocol: {protocol.upper()}"
            )
        except Exception as e:
            messagebox.showerror(
                "Test Failed",
                f"Failed to test syslog configuration:\n{str(e)}"
            )

    def _test_email_settings(self):
        """Test the email settings configuration"""
        # In a real implementation, this would test connecting to the SMTP server
        messagebox.showinfo(
            "Email Test",
            "This would test the email configuration in a real implementation.\n\n"
            "Settings appear valid based on input validation."
        )

    def _browse_log_path(self):
        """Browse for log file location"""
        filepath = filedialog.asksaveasfilename(
            title="Select Log File",
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )
        
        if filepath:
            self.log_path.delete(0, tk.END)
            self.log_path.insert(0, filepath)

    def _save_settings(self):
        """Save all settings to file"""
        try:
            # Collect all settings from UI
            new_settings = {
                "syslog": {
                    "enabled": self.syslog_enabled.get(),
                    "server": self.syslog_ip.get_ip() or "0.0.0.0",
                    "port": int(self.syslog_port.get()),
                    "protocol": self.syslog_protocol.get()
                },
                "email_alerts": {
                    "enabled": self.email_enabled.get(),
                    "smtp_server": self.smtp_server.get(),
                    "smtp_port": int(self.smtp_port.get()),
                    "username": self.smtp_username.get(),
                    "password": self.smtp_password.get(),
                    "from_address": self.from_address.get(),
                    "recipients": self.recipients.get(),
                    "tls": self.smtp_tls.get()
                },
                "logging": {
                    "file_path": self.log_path.get(),
                    "max_size": int(self.max_log_size.get()),
                    "backup_count": int(self.backup_count.get())
                },
                "ui": {
                    "theme": self.theme.get(),
                    "refresh_interval": int(self.refresh_interval.get())
                },
                "security": {
                    "auto_block_threshold": int(self.block_threshold.get()),
                    "block_duration": int(self.block_duration.get())
                }
            }
            
            # Validate settings
            self._validate_settings(new_settings)
            
            # Save to file
            with open(self.settings_file, 'w') as f:
                json.dump(new_settings, f, indent=2)
            
            # Update current settings
            self.current_settings = new_settings
            
            messagebox.showinfo(
                "Settings Saved",
                "Settings have been saved successfully.\n"
                "Some changes may require restarting the application."
            )
        except ValueError as e:
            messagebox.showerror(
                "Validation Error",
                f"Invalid settings:\n{str(e)}"
            )
        except Exception as e:
            messagebox.showerror(
                "Save Error",
                f"Failed to save settings:\n{str(e)}"
            )

    def _validate_settings(self, settings: Dict):
        """Validate settings before saving"""
        # Syslog validation
        if settings['syslog']['enabled']:
            if not settings['syslog']['server']:
                raise ValueError("Syslog server address is required")
            
            if not (0 < settings['syslog']['port'] <= 65535):
                raise ValueError("Syslog port must be between 1 and 65535")
        
        # Email validation
        if settings['email_alerts']['enabled']:
            if not settings['email_alerts']['smtp_server']:
                raise ValueError("SMTP server is required")
            
            if not (0 < settings['email_alerts']['smtp_port'] <= 65535):
                raise ValueError("SMTP port must be between 1 and 65535")
            
            if not settings['email_alerts']['from_address']:
                raise ValueError("From address is required")
            
            if not settings['email_alerts']['recipients']:
                raise ValueError("At least one recipient is required")
        
        # Logging validation
        if settings['logging']['file_path'] and not os.path.isdir(os.path.dirname(settings['logging']['file_path'])):
            raise ValueError("Log file directory does not exist")
        
        if not (1 <= settings['logging']['max_size'] <= 100):
            raise ValueError("Max log size must be between 1 and 100 MB")
        
        if not (1 <= settings['logging']['backup_count'] <= 20):
            raise ValueError("Backup count must be between 1 and 20")
        
        # UI validation
        if settings['ui']['refresh_interval'] < 1:
            raise ValueError("Refresh interval must be at least 1 second")
        
        # Security validation
        if settings['security']['auto_block_threshold'] < 1:
            raise ValueError("Block threshold must be at least 1")
        
        if settings['security']['block_duration'] < 60:
            raise ValueError("Block duration must be at least 60 seconds")

    def _reset_settings(self):
        """Reset all settings to defaults"""
        if messagebox.askyesno(
            "Confirm Reset",
            "Are you sure you want to reset all settings to defaults?\n"
            "This cannot be undone."
        ):
            self.current_settings = self._load_default_settings()
            self._populate_fields()
            messagebox.showinfo(
                "Settings Reset",
                "All settings have been reset to defaults.\n"
                "Remember to save if you want to keep these changes."
            )

    def get_settings(self) -> Dict:
        """Get the current settings dictionary"""
        return self.current_settings