import os
import sys
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont, scrolledtext
from pathlib import Path

# Import our custom logging configuration
from src.utils.logging_config import setup_logging, get_logger

# Set up logging first thing
setup_logging(log_level='DEBUG', detailed=True)

# Initialize the logger
logger = get_logger('siem.main')
logger.info("SIEM Application Starting")
from typing import Optional, Dict, Any, List, Callable, TYPE_CHECKING, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
import time
import json
import queue
import sqlite3
from datetime import datetime
import platform
import signal
import traceback
import importlib.util
from pathlib import Path

# Import application services
from services.data_collector import DataCollector
from services.dashboard_service import DashboardService, SystemMetricsWidget, SecurityAlertsWidget
from services.edr_service import EDRService
from views.edr_dashboard import EDRDashboard

# Import application modules
from src.models.database import Database
from src.models.event import EventModel
from src.utils.metrics import MetricsCollector
from src.models.db_pool import get_db_pool, close_db_pool

# Type checking imports
if TYPE_CHECKING:
    from typing import (TypeVar, Generic, Type, Union, Iterable, Iterator, 
                       Generator, AsyncGenerator, Awaitable, AsyncIterable, 
                       AsyncIterator, overload, cast, NoReturn, ClassVar, 
                       Protocol, runtime_checkable, TypedDict, Literal, AnyStr, 
                       IO, BinaryIO, TextIO, Match, Pattern, NamedTuple, 
                       DefaultDict, OrderedDict, Counter, ChainMap, Coroutine, 
                       AsyncContextManager, ContextManager)
    import tkinter as tk
    from tkinter import ttk

# Add project root to Python path first
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure basic logging first - minimal configuration for startup
log_dir = os.path.join(project_root, 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'siem.log')

# Minimal logging configuration for startup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Only console for now
)

logger = logging.getLogger('siem.main')

class SIEMSystem:
    def _setup_exception_handling(self):
        """Set up global exception handling for the application."""
        def handle_exception(exc_type, exc_value, exc_traceback):
            # Don't handle keyboard interrupts here
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            # Log the exception
            if hasattr(self, 'logger'):
                self.logger.critical("Unhandled exception", 
                                   exc_info=(exc_type, exc_value, exc_traceback))
            else:
                # Fallback to basic logging if logger isn't available
                import traceback as tb
                print(f"Unhandled exception: {exc_value}", file=sys.stderr)
                tb.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr)
            
            # Show error to user in a message box if we have a root window
            if hasattr(self, 'root') and self.root and hasattr(self.root, 'winfo_exists') and self.root.winfo_exists():
                try:
                    error_msg = f"An unexpected error occurred: {str(exc_value)}"
                    if len(error_msg) > 200:  # Limit message length
                        error_msg = error_msg[:200] + "..."
                    # Import messagebox here to avoid circular imports
                    from tkinter import messagebox
                    # Use after to ensure this runs in the main thread
                    self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", msg))
                except Exception as e:
                    # If we can't show the error dialog, log it
                    if hasattr(self, 'logger'):
                        self.logger.error("Failed to show error dialog", exc_info=True)
        
        # Set the global exception handler
        sys.excepthook = handle_exception

    def __init__(self, root: Optional[tk.Tk] = None):
        """Initialize the SIEM system with optimized loading."""
        try:
            # Initialize logger first
            self.logger = logging.getLogger('siem.siem.main')
            self.logger.info("Initializing SIEM system...")
            
            # Initialize root window with minimal configuration
            self.root = root or tk.Tk()
            self.root.title("SIEM System")
            self.root.geometry("1200x800")
            
            # Configure grid layout for the root window
            self.root.grid_rowconfigure(0, weight=1)
            self.root.grid_columnconfigure(0, weight=1)
            
            # Initialize core components to None (lazy loading)
            self._initialized = False
            self.db = None
            self.metrics = None
            self.event_model = None
            self.data_collector = None
            self.dashboard_service = None
            
            # UI state
            self.views = {}
            self.current_view = None
            self._cleanup_started = False
            
            # Create the main container for all views
            self.view_container = ttk.Frame(self.root)
            self.view_container.grid(row=0, column=0, sticky='nsew')
            
            # Thread management
            self._stop_event = threading.Event()
            self._threads = []
            
            # Use a single thread for UI updates and more for background tasks
            self._executor = ThreadPoolExecutor(
                max_workers=4,
                thread_name_prefix='SIEMWorker'
            )
            
            # Set up exception handling before any operations
            self._setup_exception_handling()
            
            # Show loading screen
            self._show_loading_screen()
            
            # Start background initialization
            self._initialize_in_background()
            
            self.logger.info("SIEM system initialization started")
            
        except Exception as e:
            self.logger.critical("Failed to initialize SIEM system", exc_info=True)
            if hasattr(self, 'root') and self.root:
                messagebox.showerror(
                    "Initialization Error",
                    f"Failed to initialize SIEM system: {str(e)}\n\nCheck logs for details."
                )
            raise
        
    def _defer_initialization(self):
        """Defer non-critical initialization to after UI is shown."""
        try:
            # Create basic UI first
            self._create_basic_ui()
            
            def safe_initialize():
                try:
                    with ThreadPoolExecutor(max_workers=4, thread_name_prefix='SIEMInit') as executor:
                        # Submit independent tasks to run in parallel
                        db_future = executor.submit(self._init_database)
                        metrics_future = executor.submit(self._init_metrics)
                        
                        # Wait for critical services
                        db_future.result()
                        metrics_future.result()
                        
                        # Now initialize UI and background services
                        self.root.after(0, self._initialize_background_services)
                        
                except Exception as e:
                    logger.error(f"Background initialization failed: {e}", exc_info=True)
                    if hasattr(self, 'loading_label') and self.loading_label.winfo_exists():
                        # Capture the error message in a default argument
                        error_text = f"Initialization Error: {str(e)[:100]}..."
                        self.root.after(0, 
                            lambda text=error_text, label=self.loading_label: 
                                label.config(text=text) if label.winfo_exists() else None)
                    if hasattr(self, 'progress') and self.progress.winfo_exists():
                        self.root.after(0, self.progress.stop)
            
            # Start background initialization in a separate thread
            threading.Thread(target=safe_initialize, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Failed to start deferred initialization: {e}", exc_info=True)
            raise
        
    def _show_loading_screen(self):
        """Display loading screen while initializing."""
        try:
            # Clear existing widgets
            for widget in self.root.winfo_children():
                widget.destroy()
            
            # Configure root window to use grid
            self.root.grid_rowconfigure(0, weight=1)
            self.root.grid_columnconfigure(0, weight=1)
            
            self.root.update_idletasks()
            self.root.update()
            
        except Exception as e:
            self.logger.error(f"Error showing loading screen: {e}", exc_info=True)
            raise
    
    def _update_status(self, message: str):
        """Update the status label on the loading screen.
        
        This method is thread-safe and can be called from any thread.
        """
        if not hasattr(self, 'status_label'):
            return
            
        def update_label(msg):
            try:
                if not hasattr(self, 'root') or not self.root or not self.root.winfo_exists():
                    return
                    
                if (hasattr(self, 'status_label') and 
                    hasattr(self.status_label, 'winfo_exists') and 
                    self.status_label.winfo_exists()):
                    self.status_label.config(text=msg)
                    self.root.update_idletasks()
            except (tk.TclError, RuntimeError, AttributeError) as e:
                self.logger.debug(f"Error updating status: {e}")
        
        # Use after to schedule the update in the main thread
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'after'):
            try:
                self.root.after(0, lambda: update_label(message))
            except Exception as e:
                self.logger.debug(f"Error scheduling status update: {e}")
        else:
            self.logger.warning("Cannot update status: root window not available")
    
    def _initialize_in_background(self):
        """Initialize components in parallel where possible for faster startup."""
        def update_status(message):
            if hasattr(self, 'loading_label') and hasattr(self.loading_label, 'winfo_exists') and self.loading_label.winfo_exists():
                self.loading_label.config(text=message)
                self.root.update_idletasks()
        
        def init_task():
            try:
                self.logger.info("Starting background initialization...")
                
                # Phase 1: Initialize database and metrics in parallel
                self.root.after(0, lambda: update_status("Initializing database..."))
                db_future = self._executor.submit(self._init_database)
                metrics_future = self._executor.submit(self._init_metrics)
                
                # Wait for database to be ready before proceeding
                db = db_future.result()
                metrics = metrics_future.result()
                
                # Phase 2: Initialize event model after database is ready
                self.root.after(0, lambda: update_status("Initializing event model..."))
                self._init_event_model()
                
                # Phase 3: Initialize background services in parallel
                self.root.after(0, lambda: update_status("Starting background services..."))
                collector_future = self._executor.submit(self._init_data_collector)
                dashboard_future = self._executor.submit(self._initialize_dashboard_service)
                
                # Wait for background services to start
                collector_future.result()
                dashboard_future.result()
                
                # Initialize EDR service if available
                if hasattr(self, '_init_edr_service'):
                    edr_future = self._executor.submit(self._init_edr_service, db)
                    edr_future.result()
                
                # Phase 4: Initialize UI
                self.root.after(0, lambda: update_status("Preparing user interface..."))
                self.root.after(0, self._initialize_ui_components)
                
            except Exception as e:
                self.logger.error("Error during background initialization", exc_info=True)
                error_msg = f"Initialization failed: {str(e)}"
                if hasattr(self, 'root') and hasattr(self.root, 'after') and self.root.winfo_exists():
                    self.root.after(0, lambda: self._show_error(error_msg) if hasattr(self, '_show_error') else None)
        
        # Start initialization in a separate thread
        if hasattr(self, 'root') and hasattr(self.root, 'after') and self.root.winfo_exists():
            thread = threading.Thread(target=init_task, daemon=True, name="SIEM-Init-Thread")
            thread.start()
            
    def _init_metrics(self):
        """Initialize metrics collection."""
        try:
            self.logger.info("Initializing metrics...")
            from src.models.metrics import DashboardMetrics
            from datetime import datetime
            # Initialize with current timestamp and empty metrics
            self.metrics = DashboardMetrics(timestamp=datetime.utcnow())
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize metrics: {e}", exc_info=True)
            return False
            
    def _init_event_model(self):
        """Initialize the event processing model."""
        try:
            self.logger.info("Initializing event model...")
            from src.models.event_model import EventModel
            self.event_model = EventModel()
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize event model: {e}", exc_info=True)
            return False
            
    def _init_data_collector(self):
        """Initialize the data collector service."""
        try:
            self.logger.info("Initializing data collector...")
            from services.data_collector import DataCollector
            self.data_collector = DataCollector(db_connection=self.db)
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize data collector: {e}", exc_info=True)
            return False
            
    def _init_edr_service(self, db_connection):
        """Initialize EDR service with the given database connection."""
        try:
            self.logger.info("Initializing EDR service...")
            from services.edr_service import EDRService
            self.edr_service = EDRService(db_connection=db_connection)
            self.edr_service.start()
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize EDR service: {e}", exc_info=True)
            return False
            
    def _initialize_dashboard_service(self):
        """Initialize the dashboard service."""
        try:
            self.logger.info("Initializing dashboard service...")
            from services.dashboard_service import DashboardService
            
            # Ensure data collector is initialized first
            if not hasattr(self, 'data_collector') or self.data_collector is None:
                if not self._init_data_collector():
                    raise RuntimeError("Failed to initialize data collector")
                    
            # Create dashboard service
            self.dashboard_service = DashboardService(self.root, self.data_collector)
            self.dashboard_service.start()
            self.logger.info("Dashboard service started successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error initializing dashboard service: {e}", exc_info=True)
            raise
            
    def _initialize_ui_components(self):
        """Initialize UI components on the main thread."""
        try:
            self.logger.info("Initializing UI components...")
            
            # Initialize views dictionary if it doesn't exist
            if not hasattr(self, 'views'):
                self.views = {}
            
            # Only initialize each view once
            if 'dashboard' not in self.views:
                self.views['dashboard'] = ttk.Frame(self.view_container)
                self._setup_dashboard_view(self.views['dashboard'])
                
            if 'edr' not in self.views:
                self.views['edr'] = ttk.Frame(self.view_container)
                self._setup_edr_view(self.views['edr'])
                
            if 'ndr' not in self.views:
                self.views['ndr'] = ttk.Frame(self.view_container)
                self._setup_ndr_view(self.views['ndr'])
                
            if 'hips' not in self.views:
                self.views['hips'] = ttk.Frame(self.view_container)
                self._setup_hips_view(self.views['hips'])
                
            if 'nips' not in self.views:
                self.views['nips'] = ttk.Frame(self.view_container)
                self._setup_nips_view(self.views['nips'])
            
            # Hide all views initially
            for view in self.views.values():
                view.pack_forget()
            
            # Start background services
            self._update_status("Starting background services...")
            if hasattr(self, '_start_background_services'):
                self._start_background_services()
            
            # Show main UI
            self.root.after(0, self._show_main_ui)
            
        except Exception as e:
            self.logger.error(f"Error initializing UI components: {e}", exc_info=True)
            raise
        
    def _show_main_ui(self):
        """Show the main application UI using grid geometry manager."""
        try:
            # Only initialize the UI once
            if hasattr(self, 'container') and hasattr(self.container, 'winfo_exists') and self.container.winfo_exists():
                self.logger.debug("UI already initialized, skipping...")
                return
                
            self.logger.info("Initializing main UI...")
            
            # Ensure root window exists and is properly configured
            if not hasattr(self, 'root') or not self.root or not self.root.winfo_exists():
                self.logger.error("Root window not available for UI initialization")
                return
            
            try:
                self.root.title("SIEM Dashboard")
                self.root.geometry("1200x800")
                
                # Configure root window grid
                self.root.grid_rowconfigure(0, weight=1)
                self.root.grid_columnconfigure(0, weight=1)
                
                # Configure style for navigation buttons
                style = ttk.Style()
                style.configure('Nav.TButton', font=('Arial', 10, 'bold'), padding=5)
                
                # Create main container using grid
                self.container = ttk.Frame(self.root, padding="5")
                self.container.grid(row=0, column=0, sticky=tk.NSEW)
                self.container.grid_rowconfigure(1, weight=1)  # For view container
                self.container.grid_columnconfigure(0, weight=1)
                
                # Create navigation frame with grid
                nav_frame = ttk.Frame(self.container, padding="5 0")
                nav_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 5))
                nav_frame.grid_columnconfigure(0, weight=1)  # Make nav frame expand horizontally
                
                # Create a frame inside nav_frame for the buttons
                button_frame = ttk.Frame(nav_frame)
                button_frame.grid(row=0, column=0, sticky=tk.W)
                
                # Navigation buttons
                nav_buttons = [
                    ("Dashboard", 'dashboard'),
                    ("EDR", 'edr'),
                    ("NDR", 'ndr'),
                    ("HIPS", 'hips'),
                    ("NIPS", 'nips')
                ]
                
                # Add navigation buttons using grid
                for col, (text, view_name) in enumerate(nav_buttons):
                    try:
                        btn = ttk.Button(
                            button_frame,
                            text=text,
                            command=lambda v=view_name: self.show_view(v) if hasattr(self, 'show_view') else None,
                            style='Nav.TButton',
                            width=10
                        )
                        btn.grid(row=0, column=col, padx=2, sticky=tk.W)
                    except Exception as e:
                        self.logger.error(f"Error creating {view_name} button: {e}", exc_info=True)
                
                # Create view container
                self.view_container = ttk.Frame(self.container, padding="5", relief=tk.SUNKEN)
                self.view_container.grid(row=1, column=0, sticky=tk.NSEW, pady=(0, 5))
                self.view_container.grid_rowconfigure(0, weight=1)
                self.view_container.grid_columnconfigure(0, weight=1)
                
                # Initialize views if not already done
                if not hasattr(self, 'views') or not self.views:
                    self._initialize_ui_components()
                
                # Show the dashboard view by default
                if hasattr(self, 'show_view'):
                    # Ensure views are initialized first
                    if not hasattr(self, 'views') or not self.views:
                        self._initialize_views()
                    # Show dashboard view immediately
                    self.show_view('dashboard')
                
                # Remove loading screen if it exists
                if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
                    self.loading_frame.destroy()
                    del self.loading_frame
                
                self.logger.info("Main UI initialization completed")
                
            except Exception as e:
                self.logger.error(f"Error in UI initialization: {e}", exc_info=True)
                raise
                
        except Exception as e:
            self.logger.error(f"Failed to show main UI: {e}", exc_info=True)
            if hasattr(self, 'root') and hasattr(self.root, 'after'):
                self.root.after(1000, self._show_main_ui)  # Retry after a delay
            
            # Create status bar
            self.status_bar = ttk.Label(
                self.container,
                text="Ready",
                relief=tk.SUNKEN,
                anchor=tk.W,
                padding=5
            )
            self.status_bar.grid(row=2, column=0, sticky=tk.EW)
            
            # Initialize views
            self._initialize_views()
            
            # Show dashboard by default
            self.show_view('dashboard')
            
            # Make sure the window is properly updated
            self.root.update_idletasks()
            
        except Exception as e:
            logging.error(f"Error showing main UI: {e}")
            raise
        
    def show_events(self):
        """Show the events view."""
        try:
            self._show_view("events")
        except Exception as e:
            logger.error(f"Failed to show events view: {e}", exc_info=True)
            self._show_error(f"Failed to load events: {str(e)}")
    
    def _stop_managers(self):
        """Stop all manager components."""
        try:
            # Stop Windows collector if it exists
            if hasattr(self, 'windows_collector') and self.windows_collector is not None:
                try:
                    if hasattr(self.windows_collector, 'stop') and callable(self.windows_collector.stop):
                        logger.debug("Stopping Windows log collector...")
                        self.windows_collector.stop()
                        logger.info("Windows log collector stopped")
                except Exception as e:
                    logger.error(f"Error stopping log collector: {e}", exc_info=True)
            
            # Stop all managers
            managers = [
                ('ndr_manager', 'NDR'),
                ('dlp_manager', 'DLP'),
                ('fim_manager', 'FIM'),
            ]
            
            for manager_attr, name in managers:
                if hasattr(self, manager_attr) and getattr(self, manager_attr):
                    try:
                        logger.debug(f"Stopping {name} manager...")
                        getattr(self, manager_attr).stop()
                        logger.info(f"{name} manager stopped")
                    except Exception as e:
                        logger.error(f"Error stopping {name} manager: {e}", exc_info=True)
            
            logger.info("All components stopped successfully")
            
        except Exception as e:
            logger.error(f"Error during stop: {e}", exc_info=True)
            raise

    def _complete_ui_initialization(self):
        """Complete the UI initialization after all services are ready."""
        try:
            # Ensure we don't initialize UI multiple times
            if hasattr(self, '_ui_initialized') and self._ui_initialized:
                return
                
            # Mark UI as initializing
            self._ui_initialized = True
            
            # Initialize the main UI
            self._show_main_ui()
            
            # Set a flag to prevent duplicate view initialization
            if not hasattr(self, '_views_initialized'):
                self._initialize_views()
                self._views_initialized = True
                
            # Show the dashboard view
            self.show_view('dashboard')
            
            # Start service status checks
            self.root.after(100, self._check_services_status)
            
        except Exception as e:
            error_msg = f"Failed to initialize UI: {str(e)}"
            logging.error(error_msg)
            if hasattr(self, 'root') and self.root.winfo_exists():
                messagebox.showerror("Initialization Error", error_msg)
    
    def _initialize_views(self):
        """Initialize all views if they don't exist."""
        try:
            # Initialize views dictionary if it doesn't exist
            if not hasattr(self, 'views'):
                self.views = {}
            
            # Only initialize each view once
            if 'dashboard' not in self.views:
                self.views['dashboard'] = ttk.Frame(self.view_container)
                self._setup_dashboard_view(self.views['dashboard'])
                
            if 'edr' not in self.views:
                self.views['edr'] = ttk.Frame(self.view_container)
                self._setup_edr_view(self.views['edr'])
                
            if 'ndr' not in self.views:
                self.views['ndr'] = ttk.Frame(self.view_container)
                self._setup_ndr_view(self.views['ndr'])
                
            if 'hips' not in self.views:
                self.views['hips'] = ttk.Frame(self.view_container)
                self._setup_hips_view(self.views['hips'])
                
            if 'nips' not in self.views:
                self.views['nips'] = ttk.Frame(self.view_container)
                self._setup_nips_view(self.views['nips'])
            
            # Hide all views initially
            for view in self.views.values():
                view.pack_forget()
                
        except Exception as e:
            logging.error(f"Error initializing views: {e}")
            raise
        
    def show_view(self, view_name):
        """Show the specified view."""
        try:
            # Don't do anything if we're already showing this view
            if hasattr(self, 'current_view') and self.current_view == view_name:
                return
                
            # Make sure views are initialized
            if not hasattr(self, 'views') or not self.views:
                self._initialize_views()
            
            # Hide all views
            for view in self.views.values():
                view.pack_forget()
            
            # Show the requested view if it exists
            if view_name in self.views and self.views[view_name].winfo_exists():
                self.views[view_name].pack(fill="both", expand=True, padx=5, pady=5)
                self.current_view = view_name
                
                # Update status bar
                if hasattr(self, 'status_bar'):
                    self.status_bar.config(text=f"View: {view_name.upper()}")
                    
                # Update window title
                self.root.title(f"SIEM Dashboard - {view_name.upper()}")
                
                # Call view-specific initialization if available
                view_obj = getattr(self, f"{view_name}_view", None)
                if view_obj and hasattr(view_obj, 'on_show'):
                    view_obj.on_show()
                    
            else:
                logger.warning(f"View not found or not initialized: {view_name}")
                if 'dashboard' in self.views and self.views['dashboard'].winfo_exists():
                    self.views['dashboard'].pack(fill="both", expand=True)
                    self.current_view = 'dashboard'
                
        except Exception as e:
            logging.error(f"Error showing view {view_name}: {e}")
            # Try to fall back to dashboard on error
            if 'dashboard' in self.views and self.views['dashboard'].winfo_exists():
                self.views['dashboard'].pack(fill="both", expand=True)
                self.current_view = 'dashboard'
    
    def on_close(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.cleanup()
            self.root.quit()
    
    def start(self):
        """Start the SIEM system and all its components."""
        try:
            logger.info("Starting SIEM system components...")
            
            # Initialize background services
            logger.info("Initializing background services...")
            self._initialize_background_services()
            logger.info("Background services initialized successfully")
            
            # Complete UI initialization
            logger.info("Starting UI initialization...")
            self._complete_ui_initialization()
            logger.info("UI initialization completed")
            
            logger.info("SIEM system started successfully")
            
            # Force log flush to ensure all messages are written
            for handler in logger.handlers:
                handler.flush()
            
            # Keep the main thread alive
            if hasattr(self, 'root') and self.root:
                self.root.mainloop()
            else:
                logger.warning("Root window not available, entering wait state")
                while True:
                    time.sleep(1)
            
        except Exception as e:
            logger.critical(f"Failed to start SIEM system: {e}", exc_info=True)
            # Ensure we log the full traceback
            import traceback
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise

    def _init_database(self):
        """Initialize the database connection with detailed logging."""
        db_initialized = False
        try:
            self.logger.info("Initializing database...")
            
            # Get database path
            db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.abspath(os.path.join(db_dir, 'siem.db'))
            self.logger.info(f"Database path: {db_path}")
            
            # Check if database exists, create if it doesn't
            if not os.path.exists(db_path):
                self.logger.warning(f"Database file not found at {db_path}, creating new database")
                try:
                    with open(db_path, 'a'):
                        os.utime(db_path, None)
                    self.logger.info(f"Successfully created new database file at {db_path}")
                except Exception as e:
                    self.logger.error(f"Failed to create database file: {e}")
                    raise
            else:
                self.logger.info(f"Database file exists at {db_path}, size: {os.path.getsize(db_path)} bytes")
            
            # Initialize database connection
            self.logger.info("Initializing database connection...")
            try:
                self.db = Database(db_path)
                self.logger.info("Database connection established successfully")
            except Exception as e:
                self.logger.error(f"Failed to connect to database: {e}", exc_info=True)
                raise
            
            # Create tables if they don't exist
            self.logger.info("Verifying database schema...")
            self._create_tables()
            
            # Verify database is accessible
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # List all tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                self.logger.info(f"Found {len(tables)} tables: {', '.join(tables) if tables else 'No tables found'}")
                
                # Check events table structure
                if 'events' in tables:
                    cursor.execute("PRAGMA table_info(events)")
                    columns = [col[1] for col in cursor.fetchall()]
                    self.logger.info(f"Events table columns: {', '.join(columns) if columns else 'No columns found'}")
                    
                    # Verify required columns exist
                    required_columns = ['id', 'timestamp', 'source', 'event_type', 'severity', 'status']
                    missing_columns = [col for col in required_columns if col not in columns]
                    if missing_columns:
                        self.logger.warning(f"Missing columns in events table: {', '.join(missing_columns)}")
                        
                        # Try to add missing columns
                        for col in missing_columns:
                            try:
                                if col == 'status':
                                    cursor.execute("ALTER TABLE events ADD COLUMN status TEXT DEFAULT 'new'")
                                elif col in ['source', 'event_type']:
                                    cursor.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
                                elif col == 'severity':
                                    cursor.execute("ALTER TABLE events ADD COLUMN severity INTEGER")
                                conn.commit()
                                self.logger.info(f"Successfully added column '{col}' to events table")
                            except Exception as e:
                                self.logger.error(f"Failed to add column '{col}' to events table: {e}")
                                conn.rollback()
                
                # Enable WAL mode for better concurrency
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.execute("PRAGMA foreign_keys=ON;")
                self.logger.info("Database optimizations applied (WAL mode, NORMAL sync, FK constraints)")
            
            db_initialized = True
            self.logger.info("Database initialization completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}", exc_info=True)
            if hasattr(self, 'db') and self.db:
                try:
                    self.db.close()
                    self.logger.info("Closed database connection after error")
                except Exception as close_error:
                    self.logger.error(f"Error closing database connection: {close_error}")
            
            if not db_initialized:
                self.logger.error("Database initialization failed. Please run setup_database_fix.py manually.")
            
            raise RuntimeError(f"Failed to initialize database: {str(e)}") from e
    
    def _create_tables(self):
        """Verify database schema and create any missing tables or columns."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                existing_tables = {row[0].lower() for row in cursor.fetchall()}
                self.logger.info(f"Found tables in database: {', '.join(existing_tables) if existing_tables else 'No tables found'}")
                
                # Define required tables and their schemas
                table_schemas = {
                    'events': """
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity INTEGER DEFAULT 1,
                        description TEXT,
                        raw_data TEXT,
                        status TEXT DEFAULT 'new',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    'alerts': """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id INTEGER,
                        title TEXT NOT NULL,
                        description TEXT,
                        status TEXT DEFAULT 'open',
                        severity INTEGER DEFAULT 1,
                        source TEXT,
                        category TEXT,
                        assigned_to TEXT,
                        resolution TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        resolved_at DATETIME,
                        FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE SET NULL
                    )
                    """,
                    'users': """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        full_name TEXT,
                        email TEXT UNIQUE,
                        role TEXT DEFAULT 'analyst',
                        is_active BOOLEAN DEFAULT 1,
                        last_login DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    'settings': """
                    CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT UNIQUE NOT NULL,
                        value TEXT,
                        description TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                }
                
                # Create missing tables
                for table_name, schema in table_schemas.items():
                    if table_name not in existing_tables:
                        try:
                            self.logger.info(f"Creating table: {table_name}")
                            cursor.execute(schema)
                            conn.commit()
                            self.logger.info(f"Successfully created table: {table_name}")
                        except Exception as e:
                            self.logger.error(f"Failed to create table {table_name}: {e}")
                            conn.rollback()
                
                # Verify required columns in events table
                cursor.execute("PRAGMA table_info(events)")
                event_columns = {col[1].lower() for col in cursor.fetchall()}
                self.logger.info(f"Found columns in events table: {', '.join(event_columns) if event_columns else 'No columns found'}")
                
                # Check for required columns and add them if missing
                required_columns = {
                    'status': 'TEXT DEFAULT "new"', 
                    'source': 'TEXT', 
                    'event_type': 'TEXT', 
                    'severity': 'INTEGER DEFAULT 1'
                }
                
                for col, col_type in required_columns.items():
                    if col not in event_columns:
                        try:
                            self.logger.warning(f"Adding missing column '{col}' to events table")
                            cursor.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
                            conn.commit()
                            self.logger.info(f"Successfully added column '{col}' to events table")
                        except Exception as e:
                            self.logger.error(f"Failed to add column '{col}' to events table: {e}")
                            conn.rollback()
                
                # Create required indexes
                required_indexes = [
                    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)",
                    "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)",
                    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
                    "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
                    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
                    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
                    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"
                ]
                
                for index_sql in required_indexes:
                    try:
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", 
                                     (index_sql.split()[-1],))
                        if not cursor.fetchone():
                            cursor.execute(index_sql)
                            conn.commit()
                            self.logger.info(f"Created index: {index_sql}")
                    except Exception as e:
                        self.logger.error(f"Failed to create index: {e}")
                        conn.rollback()
                
                # Verify database integrity
                cursor.execute("PRAGMA integrity_check")
                integrity_check = cursor.fetchone()
                if integrity_check and integrity_check[0] == 'ok':
                    self.logger.info("Database integrity check passed")
                else:
                    self.logger.error(f"Database integrity check failed: {integrity_check}")
                    raise RuntimeError("Database integrity check failed")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error in _create_tables: {e}", exc_info=True)
            raise
    
    def _generate_sample_data(self, num_events: int = 1000):
        """Generate sample event data for testing that matches the database schema."""
        import random
        import json
        from datetime import datetime, timedelta
        
        sources = ["Windows Security", "Firewall", "Application", "System", "Security"]
        event_types = ["Login", "Logout", "Access Denied", "Configuration Change", "System Error"]
        # Severity levels: 1=Low, 2=Medium, 3=High, 4=Critical
        severities = [1, 2, 3, 4]
        statuses = ["new", "in_progress", "resolved", "closed"]
        descriptions = [
            "User login attempt",
            "Failed authentication",
            "Configuration change detected",
            "System error occurred",
            "Security alert triggered",
            "Network connection established",
            "File access denied",
            "Privilege escalation attempt",
            "New process started",
            "Suspicious activity detected"
        ]
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if we already have data
                cursor.execute("SELECT COUNT(*) FROM events")
                count = cursor.fetchone()[0]
                
                if count > 0:
                    self.logger.info(f"Database already contains {count} events, skipping sample data generation")
                    return True
                
                # Generate sample events
                base_time = datetime.utcnow()
                for i in range(num_events):
                    event_time = base_time - timedelta(minutes=random.randint(0, 60*24*7))  # Last 7 days
                    source = random.choice(sources)
                    event_type = random.choice(event_types)
                    # Weights for severities: 1=Low, 2=Medium, 3=High, 4=Critical
                    severity = random.choices(severities, weights=[0.4, 0.3, 0.2, 0.1])[0]
                    status = random.choice(statuses)
                    description = random.choice(descriptions)
                    
                    # Create raw_data JSON
                    raw_data = {
                        "source": source,
                        "event_type": event_type,
                        "severity": severity,
                        "description": f"{description} - {i+1}",
                        "timestamp": event_time.isoformat(),
                        "hostname": f"HOST-{random.randint(1, 20)}",
                        "user": f"user{random.randint(1, 50)}",
                        "ip_address": f"192.168.1.{random.randint(1, 254)}",
                        "details": {
                            "category": source.split()[0],
                            "action": event_type.lower().replace(' ', '_'),
                            "count": random.randint(1, 10)
                        }
                    }
                    
                    cursor.execute(
                        """
                        INSERT INTO events 
                        (timestamp, source, event_type, severity, description, raw_data, status, processed, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                        """,
                        (
                            event_time.isoformat(),
                            source,
                            event_type,
                            severity,
                            f"{description} from {source} - {event_type}",
                            json.dumps(raw_data),
                            status,
                            random.choice([0, 1])  # Randomly mark some as processed
                        )
                    )
                    
                    # Commit every 100 records
                    if i > 0 and i % 100 == 0:
                        conn.commit()
                        self.logger.info(f"Generated {i}/{num_events} sample events...")
                
                conn.commit()
                self.logger.info(f"Successfully generated {num_events} sample events")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to generate sample data: {e}", exc_info=True)
            return False

    def _create_tables(self):
        """Verify database schema and create any missing tables or columns."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                # Check if tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                existing_tables = {row[0].lower() for row in cursor.fetchall()}
                self.logger.info(f"Found tables in database: {', '.join(existing_tables) if existing_tables else 'No tables found'}")

                # Check if required tables exist
                required_tables = {'events', 'alerts', 'users', 'settings'}
                missing_tables = required_tables - existing_tables

                if missing_tables:
                    self.logger.warning(f"Missing tables: {', '.join(missing_tables)}")
                    self.logger.warning("Please run setup_database_fix.py to initialize the database schema")
                    raise RuntimeError("Database schema is not properly initialized. Please run setup_database_fix.py")

                # Verify required columns in events table
                cursor.execute("PRAGMA table_info(events)")
                event_columns = {col[1].lower() for col in cursor.fetchall()}
                self.logger.info(f"Found columns in events table: {', '.join(event_columns) if event_columns else 'No columns found'}")

                # Check for required columns and add them if missing
                required_columns = {
                    'status': 'TEXT DEFAULT "new"',
                    'source': 'TEXT',
                    'event_type': 'TEXT',
                    'severity': 'INTEGER',
                    'description': 'TEXT',
                    'raw_data': 'TEXT',
                    'processed': 'INTEGER DEFAULT 0',
                    'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
                    'updated_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
                    'category': 'TEXT',
                    'source_ip': 'TEXT',
                    'destination_ip': 'TEXT',
                    'user_agent': 'TEXT',
                    'hostname': 'TEXT',
                    'process_name': 'TEXT',
                    'process_id': 'INTEGER',
                    'parent_process_id': 'INTEGER',
                    'command_line': 'TEXT',
                    'file_path': 'TEXT',
                    'file_hash': 'TEXT',
                    'registry_key': 'TEXT',
                    'registry_value': 'TEXT',
                    'registry_data': 'TEXT'
                }

                for col, col_type in required_columns.items():
                    if col not in event_columns:
                        self.logger.warning(f"Adding missing column '{col}' to events table")
                        try:
                            cursor.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
                            conn.commit()
                            self.logger.info(f"Added column '{col}' to events table")
                        except Exception as e:
                            self.logger.error(f"Failed to add column '{col}': {e}")
                            raise
                
                conn.commit()
                self.logger.info("Database schema verification completed")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to verify database schema: {e}", exc_info=True)
            raise
                
    def _initialize_background_services(self):
        """Initialize background services and components.
        
        This method initializes all background services required by the SIEM system,
        including metrics collection, event processing, and platform-specific collectors.
        
        Raises:
            Exception: If any critical service fails to initialize
        """
        self.logger.info("Initializing background services...")
        
        try:
            # Initialize database first
            self._init_database()
            
            # Initialize metrics collector with error handling
            try:
                self.logger.debug("Initializing metrics collector...")
                self.metrics = MetricsCollector()
                self.metrics.start()
                self.logger.info("Metrics collector initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize metrics collector: {e}", exc_info=True)
                raise RuntimeError("Failed to initialize metrics collector") from e
            
            # Initialize event model with database connection
            try:
                self.logger.debug("Initializing event model...")
                if not hasattr(self, 'db') or self.db is None:
                    raise RuntimeError("Database connection not available")
                
                # Create event model
                self.event_model = EventModel(db=self.db)
                self.logger.info("Event model initialized successfully")
                
                # Generate sample data if database is empty
                self._generate_sample_data()
            except Exception as e:
                self.logger.error(f"Failed to initialize event model: {e}", exc_info=True)
                raise RuntimeError("Failed to initialize event model") from e
            
            # Initialize data collector and dashboard service
            try:
                self.logger.debug("Initializing data collector and dashboard service...")
                self.data_collector = DataCollector(db_connection=self.db)
                self.dashboard_service = DashboardService(self.root, self.data_collector)
                self.logger.info("Data collector and dashboard service initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize data collector and dashboard service: {e}", exc_info=True)
                raise RuntimeError("Failed to initialize data collector and dashboard service") from e
            
            # Platform-specific collectors
            if sys.platform == 'win32':
                try:
                    self.logger.debug("Initializing Windows event collector...")
                    from collectors.windows import WindowsEventCollector
                    self.windows_collector = WindowsEventCollector()
                    self.windows_collector.start()
                    self.logger.info("Windows event collector started successfully")
                except ImportError as e:
                    self.logger.warning(f"Windows collector not available: {e}")
                except Exception as e:
                    self.logger.error(f"Failed to initialize Windows collector: {e}", exc_info=True)
                    # Non-critical, continue with other services
            
            # Initialize manager components
            try:
                self.logger.debug("Initializing manager components...")
                self._initialize_managers()
                self.logger.info("Manager components initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize manager components: {e}", exc_info=True)
                raise RuntimeError("Failed to initialize manager components") from e
            
            self.logger.info("All background services initialized successfully")
            
        except Exception as e:
            self.logger.critical(f"Critical error initializing background services: {e}", exc_info=True)
            # Attempt to clean up any partially initialized services
            try:
                self.cleanup()
            except Exception as cleanup_error:
                self.logger.error(f"Error during cleanup after initialization failure: {cleanup_error}", 
                                exc_info=True)
            raise
    
    def _initialize_managers(self):
        """Initialize various manager components."""
        try:
            self.logger.info("Initializing manager components...")
            
            # Import managers
            from managers.ndr import NDRManager
            from managers.dlp import DLPManager
            from managers.fim import FIMManager
            
            # Initialize NDR Manager
            self.ndr_manager = NDRManager()
            self.ndr_manager.initialize()
            
            # Initialize DLP Manager
            self.dlp_manager = DLPManager()
            self.dlp_manager.initialize()
            
            # Initialize FIM Manager
            self.fim_manager = FIMManager()
            self.fim_manager.initialize()
            
            self.logger.info("All manager components initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize manager components: {e}", exc_info=True)
            raise RuntimeError("Failed to initialize manager components") from e

    def cleanup(self):
        """
        Clean up resources and stop all services.
        This method is idempotent and can be safely called multiple times.
        """
        # Prevent multiple cleanup attempts
        if getattr(self, '_cleanup_started', False):
            self.logger.debug("Cleanup already in progress")
            return
            
        self._cleanup_started = True
        self.logger.info("Starting cleanup process...")
        
        try:
            # Stop background services
            if hasattr(self, 'edr_service') and self.edr_service:
                try:
                    self.logger.info("Stopping EDR service...")
                    self.edr_service.stop()
                except Exception as e:
                    self.logger.error(f"Error stopping EDR service: {e}", exc_info=True)
            
            # Close database connections
            if hasattr(self, 'db') and self.db:
                try:
                    self.logger.info("Closing database connections...")
                    if hasattr(self.db, 'close'):
                        self.db.close()
                except Exception as e:
                    self.logger.error(f"Error closing database: {e}", exc_info=True)
            
            # Stop thread pool
            if hasattr(self, '_executor') and self._executor:
                try:
                    self.logger.info("Shutting down thread pool...")
                    self._executor.shutdown(wait=False, cancel_futures=True)
                except Exception as e:
                    self.logger.error(f"Error shutting down thread pool: {e}", exc_info=True)
            
            # Clear any scheduled events
            if hasattr(self, 'root') and self.root and hasattr(self.root, 'after_cancel'):
                for after_id in getattr(self, '_after_ids', []):
                    try:
                        self.root.after_cancel(after_id)
                    except:
                        pass
                
            self.logger.info("Cleanup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}", exc_info=True)
            raise
            
        self._cleanup_started = True
        self.logger.info("Starting cleanup process...")
        
        try:
            # Stop the log collector if it exists
            if hasattr(self, 'windows_collector') and self.windows_collector is not None:
                try:
                    self.logger.debug("Stopping log collector...")
                    self.windows_collector.stop()
                    self.logger.debug("Log collector stopped successfully")
                except Exception as e:
                    self.logger.error(f"Error stopping log collector: {e}", exc_info=True)
                finally:
                    self.windows_collector = None
            
            # Stop all managers
            try:
                # Stop NDR manager if it exists
                if hasattr(self, 'ndr_manager') and self.ndr_manager:
                    try:
                        self.ndr_manager.stop()
                        self.logger.info("NDR manager stopped")
                    except Exception as e:
                        self.logger.error(f"Error stopping NDR manager: {e}", exc_info=True)
                
                # Stop DLP manager if it exists
                if hasattr(self, 'dlp_manager') and self.dlp_manager:
                    try:
                        self.dlp_manager.stop()
                        self.logger.info("DLP manager stopped")
                    except Exception as e:
                        self.logger.error(f"Error stopping DLP manager: {e}", exc_info=True)
                
                # Call the base _stop_managers method
                try:
                    self._stop_managers()
                except Exception as e:
                    self.logger.error(f"Error in _stop_managers: {e}", exc_info=True)
                    
            except Exception as e:
                self.logger.error(f"Unexpected error during manager cleanup: {e}", exc_info=True)
            
            # Stop dashboard service if it exists
            if hasattr(self, 'dashboard_service') and self.dashboard_service:
                try:
                    # Schedule the dashboard service stop on the main thread if needed
                    if hasattr(self, 'root') and self.root and hasattr(self.root, 'after'):
                        try:
                            self.root.after(0, self.dashboard_service.stop)
                            self.logger.info("Scheduled dashboard service stop on main thread")
                        except Exception as e:
                            self.logger.error(f"Error scheduling dashboard service stop: {e}")
                    else:
                        # If we can't schedule on main thread, try direct stop
                        try:
                            self.dashboard_service.stop()
                            self.logger.info("Dashboard service stopped")
                        except RuntimeError as e:
                            if "main thread is not in main loop" in str(e):
                                self.logger.warning("Could not stop dashboard service (main thread issue)")
                            else:
                                self.logger.error(f"Error stopping dashboard service: {e}")
                except Exception as e:
                    self.logger.error(f"Unexpected error stopping dashboard service: {e}")
            
            # Close database connection
            if hasattr(self, 'db') and self.db:
                try:
                    self.db.close()
                    self.logger.info("Database connection closed")
                except Exception as e:
                    self.logger.error(f"Error closing database connection: {e}")
            
            # Stop any running threads
            if hasattr(self, '_threads'):
                for thread in self._threads:
                    if thread.is_alive():
                        try:
                            thread.join(timeout=2.0)
                            if thread.is_alive():
                                self.logger.warning(f"Thread {thread.name} did not stop gracefully")
                        except Exception as e:
                            self.logger.error(f"Error joining thread {thread.name}: {e}")
            
            # Shutdown thread pool
            if hasattr(self, '_executor') and self._executor:
                try:
                    self._executor.shutdown(wait=False, cancel_futures=True)
                except Exception as e:
                    self.logger.error(f"Error shutting down thread pool: {e}")
            
            # Clean up Tkinter resources if needed
            if hasattr(self, 'root') and self.root and hasattr(self.root, 'destroy'):
                try:
                    # Schedule the destroy on the main thread
                    try:
                        if hasattr(self.root, 'after'):
                            self.root.after(100, self.root.destroy)
                        else:
                            self.root.destroy()
                        self.logger.info("Tkinter root window destroyed")
                    except Exception as e:
                        self.logger.debug("Error destroying Tkinter window (may be already destroyed): %s", e)
                    
                    # Clear the reference
                    if hasattr(self, 'root'):
                        del self.root
                    
                except Exception as e:
                    self.logger.error(f"Error during Tkinter cleanup: {e}", exc_info=True)
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}", exc_info=True)
        
        # Close database connection
        if hasattr(self, 'db') and self.db:
            try:
                self.db.close()
                self.logger.info("Database connection closed")
            except Exception as e:
                self.logger.error(f"Error closing database connection: {e}")
        
        # Stop any running threads
        if hasattr(self, '_threads'):
            for thread in self._threads:
                if thread.is_alive():
                    try:
                        thread.join(timeout=2.0)
                        if thread.is_alive():
                            self.logger.warning(f"Thread {thread.name} did not stop gracefully")
                    except Exception as e:
                        self.logger.error(f"Error joining thread {thread.name}: {e}")
    
    def _setup_nips_view(self, parent):
        """Set up the Network Intrusion Prevention System view."""
        try:
            frame = ttk.Frame(parent, padding="10")
            frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
            
            # Add NIPS view widgets here
            label = ttk.Label(frame, text="Network Intrusion Prevention System", font=('Helvetica', 16, 'bold'))
            label.pack(pady=20)
            
            # Add a sample button
            ttk.Button(frame, text="Run NIPS Scan", command=self.run_nips_scan).pack(pady=10)
            
            return frame
            
        except Exception as e:
            self.logger.error(f"Error setting up NIPS view: {e}", exc_info=True)
            raise
            
    def run_nips_scan(self):
        """Initiate a NIPS scan."""
        self.logger.info("Initiating NIPS scan...")
        # Add NIPS scanning logic here
            
    def _setup_ndr_view(self, parent):
        """Setup the Network Detection and Response view."""
        self.logger.info("Setting up NDR view")
        frame = ttk.Frame(parent, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Add NDR view widgets here
        label = ttk.Label(frame, text="Network Detection and Response", font=('Helvetica', 16, 'bold'))
        label.pack(pady=20)
        
        # Add a sample button
        ttk.Button(frame, text="Scan Network", command=self.scan_network).pack(pady=10)
        
        return frame
        
    def scan_network(self):
        """Initiate a network scan."""
        self.logger.info("Initiating network scan...")
        # Add network scanning logic here
        
    def _retry_dashboard(self, parent_frame, error_frame):
        """Retry loading the dashboard view.
        
        Args:
            parent_frame: The parent frame where the dashboard should be displayed
            error_frame: The error frame to remove
        """
        try:
            # Remove the error frame
            error_frame.destroy()
            
            # Clear any existing dashboard widgets
            for widget in parent_frame.winfo_children():
                widget.destroy()
            
            # Re-initialize the dashboard view
            self._setup_dashboard_view(parent_frame)
            
        except Exception as e:
            logger.error(f"Failed to retry dashboard: {e}", exc_info=True)
            # If retry fails, show error message
            error_label = ttk.Label(
                parent_frame,
                text=f"Failed to load dashboard: {str(e)}\nCheck logs for details.",
                foreground='red',
                wraplength=500,
                justify='center'
            )
            error_label.pack(expand=True, fill='both', padx=20, pady=20)
    
    def _setup_dashboard_view(self, parent_frame):
        """Set up the dashboard view with metrics and alerts."""
        try:
            # Configure parent frame
            parent_frame.grid_rowconfigure(0, weight=1)
            parent_frame.grid_columnconfigure(0, weight=1)
            
            # Create main container with padding
            container = ttk.Frame(parent_frame, padding=10)
            container.grid(row=0, column=0, sticky="nsew")
            container.grid_rowconfigure(1, weight=1)
            container.grid_columnconfigure(0, weight=1)
            
            # Add title
            title = ttk.Label(
                container,
                text="SIEM Dashboard",
                font=("Arial", 16, "bold")
            )
            title.grid(row=0, column=0, pady=10, sticky="w")
            
            # Create content frame
            content_frame = ttk.Frame(container)
            content_frame.grid(row=1, column=0, sticky="nsew")
            content_frame.grid_rowconfigure(0, weight=1)
            content_frame.grid_columnconfigure(0, weight=1)
            content_frame.grid(row=1, column=0, sticky="nsew")
            
            # Configure content frame grid
            content_frame.grid_rowconfigure(0, weight=1)
            content_frame.grid_columnconfigure(0, weight=1)
            
            # Create notebook for tabs
            self.dashboard_notebook = ttk.Notebook(content_frame)
            self.dashboard_notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
            
            # Add dashboard tab
            dashboard_tab = ttk.Frame(self.dashboard_notebook)
            self.dashboard_notebook.add(dashboard_tab, text="Overview")
            
            # Configure dashboard tab grid
            dashboard_tab.grid_rowconfigure(0, weight=1)
            dashboard_tab.grid_columnconfigure(0, weight=1)
            
            # Add dashboard widgets
            self._setup_dashboard_widgets(dashboard_tab)
            
            # Add metrics tab
            metrics_tab = ttk.Frame(self.dashboard_notebook)
            self.dashboard_notebook.add(metrics_tab, text="Metrics")
            
            # Configure metrics tab grid
            metrics_tab.grid_rowconfigure(0, weight=1)
            metrics_tab.grid_columnconfigure(0, weight=1)
            
            # Add alerts tab
            alerts_tab = ttk.Frame(self.dashboard_notebook)
            self.dashboard_notebook.add(alerts_tab, text="Alerts")
            
            # Configure alerts tab grid
            alerts_tab.grid_rowconfigure(0, weight=1)
            alerts_tab.grid_columnconfigure(0, weight=1)
            
            # Add status bar
            self.status_bar = ttk.Label(
                container,
                text="Ready",
                relief=tk.SUNKEN,
                anchor=tk.W
            )
            self.status_bar.grid(row=2, column=0, sticky="ew")
            
            # Update status
            self._update_status("Dashboard initialized")
            
            # Force update the display
            self.root.update_idletasks()
            
        except Exception as e:
            self.logger.error(f"Error setting up dashboard view: {e}", exc_info=True)
            # Try to show error in UI
            error_label = ttk.Label(
                parent_frame,
                text=f"Error initializing dashboard: {str(e)}",
                foreground="red"
            )
            error_label.pack(expand=True)
            return
            
            # Header frame
            header = ttk.Frame(dashboard_frame)
            header.grid(row=0, column=0, sticky=tk.EW, pady=(0, 10))
            header.grid_columnconfigure(0, weight=1)
            
            # Title label
            title = ttk.Label(
                header, 
                text="SIEM Security Dashboard", 
                font=('Arial', 16, 'bold')
            )
            title.grid(row=0, column=0, sticky=tk.W)
            
            # Create a notebook for different dashboard sections
            notebook = ttk.Notebook(dashboard_frame)
            notebook.grid(row=1, column=0, sticky=tk.NSEW, pady=(5, 0))
            notebook.grid_rowconfigure(0, weight=1)
            notebook.grid_columnconfigure(0, weight=1)
            
            # System Metrics Tab
            sys_metrics_frame = ttk.Frame(notebook, padding=10)
            sys_metrics_frame.grid_rowconfigure(0, weight=1)
            sys_metrics_frame.grid_columnconfigure(0, weight=1)
            notebook.add(sys_metrics_frame, text="System Metrics")
            
            try:
                # Add system metrics widget
                sys_metrics = SystemMetricsWidget(sys_metrics_frame, self.dashboard_service)
                sys_metrics.grid(row=0, column=0, sticky=tk.NSEW, padx=5, pady=5)
            except Exception as e:
                logger.error(f"Failed to create system metrics widget: {e}", exc_info=True)
                ttk.Label(
                    sys_metrics_frame, 
                    text=f"Failed to load system metrics: {str(e)}",
                    foreground='red',
                    wraplength=400
                ).pack(expand=True, fill='both', padx=20, pady=20)
            
            # Security Alerts Tab
            alerts_frame = ttk.Frame(notebook, padding=10)
            alerts_frame.grid_rowconfigure(0, weight=1)
            alerts_frame.grid_columnconfigure(0, weight=1)
            notebook.add(alerts_frame, text="Security Alerts")
            
            try:
                # Add security alerts widget
                alerts_widget = SecurityAlertsWidget(alerts_frame, self.dashboard_service)
                alerts_widget.grid(row=0, column=0, sticky=tk.NSEW, padx=5, pady=5)
            except Exception as e:
                logger.error(f"Failed to create security alerts widget: {e}", exc_info=True)
                ttk.Label(
                    alerts_frame,
                    text=f"Failed to load security alerts: {str(e)}",
                    foreground='red',
                    wraplength=400
                ).pack(expand=True, fill='both', padx=20, pady=20)
            
            # Start the dashboard service if not already started
            try:
                if not hasattr(self.dashboard_service, '_update_job') or self.dashboard_service._update_job is None:
                    self.dashboard_service.start()
                    logger.info("Dashboard service started successfully")
            except Exception as e:
                logger.error(f"Failed to start dashboard service: {e}", exc_info=True)
            
            return dashboard_frame
            
        except Exception as e:
            error_msg = f"Failed to initialize dashboard: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            # Create a frame for the error message
            error_frame = ttk.Frame(parent_frame)
            error_frame.grid(row=0, column=0, sticky=tk.NSEW)
            error_frame.grid_rowconfigure(0, weight=1)
            error_frame.grid_columnconfigure(0, weight=1)
            
            # Add error message
            error_label = ttk.Label(
                error_frame,
                text=f"Failed to load dashboard: {str(e)}\nCheck logs for details.",
                foreground='red',
                wraplength=500,
                justify='center'
            )
            error_label.grid(row=0, column=0, sticky='nsew', padx=20, pady=20)
            
            # Add a retry button
            retry_btn = ttk.Button(
                error_frame,
                text="Retry",
                command=lambda: self._retry_dashboard(parent_frame, error_frame)
            )
            retry_btn.grid(row=1, column=0, pady=10)
            
            return error_frame

def main():
    """Main entry point for the SIEM application.
    
    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    try:
        # Set up logging first
        logger = setup_logging()
        logger.info("Starting SIEM application")
        
        # Parse command line arguments
        debug_mode = '--debug' in sys.argv
        
        # Set up debug mode if requested
        if debug_mode:
            logger.setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
            
            # Enable debugpy if available
            try:
                import debugpy
                debugpy.listen(('0.0.0.0', 5678))
                logger.info("Debugger listening on port 5678")
            except ImportError:
                logger.warning("debugpy not available, running without debugger")
        
        # Initialize Tkinter
        import tkinter as tk
        from tkinter import ttk, messagebox
        
        # Create and configure main window
        root = tk.Tk()
        
        # Set window properties
        root.title("SIEM System")
        root.minsize(1200, 800)
        
        # Configure grid for the root window
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)
        
        # Center window on screen
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - 1200) // 2
        y = (screen_height - 800) // 2
        root.geometry(f"1200x800+{x}+{y}")
        
        # Create a frame to hold the main content
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Create application instance
        try:
            app = SIEMSystem(root)
            
            # Set up proper cleanup on exit
            def on_closing():
                if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
                    logger.info("Application shutdown requested by user")
                    try:
                        app.cleanup()
                    except Exception as e:
                        logger.error(f"Error during cleanup: {e}", exc_info=True)
                    finally:
                        root.destroy()
                        logger.info("Application shutdown complete")
            
            root.protocol("WM_DELETE_WINDOW", on_closing)
            
            # Start the application
            logger.info("Starting main event loop")
            root.mainloop()
            
            logger.info("Application exited successfully")
            return 0
            
        except Exception as e:
            logger.critical("Failed to initialize SIEM system", exc_info=True)
            messagebox.showerror(
                "Initialization Error",
                f"Failed to initialize SIEM system: {str(e)}\n\nCheck logs for details."
            )
            return 1
        
    except Exception as e:
        logger.critical(f"Fatal error in main application: {e}", exc_info=True)
        if 'root' in locals() and hasattr(root, 'winfo_exists') and root.winfo_exists():
            messagebox.showerror(
                "Fatal Error",
                f"A critical error occurred: {str(e)}\n\nThe application will now exit.\n\nCheck logs for details."
            )
        return 1

def setup_logging():
    """Configure application-wide logging with rotation and file handling."""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'siem_system.log')
    error_log_file = os.path.join(log_dir, 'siem_errors.log')
    
    # Main logger configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
            ),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Separate error log file handler
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logging.getLogger('').addHandler(error_handler)
    
    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    logging.getLogger('PIL').setLevel(logging.WARNING)
    
    return logging.getLogger('siem.main')


def handle_unhandled_exception(exc_type, exc_value, exc_traceback):
    """Handle any uncaught exceptions and log them."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Call the default handler for keyboard interrupts
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logger = logging.getLogger('siem.unhandled')
    logger.critical(
        "Unhandled exception",
        exc_info=(exc_type, exc_value, exc_traceback)
    )
    
    # Try to show error in UI if possible
    try:
        import tkinter.messagebox as messagebox
        messagebox.showerror(
            "Unexpected Error",
            f"An unexpected error occurred. Please check the logs for details.\n\n{str(exc_value)}"
        )
    except Exception:
        pass


if __name__ == "__main__":
    try:
        # Configure asyncio for better performance on Windows
        if sys.platform == 'win32':
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Set global exception handler
        sys.excepthook = handle_unhandled_exception
        
        # Initialize logging
        logger.info("Starting SIEM application")
        
        # Run the application
        exit_code = main()
        logger.info(f"Application exited with code {exit_code}")
        sys.exit(exit_code)
        
    except Exception as e:
        logger.critical(f"Fatal error in main: {e}", exc_info=True)
        sys.exit(1)