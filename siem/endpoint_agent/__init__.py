"""
SIEM Endpoint Agent
------------------
A lightweight agent for collecting and forwarding system logs and information to the SIEM server.
"""

__version__ = "1.0.0"
__author__ = "Security Ops Center"
__license__ = "MIT"

# Import main classes and functions
from .agent import SIEMAgent
from .collectors import (
    BaseCollector,
    WindowsEventCollector,
    SysmonCollector,
    SystemInfoCollector
)
from .utils import (
    setup_logging,
    load_config,
    get_hostname,
    get_system_info,
    is_running_as_admin
)

# Define __all__ for explicit exports
__all__ = [
    'SIEMEndpointAgent',
    'BaseCollector',
    'WindowsEventCollector',
    'SysmonCollector',
    'SystemInfoCollector',
    'setup_logging',
    'load_config',
    'get_hostname',
    'get_system_info',
    'is_running_as_admin',
]

# Set up default logging to prevent "No handler found" warnings
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
