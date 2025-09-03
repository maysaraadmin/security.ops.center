#!/usr/bin/env python3
"""
Agentless Monitoring Dashboard
-----------------------------
A PyQt5-based dashboard for managing agentless monitoring services.
"""
import sys
import logging
import asyncio
from pathlib import Path
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('agentless_dashboard.log')
    ]
)

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def main(config_path: Optional[str] = None):
    """Main entry point for the Agentless Monitoring Dashboard.
    
    Args:
        config_path: Optional path to the configuration file
    """
    try:
        from PyQt5.QtWidgets import QApplication
        from siem.gui.agentless.dashboard import AgentlessDashboard
        
        # Set up asyncio event loop for Qt
        from qasync import QEventLoop, enable_qt_logging
        
        # Enable Qt logging
        enable_qt_logging()
        
        # Create Qt application
        app = QApplication(sys.argv)
        loop = QEventLoop(app)
        asyncio.set_event_loop(loop)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Create and show the main window
        window = AgentlessDashboard(config_path=config_path)
        window.show()
        
        # Start the event loop
        with loop:
            sys.exit(loop.run_forever())
            
    except ImportError as e:
        print(f"Error: {e}")
        print("Please install the required dependencies:")
        print("pip install pyyaml PyQt5 qasync")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Agentless Monitoring Dashboard')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    args = parser.parse_args()
    
    sys.exit(main(config_path=args.config))
