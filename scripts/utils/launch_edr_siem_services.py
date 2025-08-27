"""
EDR and SIEM Services Launcher

A robust launcher for running both EDR and SIEM services with proper configuration.
"""
import os
import sys
import time
import signal
import logging
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('edr_siem_services.log')
    ]
)
logger = logging.getLogger('edr_siem_launcher')

def run_siem_service():
    """Run the SIEM service."""
    try:
        from src.siem.launcher import run_siem
        logger.info("Starting SIEM service...")
        return run_siem()
    except Exception as e:
        logger.error(f"Failed to start SIEM service: {e}", exc_info=True)
        return False

def run_edr_service():
    """Run the EDR service."""
    try:
        # Use the minimal launcher for EDR
        from launch_minimal import main as run_edr
        logger.info("Starting EDR service...")
        return run_edr()
    except Exception as e:
        logger.error(f"Failed to start EDR service: {e}", exc_info=True)
        return False

def main():
    """Main entry point."""
    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received. Stopping services...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting EDR and SIEM services...")
    
    # Start SIEM in a separate process
    siem_process = None
    try:
        siem_process = subprocess.Popen(
            [sys.executable, "launch_siem.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        logger.info("SIEM service started")
    except Exception as e:
        logger.error(f"Failed to start SIEM service: {e}")
        return 1
    
    # Start EDR in a separate process
    edr_process = None
    try:
        edr_process = subprocess.Popen(
            [sys.executable, "launch_minimal.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        logger.info("EDR service started")
    except Exception as e:
        logger.error(f"Failed to start EDR service: {e}")
        if siem_process:
            siem_process.terminate()
        return 1
    
    try:
        # Monitor processes
        while True:
            # Check if processes are still running
            if siem_process.poll() is not None:
                logger.error("SIEM service has stopped")
                break
                
            if edr_process.poll() is not None:
                logger.error("EDR service has stopped")
                break
            
            # Print output from both processes
            for process, name in [(siem_process, 'SIEM'), (edr_process, 'EDR')]:
                output = process.stdout.readline()
                if output:
                    logger.info(f"{name}: {output.strip()}")
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Stopping services...")
    
    finally:
        # Terminate processes
        for process, name in [(siem_process, 'SIEM'), (edr_process, 'EDR')]:
            if process and process.poll() is None:
                logger.info(f"Stopping {name} service...")
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning(f"{name} service did not stop gracefully, forcing...")
                    process.kill()
        
        logger.info("All services have been stopped")
    
    return 0

if __name__ == "__main__":
    # Add the project root to the Python path
    project_root = str(Path(__file__).parent.absolute())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    sys.exit(main())
