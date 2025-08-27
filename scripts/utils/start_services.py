"""
Start EDR and SIEM Services

This script starts both the EDR and SIEM services using their respective launchers.
"""
import os
import sys
import time
import logging
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('services.log')
    ]
)
logger = logging.getLogger('services_launcher')

def run_service(script_name, service_name):
    """Run a service script and return the process."""
    try:
        cmd = [sys.executable, script_name]
        logger.info(f"Starting {service_name} service: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        return process
    except Exception as e:
        logger.error(f"Failed to start {service_name}: {e}")
        return None

def main():
    """Main entry point."""
    # Get the project root directory
    project_root = Path(__file__).parent.absolute()
    
    # Start SIEM service
    siem_process = run_service('launch_siem.py', 'SIEM')
    if not siem_process:
        logger.error("Failed to start SIEM service")
        return 1
    
    # Start EDR service (using minimal launcher as fallback)
    edr_process = run_service('launch_minimal.py', 'EDR')
    if not edr_process:
        logger.error("Failed to start EDR service")
        siem_process.terminate()
        return 1
    
    try:
        logger.info("Both services started. Press Ctrl+C to stop.")
        
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
    sys.exit(main())
