"""
EDR and SIEM Launcher

A simple launcher script that starts both EDR and SIEM services
using their respective launchers.
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
        logging.FileHandler('edr_siem_launch.log')
    ]
)
logger = logging.getLogger('edr_siem_launcher')

def run_command(command, cwd=None):
    """Run a command and log its output."""
    logger.info(f"Running command: {' '.join(command)}")
    return subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

def main():
    """Main entry point."""
    try:
        # Get the project root directory
        project_root = Path(__file__).parent.absolute()
        
        # Start EDR service in a separate process
        edr_script = project_root / 'launch_edr.py'
        if not edr_script.exists():
            logger.error(f"EDR launcher not found at {edr_script}")
            return 1
            
        logger.info("Starting EDR service...")
        edr_process = run_command([sys.executable, str(edr_script)])
        
        # Start SIEM service in a separate process
        siem_script = project_root / 'launch_siem.py'
        if not siem_script.exists():
            logger.error(f"SIEM launcher not found at {siem_script}")
            return 1
            
        logger.info("Starting SIEM service...")
        siem_process = run_command([sys.executable, str(siem_script)])
        
        # Monitor processes
        try:
            while True:
                # Check if either process has terminated
                if edr_process.poll() is not None:
                    logger.error("EDR service has stopped")
                    break
                    
                if siem_process.poll() is not None:
                    logger.error("SIEM service has stopped")
                    break
                    
                # Read and log output
                for process, name in [(edr_process, "EDR"), (siem_process, "SIEM")]:
                    output = process.stdout.readline()
                    if output:
                        logger.info(f"{name}: {output.strip()}")
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down services...")
            
        finally:
            # Terminate processes
            for process, name in [(edr_process, "EDR"), (siem_process, "SIEM")]:
                if process.poll() is None:  # If process is still running
                    logger.info(f"Stopping {name} service...")
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"{name} service did not terminate gracefully, forcing...")
                        process.kill()
            
            logger.info("All services have been stopped")
            
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
