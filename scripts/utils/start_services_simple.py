"""
Simple Service Launcher

Starts SIEM and EDR services in the correct order.
"""
import os
import sys
import time
import subprocess
import signal
from pathlib import Path

# Configure logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('service_launcher.log')
    ]
)
logger = logging.getLogger('service_launcher')

def run_service(command, name):
    """Run a service in a subprocess and return the process object."""
    try:
        logger.info(f"Starting {name} service...")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        logger.info(f"{name} service started with PID {process.pid}")
        return process
    except Exception as e:
        logger.error(f"Failed to start {name} service: {e}")
        return None

def main():
    """Main function to start and manage services."""
    # Start the web-enabled SIEM service
    siem_process = run_service(
        [sys.executable, "web_siem.py"],
        "SIEM"
    )
    
    if not siem_process:
        logger.error("Failed to start SIEM service")
        return 1
    
    # Give SIEM some time to initialize
    logger.info("Waiting for SIEM to initialize...")
    time.sleep(5)
    
    # Start the simple EDR service
    edr_process = run_service(
        [sys.executable, "simple_edr.py"],
        "EDR"
    )
    
    if not edr_process:
        logger.error("Failed to start EDR service")
        siem_process.terminate()
        return 1
    
    # Set up signal handler for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received. Stopping services...")
        for proc, name in [(siem_process, "SIEM"), (edr_process, "EDR")]:
            if proc and proc.poll() is None:
                logger.info(f"Stopping {name} service...")
                proc.terminate()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Monitor processes
    try:
        logger.info("Services are running. Press Ctrl+C to stop.")
        while True:
            # Check if processes are still running
            if siem_process.poll() is not None:
                logger.error("SIEM service has stopped")
                break
                
            if edr_process.poll() is not None:
                logger.error("EDR service has stopped")
                break
            
            # Log output from services
            for process, name in [(siem_process, "SIEM"), (edr_process, "EDR")]:
                output = process.stdout.readline()
                if output:
                    logger.info(f"{name}: {output.strip()}")
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    
    finally:
        # Terminate processes
        for process, name in [(siem_process, "SIEM"), (edr_process, "EDR")]:
            if process and process.poll() is None:
                logger.info(f"Stopping {name} service...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"{name} service did not stop gracefully, forcing...")
                    process.kill()
        
        logger.info("All services have been stopped")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
