"""
Start Script for EDR Agent with Web Interface
-------------------------------------------
This script starts both the EDR agent and the web interface.
"""
import os
import sys
import subprocess
import time
import webbrowser
from pathlib import Path

# Configuration
HOST = '127.0.0.1'  # Changed from 0.0.0.0 for better compatibility on Windows
PORT = 5000
EDR_AGENT_SCRIPT = 'start_edr.py'
WEB_APP_SCRIPT = 'web/app_enhanced.py'
REQUIREMENTS_FILE = 'web/requirements-web.txt'

# ANSI color codes for console output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header():
    """Print the application header."""
    print(f"{Colors.HEADER}{'='*60}")
    print(f"{'EDR Agent with Web Interface'.center(60)}")
    print(f"{'='*60}{Colors.ENDC}\n")

def check_requirements():
    """Check if all required Python packages are installed."""
    print(f"{Colors.OKBLUE}[*] Checking requirements...{Colors.ENDC}")
    try:
        with open(REQUIREMENTS_FILE, 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        import pkg_resources
        installed_packages = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
        missing_packages = []
        
        for req in requirements:
            req_name = req.split('==')[0].lower()
            if req_name not in installed_packages:
                missing_packages.append(req_name)
        
        if missing_packages:
            print(f"{Colors.WARNING}[!] Missing required packages: {', '.join(missing_packages)}{Colors.ENDC}")
            install = input("Do you want to install missing packages? (y/n): ").strip().lower()
            if install == 'y':
                print(f"{Colors.OKBLUE}[*] Installing missing packages...{Colors.ENDC}")
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', REQUIREMENTS_FILE])
                print(f"{Colors.OKGREEN}[+] Successfully installed all required packages{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}[!] Some required packages are missing. The application may not work correctly.{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}[+] All required packages are installed{Colors.ENDC}")
            
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error checking requirements: {e}{Colors.ENDC}")
        return False
    
    return True

def start_edr_agent():
    """Start the EDR agent in a separate process."""
    print(f"{Colors.OKBLUE}[*] Starting EDR Agent...{Colors.ENDC}")
    
    try:
        # Check if the EDR agent script exists
        if not os.path.exists(EDR_AGENT_SCRIPT):
            print(f"{Colors.FAIL}[!] EDR agent script not found: {EDR_AGENT_SCRIPT}{Colors.ENDC}")
            return None
        
        # Start the EDR agent in a separate process
        edr_process = subprocess.Popen(
            [sys.executable, EDR_AGENT_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Wait a moment to check if the process started successfully
        time.sleep(2)
        
        if edr_process.poll() is not None:
            # Process has already terminated
            _, stderr = edr_process.communicate()
            print(f"{Colors.FAIL}[!] Failed to start EDR agent:{Colors.ENDC}")
            print(stderr)
            return None
        
        print(f"{Colors.OKGREEN}[+] EDR Agent started successfully (PID: {edr_process.pid}){Colors.ENDC}")
        return edr_process
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error starting EDR agent: {e}{Colors.ENDC}")
        return None

def start_web_interface():
    """Start the web interface in a separate process."""
    print(f"{Colors.OKBLUE}[*] Starting Web Interface...{Colors.ENDC}")
    
    try:
        # Check if the web app script exists
        if not os.path.exists(WEB_APP_SCRIPT):
            print(f"{Colors.FAIL}[!] Web application script not found: {WEB_APP_SCRIPT}{Colors.ENDC}")
            return None
        
        # Set environment variables for the web app
        env = os.environ.copy()
        env['FLASK_APP'] = 'app_enhanced.py'
        env['FLASK_ENV'] = 'development'
        env['PYTHONPATH'] = os.path.dirname(os.path.abspath(__file__))
        
        # Start the web app in a separate process
        web_process = subprocess.Popen(
            [sys.executable, WEB_APP_SCRIPT],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Wait a moment to check if the process started successfully
        time.sleep(3)
        
        if web_process.poll() is not None:
            # Process has already terminated
            _, stderr = web_process.communicate()
            print(f"{Colors.FAIL}[!] Failed to start web interface:{Colors.ENDC}")
            print(stderr)
            return None
        
        print(f"{Colors.OKGREEN}[+] Web Interface started successfully (PID: {web_process.pid}){Colors.ENDC}")
        return web_process
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error starting web interface: {e}{Colors.ENDC}")
        return None

def open_browser():
    """Open the default web browser to the web interface."""
    url = f'http://{HOST}:{PORT}'
    print(f"{Colors.OKBLUE}[*] Opening web browser to: {url}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] If the page doesn't load, try: http://localhost:{PORT}{Colors.ENDC}")
    
    try:
        webbrowser.open(url)
        print(f"{Colors.OKGREEN}[+] Web browser opened successfully{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.WARNING}[!] Failed to open web browser: {e}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Please open your browser and navigate to: {url}{Colors.ENDC}")

def main():
    """Main function to start the EDR agent and web interface."""
    print_header()
    
    # Check requirements
    if not check_requirements():
        print(f"{Colors.FAIL}[!] Exiting due to missing requirements{Colors.ENDC}")
        sys.exit(1)
    
    # Start EDR agent
    edr_process = start_edr_agent()
    if not edr_process:
        print(f"{Colors.FAIL}[!] Failed to start EDR agent. Exiting...{Colors.ENDC}")
        sys.exit(1)
    
    # Start web interface
    web_process = start_web_interface()
    if not web_process:
        print(f"{Colors.FAIL}[!] Failed to start web interface. Exiting...{Colors.ENDC}")
        edr_process.terminate()
        sys.exit(1)
    
    # Open browser
    open_browser()
    
    print(f"\n{Colors.OKGREEN}{'='*60}")
    print(f"{'EDR Agent and Web Interface are running!'.center(60)}")
    print(f"{'='*60}{Colors.ENDC}")
    print(f"\n{Colors.BOLD}Access the web interface at:{Colors.ENDC} {Colors.UNDERLINE}http://{HOST}:{PORT}{Colors.ENDC}")
    print(f"{Colors.BOLD}Default credentials:{Colors.ENDC}")
    print(f"  - Username: {Colors.OKBLUE}admin{Colors.ENDC}")
    print(f"  - Password: {Colors.OKBLUE}admin{Colors.ENDC}")
    print(f"\n{Colors.WARNING}Press Ctrl+C to stop the application...{Colors.ENDC}")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[*] Shutting down...{Colors.ENDC}")
        
        # Terminate processes
        if edr_process:
            print(f"{Colors.OKBLUE}[*] Stopping EDR Agent...{Colors.ENDC}")
            edr_process.terminate()
            try:
                edr_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                edr_process.kill()
            print(f"{Colors.OKGREEN}[+] EDR Agent stopped{Colors.ENDC}")
        
        if web_process:
            print(f"{Colors.OKBLUE}[*] Stopping Web Interface...{Colors.ENDC}")
            web_process.terminate()
            try:
                web_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                web_process.kill()
            print(f"{Colors.OKGREEN}[+] Web Interface stopped{Colors.ENDC}")
        
        print(f"\n{Colors.OKGREEN}[+] Application has been stopped{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
