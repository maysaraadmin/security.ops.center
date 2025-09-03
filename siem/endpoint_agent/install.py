#!/usr/bin/env python3
"""
SIEM Endpoint Agent Installer
----------------------------
This script installs and configures the SIEM Endpoint Agent on the local system.
"""
import os
import sys
import shutil
import platform
import subprocess
import argparse
from pathlib import Path

# Configuration
PACKAGE_NAME = "siem-endpoint-agent"
SERVICE_NAME = "SIEMEndpointAgent"
CONFIG_DIR = {
    'Windows': r"C:\ProgramData\SIEM\endpoint_agent",
    'Linux': "/etc/siem/endpoint_agent",
    'Darwin': "/Library/Application Support/SIEM/endpoint_agent"
}
LOG_DIR = {
    'Windows': r"C:\ProgramData\SIEM\logs",
    'Linux': "/var/log/siem",
    'Darwin': "/var/log/siem"
}

# Colors for console output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.upper()}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")

def print_success(text: str) -> None:
    """Print a success message."""
    print(f"{Colors.OKGREEN}[+] {text}{Colors.ENDC}")

def print_warning(text: str) -> None:
    """Print a warning message."""
    print(f"{Colors.WARNING}[!] {text}{Colors.ENDC}")

def print_error(text: str) -> None:
    """Print an error message."""
    print(f"{Colors.FAIL}[-] {text}{Colors.ENDC}")

def print_info(text: str) -> None:
    """Print an info message."""
    print(f"{Colors.OKBLUE}[*] {text}{Colors.ENDC}")

def is_admin() -> bool:
    """Check if the script is running with admin/root privileges."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_platform() -> str:
    """Get the current platform."""
    system = platform.system()
    if system not in ['Windows', 'Linux', 'Darwin']:
        print_warning(f"Unsupported platform: {system}. Attempting to continue...")
    return system

def create_directory(path: str) -> bool:
    """Create a directory if it doesn't exist."""
    try:
        os.makedirs(path, exist_ok=True)
        print_success(f"Created directory: {path}")
        return True
    except Exception as e:
        print_error(f"Failed to create directory {path}: {e}")
        return False

def copy_file(src: str, dst: str) -> bool:
    """Copy a file from src to dst."""
    try:
        shutil.copy2(src, dst)
        print_success(f"Copied {src} to {dst}")
        return True
    except Exception as e:
        print_error(f"Failed to copy {src} to {dst}: {e}")
        return False

def install_dependencies() -> bool:
    """Install the required Python packages."""
    print_info("Installing dependencies...")
    
    try:
        # Check if pip is available
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Install the package in development mode
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print_success("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        print_error(f"STDOUT: {e.stdout}")
        print_error(f"STDERR: {e.stderr}")
        return False
    except Exception as e:
        print_error(f"Unexpected error installing dependencies: {e}")
        return False

def configure_agent(config_dir: str, log_dir: str, siem_server: str, 
                  siem_port: int, use_tls: bool, verify_ssl: bool) -> bool:
    """Create or update the agent configuration."""
    print_info("Configuring the agent...")
    
    config_path = os.path.join(config_dir, "config.yaml")
    
    # Create a basic configuration
    config = f"""# SIEM Endpoint Agent Configuration

# SIEM Server Configuration
siem_server: "{siem_server}"  # SIEM server hostname or IP
siem_port: {siem_port}        # SIEM server port
use_tls: {str(use_tls).lower()}           # Use TLS for communication
verify_ssl: {str(verify_ssl).lower()}        # Verify SSL/TLS certificates

# Logging Configuration
logging:
  level: INFO                # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "{os.path.join(log_dir, 'siem_agent.log')}"
  max_size: 10               # Max log file size in MB
  backup_count: 5            # Number of backup logs to keep

# Collector Configuration
collectors:
  windows_events:
    enabled: true
    channels:                # Windows Event Log channels to monitor
      - Security
      - System
      - Application
    
  sysmon:
    enabled: true            # Requires Sysmon to be installed
    
  system_info:
    enabled: true
    interval: 3600           # Collect system info every hour (in seconds)

# Advanced Settings
advanced:
  batch_size: 50             # Number of events to send in each batch
  max_retries: 3             # Maximum number of retries for failed sends
  retry_delay: 5             # Delay between retries (in seconds)
  heartbeat_interval: 300     # Send heartbeat every 5 minutes (in seconds)
  cache_dir: "{os.path.join(config_dir, 'cache')}"  # Directory for temporary files
"""
    
    try:
        with open(config_path, 'w') as f:
            f.write(config)
        print_success(f"Configuration saved to {config_path}")
        return True
    except Exception as e:
        print_error(f"Failed to write configuration: {e}")
        return False

def install_service(install_dir: str) -> bool:
    """Install the agent as a system service."""
    print_info("Installing the agent as a service...")
    
    system = get_platform()
    
    try:
        if system == 'Windows':
            return _install_windows_service(install_dir)
        else:
            return _install_linux_service(install_dir)
    except Exception as e:
        print_error(f"Failed to install service: {e}")
        return False

def _install_windows_service(install_dir: str) -> bool:
    """Install the agent as a Windows service."""
    try:
        # Install the service using NSSM (Non-Sucking Service Manager)
        nssm_exe = os.path.join(install_dir, "nssm.exe")
        
        # Download NSSM if it doesn't exist
        if not os.path.exists(nssm_exe):
            import urllib.request
            import zipfile
            import tempfile
            
            print_info("Downloading NSSM...")
            
            nssm_url = "https://nssm.cc/release/nssm-2.24.zip"
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, "nssm.zip")
            
            urllib.request.urlretrieve(nssm_url, zip_path)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find the correct executable (32-bit or 64-bit)
            arch = platform.architecture()[0]
            if arch == '64bit':
                src_exe = os.path.join(temp_dir, "nssm-2.24", "win64", "nssm.exe")
            else:
                src_exe = os.path.join(temp_dir, "nssm-2.24", "win32", "nssm.exe")
            
            shutil.copy(src_exe, nssm_exe)
            
            # Clean up
            shutil.rmtree(temp_dir)
        
        # Install the service
        python_exe = sys.executable
        script_path = os.path.join(install_dir, "siem", "endpoint_agent", "__main__.py")
        
        # Remove the service if it already exists
        subprocess.run([nssm_exe, "remove", SERVICE_NAME, "confirm"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Install the service
        subprocess.run([nssm_exe, "install", SERVICE_NAME, python_exe, script_path], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Configure the service
        subprocess.run([nssm_exe, "set", SERVICE_NAME, "AppDirectory", install_dir], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        subprocess.run([nssm_exe, "set", SERVICE_NAME, "Description", 
                       "SIEM Endpoint Agent - Collects and forwards system logs and security events"], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        subprocess.run([nssm_exe, "set", SERVICE_NAME, "Start", "SERVICE_AUTO_START"], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print_success("Windows service installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install Windows service: {e}")
        print_error(f"STDOUT: {e.stdout}")
        print_error(f"STDERR: {e.stderr}")
        return False
    except Exception as e:
        print_error(f"Unexpected error installing Windows service: {e}")
        return False

def _install_linux_service(install_dir: str) -> bool:
    """Install the agent as a Linux systemd service."""
    try:
        service_content = f"""[Unit]
Description=SIEM Endpoint Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={install_dir}
ExecStart={sys.executable} -m siem.endpoint_agent
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""
        service_path = "/etc/systemd/system/siem-endpoint-agent.service"
        
        with open(service_path, 'w') as f:
            f.write(service_content)
        
        # Reload systemd and enable the service
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "siem-endpoint-agent"], check=True)
        
        print_success("Linux service installed successfully")
        print_info("Start the service with: systemctl start siem-endpoint-agent")
        return True
        
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install Linux service: {e}")
        return False
    except Exception as e:
        print_error(f"Unexpected error installing Linux service: {e}")
        return False

def uninstall() -> None:
    """Uninstall the SIEM Endpoint Agent."""
    print_header("uninstalling siem endpoint agent")
    
    system = get_platform()
    config_dir = CONFIG_DIR.get(system, "/etc/siem/endpoint_agent")
    
    # Stop and remove the service
    try:
        if system == 'Windows':
            # Stop and remove the service using NSSM
            nssm_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nssm.exe")
            if os.path.exists(nssm_exe):
                subprocess.run([nssm_exe, "stop", SERVICE_NAME], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run([nssm_exe, "remove", SERVICE_NAME, "confirm"], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Remove NSSM
                try:
                    os.remove(nssm_exe)
                except Exception:
                    pass
        else:
            # Stop and disable the Linux service
            subprocess.run(["systemctl", "stop", "siem-endpoint-agent"], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["systemctl", "disable", "siem-endpoint-agent"], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Remove the service file
            service_path = "/etc/systemd/system/siem-endpoint-agent.service"
            if os.path.exists(service_path):
                os.remove(service_path)
            
            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print_success("Service removed successfully")
    except Exception as e:
        print_warning(f"Failed to remove service: {e}")
    
    # Remove the configuration directory
    try:
        if os.path.exists(config_dir):
            shutil.rmtree(config_dir)
            print_success(f"Removed configuration directory: {config_dir}")
    except Exception as e:
        print_warning(f"Failed to remove configuration directory: {e}")
    
    print_success("SIEM Endpoint Agent has been uninstalled")

def main():
    """Main function for the installer."""
    parser = argparse.ArgumentParser(description='SIEM Endpoint Agent Installer')
    
    # Installation options
    parser.add_argument('--uninstall', action='store_true', help='Uninstall the agent')
    parser.add_argument('--siem-server', default='siem.example.com', 
                       help='SIEM server hostname or IP')
    parser.add_argument('--siem-port', type=int, default=514, 
                       help='SIEM server port')
    parser.add_argument('--no-tls', action='store_true', 
                       help='Disable TLS for communication with the SIEM server')
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('--no-service', action='store_true',
                       help='Do not install as a service')
    
    args = parser.parse_args()
    
    # Check for admin/root privileges
    if not is_admin():
        print_error("This script requires administrator/root privileges.")
        print_info(f"Please run this script as an administrator or with sudo.")
        sys.exit(1)
    
    # Uninstall if requested
    if args.uninstall:
        uninstall()
        return
    
    # Get platform information
    system = get_platform()
    config_dir = CONFIG_DIR.get(system, "/etc/siem/endpoint_agent")
    log_dir = LOG_DIR.get(system, "/var/log/siem")
    
    # Get the installation directory (where this script is located)
    install_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Print installation header
    print_header(f"installing siem endpoint agent on {system}")
    print_info(f"Installation directory: {install_dir}")
    print_info(f"Configuration directory: {config_dir}")
    print_info(f"Log directory: {log_dir}")
    
    # Create required directories
    create_directory(config_dir)
    create_directory(log_dir)
    create_directory(os.path.join(config_dir, "certs"))
    
    # Install Python dependencies
    if not install_dependencies():
        print_error("Failed to install dependencies. Aborting installation.")
        sys.exit(1)
    
    # Configure the agent
    if not configure_agent(
        config_dir=config_dir,
        log_dir=log_dir,
        siem_server=args.siem_server,
        siem_port=args.siem_port,
        use_tls=not args.no_tls,
        verify_ssl=not args.no_verify_ssl
    ):
        print_error("Failed to configure the agent. Aborting installation.")
        sys.exit(1)
    
    # Install as a service if requested
    if not args.no_service:
        if not install_service(install_dir):
            print_warning("Failed to install the agent as a service. "
                         "You can still run it manually.")
    
    print_header("installation complete")
    print_success("SIEM Endpoint Agent has been installed successfully!")
    
    if not args.no_service:
        if system == 'Windows':
            print_info("The agent has been installed as a Windows service.")
            print_info("You can start it using the Services application or with:")
            print_info("  net start SIEMEndpointAgent")
        else:
            print_info("The agent has been installed as a systemd service.")
            print_info("Start the service with:")
            print_info("  systemctl start siem-endpoint-agent")
    else:
        print_info("You can run the agent manually with:")
        print_info(f"  {sys.executable} -m siem.endpoint_agent")
    
    print_info("\nCheck the logs at:")
    print_info(f"  {os.path.join(log_dir, 'siem_agent.log')}")

if __name__ == "__main__":
    main()
