"""
SOC Component Launcher

This script provides a unified way to launch individual SOC components or all of them together.
"""

import argparse
import importlib
import logging
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Type

# Add the project root to the Python path
project_root = str(Path(__file__).absolute().parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Component configurations
COMPONENTS = {
    'siem': {
        'module': 'src.siem.launcher',
        'class_name': 'SIEMLauncher',
        'description': 'Security Information and Event Management',
        'default_config': 'config/siem_config.yaml'
    },
    'edr': {
        'module': 'src.edr.launcher',
        'class_name': 'EDRLauncher',
        'description': 'Endpoint Detection and Response',
        'default_config': 'config/edr_config.yaml'
    },
    'dlp': {
        'module': 'src.dlp.launcher',
        'class_name': 'DLPLauncher',
        'description': 'Data Loss Prevention',
        'default_config': 'config/dlp_config.yaml'
    },
    'fim': {
        'module': 'src.fim.launcher',
        'class_name': 'FIMLauncher',
        'description': 'File Integrity Monitoring',
        'default_config': 'config/fim_config.yaml'
    },
    'hips': {
        'module': 'src.hips.launcher',
        'class_name': 'HIPSLauncher',
        'description': 'Host-based Intrusion Prevention System',
        'default_config': 'config/hips_config.yaml'
    },
    'nips': {
        'module': 'src.nips.launcher',
        'class_name': 'NIPSLauncher',
        'description': 'Network Intrusion Prevention System',
        'default_config': 'config/nips_config.yaml'
    },
}

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file.
        
    Returns:
        Dictionary containing the configuration.
    """
    import yaml
    
    if not config_path:
        return {}
        
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logging.error(f"Failed to load configuration from {config_path}: {e}")
        return {}

def setup_logging(config: Dict[str, Any], component: str = 'soc') -> None:
    """Set up logging configuration.
    
    Args:
        config: Logging configuration dictionary.
        component: Component name for log file naming.
    """
    log_config = config.get('logging', {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': f'{component}.log'
    })
    
    logging.basicConfig(
        level=getattr(logging, log_config.get('level', 'INFO')),
        format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_config.get('file', f'{component}.log'))
        ]
    )

def get_launcher_class(component: str) -> Optional[Type]:
    """Get the launcher class for a component.
    
    Args:
        component: Component name.
        
    Returns:
        The launcher class if found, None otherwise.
    """
    if component not in COMPONENTS:
        logging.error(f"Unknown component: {component}")
        return None
        
    try:
        module = importlib.import_module(COMPONENTS[component]['module'])
        return getattr(module, COMPONENTS[component]['class_name'])
    except (ImportError, AttributeError) as e:
        logging.error(f"Failed to import launcher for {component}: {e}")
        return None

def run_component(component: str, config_path: Optional[str] = None) -> bool:
    """Run a single component.
    
    Args:
        component: Component name.
        config_path: Path to the configuration file.
        
    Returns:
        True if the component ran successfully, False otherwise.
    """
    # Load configuration
    config = load_config(config_path or COMPONENTS[component]['default_config'])
    
    # Set up logging
    setup_logging(config, component)
    logger = logging.getLogger(f'soc.{component}')
    
    # Get and initialize the launcher
    launcher_class = get_launcher_class(component)
    if not launcher_class:
        return False
        
    try:
        launcher = launcher_class(config)
        logger.info(f"Starting {component.upper()} component")
        return launcher.run()
    except Exception as e:
        logger.error(f"Error running {component}: {e}", exc_info=True)
        return False

def run_all_components(config_dir: str = 'config') -> bool:
    """Run all components.
    
    Args:
        config_dir: Directory containing configuration files.
        
    Returns:
        True if all components ran successfully, False otherwise.
    """
    import threading
    import time
    
    threads = []
    results = {}
    
    def run_component_thread(component: str):
        config_path = str(Path(config_dir) / f"{component}_config.yaml")
        results[component] = run_component(component, config_path)
    
    # Start all components in separate threads
    for component in COMPONENTS:
        thread = threading.Thread(
            target=run_component_thread,
            args=(component,),
            name=f"{component}-thread",
            daemon=True
        )
        thread.start()
        threads.append(thread)
        time.sleep(1)  # Stagger component startup
    
    # Wait for all threads to complete
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nShutting down all components...")
        return False
    
    # Check results
    success = all(results.values())
    if success:
        print("All components completed successfully")
    else:
        failed = [c for c, r in results.items() if not r]
        print(f"Some components failed: {', '.join(failed)}")
    
    return success

def list_components() -> None:
    """List all available components."""
    print("\nAvailable components:")
    print("-" * 50)
    for name, info in COMPONENTS.items():
        print(f"{name.upper():<8} - {info['description']}")
        print(f"  Module: {info['module']}.{info['class_name']}")
        print(f"  Config: {info['default_config']}")
        print()

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='SOC Component Launcher')
    
    # Add subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run components')
    run_parser.add_argument(
        'components', 
        nargs='*', 
        default=['all'],
        help='Components to run (default: all)'
    )
    run_parser.add_argument(
        '--config', 
        help='Path to configuration file or directory (for all components)'
    )
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available components')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle commands
    if args.command == 'run':
        if 'all' in args.components or not args.components:
            print("Starting all SOC components...")
            success = run_all_components(args.config)
        else:
            success = True
            for component in args.components:
                if component not in COMPONENTS:
                    print(f"Unknown component: {component}")
                    success = False
                    continue
                    
                print(f"Starting {component.upper()} component...")
                if not run_component(component, args.config):
                    success = False
        
        sys.exit(0 if success else 1)
        
    elif args.command == 'list':
        list_components()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
