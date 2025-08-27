# File Integrity Monitoring (FIM) System

The File Integrity Monitoring (FIM) system provides real-time monitoring of files, directories, and registry keys for unauthorized changes. It includes advanced ransomware detection capabilities to identify potential security threats.

## Features

- **Real-time Monitoring**: Monitor files, directories, and registry keys for changes
- **Ransomware Detection**: Advanced heuristics to detect potential ransomware activity
- **Customizable Alerts**: Configure alerts for specific types of changes
- **Baseline Management**: Create and manage baselines for file integrity checking
- **Cross-platform**: Works on Windows, Linux, and macOS

## Components

### Core Components

- `core.py`: Main FIM engine and event handling
- `monitors/`: Platform-specific monitoring implementations
  - `windows.py`: Windows-specific monitoring
  - `linux.py`: Linux-specific monitoring
  - `darwin.py`: macOS-specific monitoring
- `ransomware_detector.py`: Ransomware detection engine
- `handlers.py`: Event handlers for different types of events

### Ransomware Detection

The ransomware detection system looks for the following patterns:

- **Suspicious File Extensions**: Common ransomware extensions (.encrypted, .locked, .crypt, etc.)
- **High File Activity**: Unusually high number of file modifications in a short time
- **Suspicious Locations**: Modifications in sensitive system directories
- **Suspicious Processes**: Known suspicious processes performing file operations
- **Extension Changes**: Mass file extension changes

## Usage

### Basic Usage

```python
from fim.core import FIMEngine

def handle_event(event):
    print(f"[EVENT] {event.event_type.name}: {event.src_path}")

# Initialize the FIM engine
engine = FIMEngine()

# Add event handler
engine.add_handler(handle_event)

# Add paths to monitor
engine.add_monitor("/path/to/monitor", recursive=True)

# Create baseline and start monitoring
engine.create_baseline()
engine.start()

# Keep the script running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    engine.stop()
```

### Ransomware Detection

```python
from fim.core import FIMEngine

def handle_alert(alert):
    print(f"[ALERT] {alert['severity'].upper()}: {alert['message']}")
    print(f"File: {alert.get('file_path', 'N/A')}")

# Initialize with ransomware detection
config = {
    'enable_ransomware_detection': True,
    'ransomware_config': {
        'file_mod_threshold': 100,  # Alert if >100 files modified per minute
        'extension_change_threshold': 20,  # Alert if >20 extensions changed per minute
    }
}

engine = FIMEngine(config)
engine.add_alert_callback(handle_alert)

# Add paths to monitor and start
engine.add_monitor("/sensitive/data", recursive=True)
engine.create_baseline()
engine.start()
```

## Configuration

The FIM engine can be configured using a dictionary with the following options:

```python
config = {
    'baseline_file': 'fim_baseline.json',
    'hash_algorithm': 'sha256',
    'enable_ransomware_detection': True,
    'ransomware_config': {
        'file_mod_threshold': 100,
        'extension_change_threshold': 20,
    },
    'exclude_patterns': ['*.tmp', '*.log', '*.bak'],
    'include_patterns': ['*'],  # Only monitor files matching these patterns
}
```

## Demo

A demo script is available in `examples/fim_demo.py`:

```bash
python examples/fim_demo.py /path/to/monitor
```

## Requirements

- Python 3.7+
- watchdog (for cross-platform monitoring)
- pywin32 (Windows only)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
