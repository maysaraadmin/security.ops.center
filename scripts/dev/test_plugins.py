"""
Test script to verify plugin loading.
"""
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Test importing plugins
print("Testing plugin imports...")
try:
    from src.siem.plugins import sysmon, windows_events, firewall
    print("✅ Successfully imported all plugins!")
    
    # Test creating plugin instances
    print("\nTesting plugin creation...")
    sysmon_plugin = sysmon.create_plugin({})
    windows_plugin = windows_events.create_plugin({"channels": ["Security"]})
    firewall_plugin = firewall.create_plugin({"log_path": "/var/log/ufw.log"})
    
    print(f"✅ Successfully created plugin instances:")
    print(f"- {sysmon_plugin.__class__.__name__}")
    print(f"- {windows_plugin.__class__.__name__}")
    print(f"- {firewall_plugin.__class__.__name__}")
    
except Exception as e:
    print(f"❌ Error: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()

# Test plugin discovery
print("\nTesting plugin discovery...")
plugin_dir = os.path.join("src", "siem", "plugins")
print(f"Looking for plugins in: {os.path.abspath(plugin_dir)}")

if os.path.exists(plugin_dir):
    print("Found these Python files in the plugins directory:")
    for f in os.listdir(plugin_dir):
        if f.endswith('.py') and not f.startswith('__'):
            print(f"- {f}")
else:
    print(f"❌ Directory not found: {plugin_dir}")

print("\nTest complete!")
