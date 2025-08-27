import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Now import and run the dashboard
from siem.web.unified_dashboard import app

if __name__ == '__main__':
    print("Starting SIEM Dashboard...")
    print("Please open http://localhost:5000 in your browser")
    app.run(host='0.0.0.0', port=5000, debug=True)
