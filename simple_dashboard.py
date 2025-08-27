"""
Simple SIEM Dashboard
A basic version to test the web server functionality.
"""
from flask import Flask, render_template_string, jsonify
import psutil
import platform
import datetime

app = Flask(__name__)

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { background-color: #d4edda; color: #155724; }
        .error { background-color: #f8d7da; color: #721c24; }
        .info { background-color: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SIEM Dashboard</h1>
        <div class="status success">
            <h2>Status: Running</h2>
            <p>Server time: {{ time }}</p>
        </div>
        <div class="status info">
            <h3>System Information</h3>
            <p>OS: {{ system_info.system }} {{ system_info.release }}</p>
            <p>CPU: {{ system_info.cpu }}%</p>
            <p>Memory: {{ system_info.memory }}%</p>
        </div>
        <div class="status info">
            <h3>SIEM Status</h3>
            <p>Dashboard is running successfully!</p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    system_info = {
        'system': platform.system(),
        'release': platform.release(),
        'cpu': psutil.cpu_percent(),
        'memory': psutil.virtual_memory().percent,
    }
    return render_template_string(
        HTML_TEMPLATE,
        time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        system_info=system_info
    )

if __name__ == '__main__':
    print("Starting SIEM Dashboard...")
    print("Please open http://localhost:5000 in your browser")
    app.run(host='0.0.0.0', port=5000, debug=True)
