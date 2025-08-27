"""
Test script to run a minimal SIEM web interface for testing.
"""
import os
import sys
from flask import Flask, render_template_string

# Create a basic Flask app
app = Flask(__name__)

# Simple route to test the web interface
@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
            .content { margin-top: 20px; }
            .event-list { border: 1px solid #ddd; border-radius: 5px; padding: 15px; }
            .event { padding: 10px; border-bottom: 1px solid #eee; }
            .event:last-child { border-bottom: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Operations Center</h1>
                <p>SIEM Dashboard</p>
            </div>
            
            <div class="content">
                <h2>Recent Security Events</h2>
                <div class="event-list">
                    <div class="event">
                        <strong>Event 1:</strong> User login detected
                    </div>
                    <div class="event">
                        <strong>Event 2:</strong> File modification detected
                    </div>
                    <div class="event">
                        <strong>Event 3:</strong> Network connection established
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("Starting SIEM web interface on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
