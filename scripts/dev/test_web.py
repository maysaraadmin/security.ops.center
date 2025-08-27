"""
Test Web Interface

A simple Flask app to test the web interface.
"""
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    """Render the test page."""
    status = {
        'status': 'running',
        'components': {
            'log_collector': {'status': 'running'},
            'correlation_engine': {'status': 'running'},
            'dummy_component': {'status': 'stopped'},
        }
    }
    return render_template('test.html', **status)

if __name__ == '__main__':
    print("Starting test web server...")
    print(" * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)")
    app.run(debug=True)
