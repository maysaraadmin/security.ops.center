import requests
import json

try:
    # Test the root endpoint
    print("Testing root endpoint...")
    response = requests.get('http://127.0.0.1:5000/')
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text[:200]}")
    
    # Test the API status endpoint
    print("\nTesting API status endpoint...")
    response = requests.get('http://127.0.0.1:5000/api/status')
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
except requests.exceptions.RequestException as e:
    print(f"Error making request: {e}")
