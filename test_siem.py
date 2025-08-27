import sys
from src.siem.web import create_app

def test_siem():
    try:
        # Create the app with default configuration
        app = create_app()
        
        # Print routes
        print("\nAvailable routes:")
        for rule in app.url_map.iter_rules():
            print(f"- {rule.endpoint}: {rule.rule}")
            
        print("\n✅ SIEM web interface is ready to start!")
        print("Run the following command to start the server:")
        print("python -m src.siem.web.run")
        
    except Exception as e:
        print(f"❌ Error testing SIEM: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(test_siem())
