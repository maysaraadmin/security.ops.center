import os
import shutil
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).parent

# New directory structure
DIR_STRUCTURE = {
    'src': {
        'edr': ['core', 'agent', 'detection', 'response', 'utils'],
        'web': ['api', 'auth', 'models', 'services', 'static', 'templates'],
        'utils': ['logging', 'config', 'helpers']
    },
    'config': ['env', 'rules', 'policies'],
    'docs': ['architecture', 'api', 'deployment', 'user_guides'],
    'tests': ['unit', 'integration', 'e2e'],
    'scripts': ['deployment', 'maintenance', 'setup'],
    'data': {'logs', 'db', 'reports', 'artifacts'},
    'deploy': ['docker', 'kubernetes', 'terraform'],
    'web': ['static', 'templates', 'js', 'css']
}

def create_directory_structure():
    """Create the directory structure for the project."""
    print("Creating directory structure...")
    
    for parent, children in DIR_STRUCTURE.items():
        # Create parent directory
        parent_path = PROJECT_ROOT / parent
        parent_path.mkdir(exist_ok=True)
        print(f"Created directory: {parent_path}")
        
        # Create child directories
        if isinstance(children, (list, set)):
            for child in children:
                child_path = parent_path / child
                child_path.mkdir(exist_ok=True)
                print(f"  └── {child}")
        elif isinstance(children, dict):
            for child, subchildren in children.items():
                child_path = parent_path / child
                child_path.mkdir(exist_ok=True)
                print(f"  └── {child}")
                for subchild in subchildren:
                    subchild_path = child_path / subchild
                    subchild_path.mkdir(exist_ok=True)
                    print(f"      └── {subchild}")
    
    print("\nDirectory structure created successfully!")

def organize_existing_files():
    """Reorganize existing files into the new structure."""
    print("\nReorganizing existing files...")
    
    # Example of how to move files (customize as needed)
    move_rules = [
        # (source, destination)
        ('web/static', 'web/static'),
        ('web/templates', 'web/templates'),
        ('edr', 'src/edr'),
        ('scripts', 'scripts'),
        ('config', 'config'),
        ('tests', 'tests'),
        ('docs', 'docs')
    ]
    
    for src, dst in move_rules:
        src_path = PROJECT_ROOT / src
        dst_path = PROJECT_ROOT / dst
        
        if src_path.exists():
            if src_path.is_file():
                shutil.move(str(src_path), str(dst_path / src_path.name))
                print(f"Moved {src_path} to {dst_path}/")
            else:
                for item in src_path.glob('*'):
                    if item.is_file():
                        shutil.move(str(item), str(dst_path / item.name))
                        print(f"Moved {item} to {dst_path}/")
    
    print("\nFiles reorganized successfully!")

def create_requirements_file():
    """Create a consolidated requirements file."""
    requirements = {
        'Flask==2.3.3',
        'Flask-SocketIO==5.3.5',
        'Flask-Login==0.6.2',
        'Flask-WTF==1.2.1',
        'python-dotenv==1.0.0',
        'psutil==5.9.5',
        'python-dateutil==2.8.2',
        'pywin32>=311; sys_platform == "win32"',
        'gevent==22.10.2',
        'gevent-websocket==0.10.1',
        'python-engineio==4.6.1',
        'python-socketio==5.8.0',
        'Werkzeug==2.3.7',
        'requests==2.31.0',
        'PyJWT==2.8.0',
        'gunicorn==21.2.0; sys_platform != "win32"',
        'eventlet==0.33.3; sys_platform != "win32"',
        'Flask-SQLAlchemy==3.0.5',
        'Flask-Migrate==4.0.5',
        'Flask-Cors==4.0.0',
        'Flask-Bcrypt==1.0.1',
        'email-validator==2.0.0.post2',
        'pandas==2.0.3',
        'numpy==1.24.3',
        'matplotlib==3.7.2'
    }
    
    with open(PROJECT_ROOT / 'requirements.txt', 'w') as f:
        f.write("# Core dependencies\n")
        f.write("\n".join(sorted(requirements)))
        f.write("\n")
    
    print("\nRequirements file created successfully!")

def create_readme():
    """Create a basic README.md file."""
    readme_content = """# Security Operations Center (SOC) EDR Solution

## Project Structure

```
.
├── config/               # Configuration files
│   ├── env/             # Environment variables
│   ├── rules/           # Detection rules
│   └── policies/        # Security policies
├── data/                # Data storage
│   ├── db/              # Database files
│   ├── logs/            # Application logs
│   └── reports/         # Generated reports
├── docs/                # Documentation
│   ├── api/             # API documentation
│   ├── architecture/    # System architecture
│   └── user_guides/     # User guides
├── scripts/             # Utility scripts
│   ├── deployment/      # Deployment scripts
│   ├── maintenance/     # Maintenance scripts
│   └── setup/           # Setup scripts
├── src/                 # Source code
│   ├── edr/             # EDR core functionality
│   ├── utils/           # Utility functions
│   └── web/             # Web interface
├── tests/               # Test suites
│   ├── unit/            # Unit tests
│   ├── integration/     # Integration tests
│   └── e2e/             # End-to-end tests
└── web/                 # Web application
    ├── static/          # Static files (CSS, JS, images)
    └── templates/       # HTML templates

## Getting Started

### Prerequisites
- Python 3.8+
- pip

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd security.ops.center
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # Windows
   .\\venv\\Scripts\\activate  
   
   # Linux/Mac
   source venv/bin/activate  
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Run the application:
   ```bash
   python -m src.web.app
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
"""
    
    with open(PROJECT_ROOT / 'README.md', 'w') as f:
        f.write(readme_content)
    
    print("\nREADME.md created successfully!")

if __name__ == "__main__":
    print("Starting project organization...\n")
    create_directory_structure()
    organize_existing_files()
    create_requirements_file()
    create_readme()
    print("\nProject organization complete!")
