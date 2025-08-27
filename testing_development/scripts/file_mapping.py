"""File mapping for SIEM project reorganization."""

# Format: {"source": "destination"}
FILE_MAPPING = {
    # Core application
    "main.py": "siem/__main__.py",
    "setup.py": "siem/setup.py",
    "requirements.txt": "siem/requirements.txt",
    
    # Core modules
    "core/": "siem/core/",
    "models/": "siem/models/",
    "services/": "siem/services/",
    "api/": "siem/api/",
    "views/": "siem/ui/views/",
    "managers/": "siem/core/managers/",
    
    # Security modules
    "edr/": "security_modules/edr/",
    "dlp/": "security_modules/dlp/",
    "fim/": "security_modules/fim/",
    "ndr/": "security_modules/ndr/",
    "nips/": "security_modules/nips/",
    "hips/": "security_modules/hips/",
    "ueba/": "security_modules/ueba/",
    
    # Infrastructure
    "config/": "infrastructure/config/",
    "migrations/": "infrastructure/database/migrations/",
    "deployments/": "infrastructure/deployments/",
    "utils/": "infrastructure/utils/",
    
    # Testing & Development
    "tests/": "testing_development/tests/",
    "scripts/": "testing_development/scripts/",
    "docs/": "testing_development/docs/",
    
    # Data & Logs (will be handled separately)
    "data/": "data_logs/data/",
    "logs/": "data_logs/logs/",
    "db_backups/": "data_logs/backups/"
}

# Files to exclude from copying
EXCLUDE_FILES = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".DS_Store",
    "*.db",
    "*.log",
    "*.bak",
    "*.swp",
    "*.swo"
]
