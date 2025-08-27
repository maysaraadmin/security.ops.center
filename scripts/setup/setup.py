from setuptools import setup, find_packages

setup(
    name="security-operations-center",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        # Core Dependencies
        "python-dateutil>=2.8.2",
        "pytz>=2021.3",
        "pyyaml>=6.0.1",
        "requests>=2.28.1",
        "python-json-logger>=2.0.4",
        "pywin32>=300; sys_platform == 'win32'",
        "pypiwin32>=223; sys_platform == 'win32'",
        
        # Network & Security
        "scapy>=2.5.0",
        "ipaddress>=1.0.23",
        "watchdog>=2.1.6",
        "psutil>=5.9.0",
        "dnspython>=2.2.1",
        "yara-python>=4.2.3",
        "pycryptodome>=3.15.0",
        "python-jose[cryptography]>=3.3.0",
        
        # File & Data Processing
        "pandas>=1.3.5",
        "numpy>=1.21.6",
        "python-magic>=0.4.27",
        "filetype>=1.0.7",
        "python-magic-bin>=0.4.14; sys_platform == 'win32'",
        
        # Web & API
        "flask>=2.1.3",
        "flask-cors>=3.0.10",
        "gunicorn>=20.1.0",
        "passlib[bcrypt]>=1.7.4",
        "python-multipart>=0.0.5",
        
        # Database
        "sqlalchemy>=1.4.42",
        "psycopg2-binary>=2.9.3",
        "redis>=4.3.4",
        
        # Monitoring & Metrics
        "prometheus-client>=0.14.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.1.2",
            "pytest-cov>=3.0.0",
            "black>=22.8.0",
            "flake8>=5.0.4",
            "mypy>=0.971",
            "pylint>=2.14.5",
        ]
    },
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "soc=siem.core.cli:main",
        ],
    },
)
