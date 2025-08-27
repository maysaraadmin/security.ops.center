from setuptools import setup, find_packages

setup(
    name="siem",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        # List your dependencies here
        "psutil>=5.9.0",
        "python-dateutil>=2.8.2",
        "pyyaml>=6.0.1",
        "requests>=2.28.1",
        "python-json-logger>=2.0.4",
        "pywin32>=300; sys_platform == 'win32'",
        "pypiwin32>=223; sys_platform == 'win32'"
    ],
    python_requires=">=3.8",
)
