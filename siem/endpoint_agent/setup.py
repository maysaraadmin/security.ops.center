from setuptools import setup, find_packages
import os
import sys

# Read the contents of README.md
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Define package version
VERSION = '1.0.0'

# Define package data
package_data = {
    'siem.endpoint_agent': [
        'config.yaml',
        '*.pem',  # For certificates
    ]
}

# Platform-specific dependencies
extras_require = {
    'windows': ['pywin32>=305', 'wmi>=1.5.1', 'pycryptodomex>=3.15.0'],
    'linux': ['python-prctl>=1.8.1'],
    'darwin': ['pyobjc-framework-SystemConfiguration>=9.0.1'],
}

# Common dependencies
install_requires = [
    'python-dateutil>=2.8.2',
    'pyyaml>=6.0',
    'psutil>=5.9.0',
    'requests>=2.28.1',
    'cryptography>=38.0.1',
    'netifaces>=0.11.0',
    'py-cpuinfo>=9.0.0',
    'distro>=1.8.0',
]

# Add platform-specific dependencies
if sys.platform == 'win32':
    install_requires.extend(extras_require['windows'])
elif sys.platform.startswith('linux'):
    install_requires.extend(extras_require['linux'])
elif sys.platform == 'darwin':
    install_requires.extend(extras_require['darwin'])

# Development dependencies
extras_require['dev'] = [
    'pytest>=7.2.0',
    'pytest-cov>=4.0.0',
    'black>=22.12.0',
    'flake8>=6.0.0',
    'mypy>=0.991',
    'sphinx>=6.1.1',
    'sphinx-rtd-theme>=1.2.0',
    'pre-commit>=3.0.0',
]

setup(
    name='siem-endpoint-agent',
    version=VERSION,
    description='SIEM Endpoint Agent for collecting and forwarding system logs and security events',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Security Ops Center',
    author_email='security@example.com',
    url='https://github.com/your-org/siem-endpoint-agent',
    packages=find_packages(include=['siem', 'siem.endpoint_agent*']),
    package_data=package_data,
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        'console_scripts': [
            'siem-agent=siem.endpoint_agent.agent:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Systems Administration',
    ],
    python_requires='>=3.7',
    keywords='siem security monitoring logging endpoint',
    project_urls={
        'Documentation': 'https://siem-endpoint-agent.readthedocs.io',
        'Source': 'https://github.com/your-org/siem-endpoint-agent',
        'Bug Reports': 'https://github.com/your-org/siem-endpoint-agent/issues',
    },
)
