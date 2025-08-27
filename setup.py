from setuptools import setup, find_packages

setup(
    name="siem",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'flask>=2.0.1',
        'pywin32>=300',
        'psutil>=5.9.0',
        'pyyaml>=6.0',
    ],
    entry_points={
        'console_scripts': [
            'siem-collector=siem.collectors.cli:main',
            'siem-web=siem.web.server:main',
        ],
    },
    include_package_data=True,
    python_requires='>=3.6',
)
