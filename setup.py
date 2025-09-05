from setuptools import setup, find_packages

setup(
    name="security-ops-center",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'PyQt5>=5.15.0',
    ],
    entry_points={
        'console_scripts': [
            'dlp-gui=dlp.dlp_gui:main',
            'edr-gui=edr.edr_gui:main',
            'edr-agent-gui=edr.edr_agent_gui:main',
        ],
    },
)
