from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="security-ops-center",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=requirements,
    python_requires=">=3.8",
    
    # Metadata
    author="Your Name",
    author_email="your.email@example.com",
    description="Security Operations Center with EDR capabilities",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/security.ops.center",
    
    # Entry points
    entry_points={
        'console_scripts': [
            'soc-edr=edr.cli:main',
            'soc-web=web.app:main',
        ],
    },
    
    # Additional files
    include_package_data=True,
    package_data={
        '': ['*.yaml', '*.json', '*.html', '*.css', '*.js', '*.md'],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
