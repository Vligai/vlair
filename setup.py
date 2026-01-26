#!/usr/bin/env python3
"""
Setup script for SecOps Helper

Install with: pip install -e .
Or: python setup.py install
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file) as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="secops-helper",
    version="2.0.0",
    author="Vligai",
    description="Security operations toolkit for threat analysis and incident response",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Vligai/secops-helper",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "black>=23.9.1",
            "flake8>=6.1.0",
            "isort>=5.12.0",
            "pre-commit>=3.4.0",
            "bandit>=1.7.5",
        ],
        "pcap": [
            "scapy>=2.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "secops-helper=secops_helper:main",
            "secops=secops_helper:main",  # Shorter alias
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.yml", "*.yaml", "*.ini", "*.toml"],
    },
    keywords=[
        "security",
        "secops",
        "threat-intelligence",
        "ioc",
        "incident-response",
        "soc",
        "malware-analysis",
        "cybersecurity",
    ],
    project_urls={
        "Bug Reports": "https://github.com/Vligai/secops-helper/issues",
        "Source": "https://github.com/Vligai/secops-helper",
        "Documentation": "https://github.com/Vligai/secops-helper/blob/main/README.md",
    },
)
