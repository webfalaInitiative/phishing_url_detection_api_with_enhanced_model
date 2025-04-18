# setup.py
import os
import logging
from pathlib import Path

def setup_project():
    """Create necessary directories and download initial data"""
    # Create directory structure
    directories = ['data', 'models', 'logs']
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"Created directory: {dir_name}")

if __name__ == "__main__":
    setup_project()