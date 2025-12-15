#!/usr/bin/env python3
"""
Simple runner for Day 7 CLI
"""
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the CLI
from src.cli.main_cli import main

if __name__ == "__main__":
    main()
