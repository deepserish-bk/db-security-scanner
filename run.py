#!/usr/bin/env python3
"""
Simple runner script that fixes import paths automatically
"""
import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Now run the main module
from src.main import main

if __name__ == "__main__":
    main()
