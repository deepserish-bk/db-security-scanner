#!/usr/bin/env python3
"""
Universal runner for Database Security Scanner
"""
import sys
import os

# Always works from any location
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from src.cli.main_cli import main
    main()
except ImportError as e:
    print(f"Error: {e}")
    print("Make sure you're in the project root directory!")
    sys.exit(1)
