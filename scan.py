#!/usr/bin/env python3
"""
Universal Security Scanner Runner
Always works from project root
"""
import sys
import os

# Set up path - always works from project root
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

print(f"🔧 Project root: {project_root}")

try:
    from src.cli.main_cli import main
    print("✅ CLI loaded successfully")
    main()
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please make sure:")
    print("1. You're in the project root directory")
    print("2. The src/ directory exists")
    print("3. You have all dependencies installed")
    sys.exit(1)
