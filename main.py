#!/usr/bin/env python3
"""
VulnBot - Automated Vulnerability Scanner
Main entry point for the application
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from vulnbot.cli import main

if __name__ == '__main__':
    main()
