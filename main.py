#!/usr/bin/env python3
"""Entry point: python3 main.py [--log-dir DIR] <command>   (see --help)"""
import sys

from log_sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
