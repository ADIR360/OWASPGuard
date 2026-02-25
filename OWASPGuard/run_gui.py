#!/usr/bin/env python3
"""
Quick launcher for OWASPGuard GUI.
"""
try:
    from gui.modern_app import main
except ImportError:
    from gui.app import main

if __name__ == '__main__':
    main()

