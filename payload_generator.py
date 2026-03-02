#!/usr/bin/env python3
"""
Payload Generator — backward-compatible wrapper.
Implementation: fray/payload_generator.py

Preferred usage:
    pip install fray
    fray payloads
"""
import runpy, sys, os
sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fray", "payload_generator.py")
runpy.run_path(sys.argv[0], run_name="__main__")
