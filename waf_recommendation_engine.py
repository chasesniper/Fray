#!/usr/bin/env python3
"""
WAF Recommendation Engine — backward-compatible wrapper.
Implementation: fray/recommender.py

Preferred usage:
    pip install fray
"""
import runpy, sys, os
sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fray", "recommender.py")
runpy.run_path(sys.argv[0], run_name="__main__")
