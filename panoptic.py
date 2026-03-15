#!/usr/bin/env python3
"""Compatibility shim — delegates to the panoptic package."""

from panoptic.__main__ import main

if __name__ == "__main__":
    main()
