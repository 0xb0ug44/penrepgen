#!/usr/bin/env python3
"""Module execution entry point: python -m penrepgen."""

from __future__ import annotations

import sys
from penrepgen.cli import main

if __name__ == "__main__":
    sys.exit(main())
