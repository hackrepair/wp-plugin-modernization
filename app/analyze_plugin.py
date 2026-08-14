#!/usr/bin/env python3
# Copyright (C) 2026 Jim Walker
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compatibility entrypoint for running the analyzer from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from wp_plugin_modernization.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
