"""Repository-wide pytest configuration for imports and property-test budgets."""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

from hypothesis import settings


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

settings.register_profile(
    "ci",
    max_examples=75,
    deadline=timedelta(milliseconds=500),
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
