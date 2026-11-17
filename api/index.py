import sys
from pathlib import Path

# Vercel runs this file from api/, so the project root must be importable to load app.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app  # noqa: E402,F401
