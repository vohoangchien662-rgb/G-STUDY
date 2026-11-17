"""Compatibility launcher for local development. Vercel uses app.py directly."""
import os
from app import app, initialize_database

if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8090")), debug=False)
