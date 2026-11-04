"""PyInstaller entry point for PILA Suite Community. Runs the local GUI server."""
import os
import sys

# Allow running from source (frozen builds bundle freescore directly).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freescore.server import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
