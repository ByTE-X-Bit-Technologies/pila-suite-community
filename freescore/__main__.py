"""Entry point: `python -m freescore` (and the packaged .exe) start the GUI."""
from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
