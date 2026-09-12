"""PyInstaller entry point.

gui/main.py uses relative imports (package-internal), so it can't be the
Analysis script itself - PyInstaller's bootloader runs that file as a
top-level script with no package context, which breaks `from .. import`.
This tiny wrapper imports the package properly instead.
"""

from ot_discovery.gui.main import main

if __name__ == "__main__":
    main()
