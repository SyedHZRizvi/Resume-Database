"""
TransCrypts Resume Database — Launcher
=======================================
This tiny script is called by START_APP.bat.
It reliably finds pythonw.exe (no console window) and starts the desktop app.

Why this exists instead of putting everything in the .bat file:
  Python's sys.executable always gives the EXACT path to the running Python
  interpreter, so we can find pythonw.exe right next to it — no PATH lookup,
  no guessing, works in every environment including desktop shortcuts.
"""

import sys
import os
import subprocess

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE       = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.dirname(sys.executable)          # e.g. C:\Python314\
PYTHONW    = os.path.join(PYTHON_DIR, 'pythonw.exe')  # no-console Python
SCRIPT     = os.path.join(HERE, 'start_desktop.py')

# ── Sanity check ──────────────────────────────────────────────────────────────
if not os.path.isfile(SCRIPT):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            f'Could not find start_desktop.py in:\n{HERE}\n\n'
            'Please make sure all files are in D:\\TransCrypts\\ResumeDatabase\\',
            'TransCrypts — File Missing',
            0x10  # MB_ICONERROR
        )
    except Exception:
        pass
    sys.exit(1)

# ── Launch the desktop app ─────────────────────────────────────────────────────
if os.path.isfile(PYTHONW):
    # pythonw.exe = Python that never opens a console window — ideal
    subprocess.Popen([PYTHONW, SCRIPT])
else:
    # Fallback: regular python.exe but with the CREATE_NO_WINDOW flag
    # so Windows doesn't create a console for it
    CREATE_NO_WINDOW = 0x08000000
    subprocess.Popen([sys.executable, SCRIPT],
                     creationflags=CREATE_NO_WINDOW)

# This process exits immediately — the spawned pythonw process keeps running
