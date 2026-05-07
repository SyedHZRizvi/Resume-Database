"""
TransCrypts Resume Database — Desktop App
==========================================
Started by launcher.py (called from START_APP.bat).
Opens the app as a clean desktop window with no browser address bar.

If something goes wrong a message box is shown AND details are written to:
  startup.log  (in the same folder as this file)
"""

import os
import sys
import time
import threading
import urllib.request
from datetime import datetime

# ── Working directory & log file ──────────────────────────────────────────────
HERE     = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(HERE, 'startup.log')
APP_URL  = 'http://127.0.0.1:5000'

os.chdir(HERE)


def _log(msg):
    """Append one timestamped line to startup.log."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {msg}\n")
    except Exception:
        pass


def _error(title, msg):
    """Show a Windows message box AND write to the log — works without a console."""
    _log(f'ERROR: {msg}')
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0x10)  # MB_ICONERROR
    except Exception:
        pass


# ─── Flask startup ─────────────────────────────────────────────────────────────

def _run_flask():
    try:
        _log('Importing app module…')
        from app import (app, init_db, create_default_admin,
                         _auto_reanalyze_on_startup, _backfill_file_hashes)
        _log('Running init_db…')
        init_db()
        _log('Running create_default_admin…')
        create_default_admin()
        threading.Thread(target=_auto_reanalyze_on_startup, daemon=True).start()
        threading.Thread(target=_backfill_file_hashes,       daemon=True).start()
        _log('Starting Flask on 127.0.0.1:5000…')
        app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
    except Exception as exc:
        _log(f'Flask startup failed: {exc}')


def _wait_for_server(timeout=25):
    _log(f'Waiting for server (up to {timeout}s)…')
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(APP_URL + '/', timeout=1)
            _log('Server is ready.')
            return True
        except Exception:
            time.sleep(0.2)
    _log('Server did not respond within timeout.')
    return False


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    _log('=== TransCrypts Desktop App starting ===')
    _log(f'Python: {sys.executable}')
    _log(f'Working dir: {HERE}')

    # 1. Start Flask
    _log('Launching Flask thread…')
    threading.Thread(target=_run_flask, daemon=True).start()

    # 2. Wait for Flask to be ready
    if not _wait_for_server(timeout=25):
        _error(
            'TransCrypts — Startup Failed',
            'The database server did not start within 25 seconds.\n\n'
            'Possible causes:\n'
            '  • A package is missing (try: pip install -r requirements.txt)\n'
            '  • Port 5000 is already in use by another program\n'
            '  • An error in app.py\n\n'
            f'Check the log file for details:\n{LOG_FILE}'
        )
        sys.exit(1)

    # 3. Open the app in the default browser (new window, not a background tab)
    _log('Opening app in default browser…')
    import webbrowser
    webbrowser.open_new(APP_URL)
    _log('Browser launched — keeping Flask alive until this process is killed.')

    # Keep the process alive so Flask keeps running
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        _error('TransCrypts — Unexpected Error',
               f'An unexpected error occurred:\n\n{exc}\n\n'
               f'Check the log file:\n{LOG_FILE}')
        _log(f'UNHANDLED EXCEPTION: {exc}')
        sys.exit(1)
