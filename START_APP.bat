@echo off
::
:: TransCrypts Resume Database
:: ===========================
:: Double-click this file OR use the desktop shortcut to open the app.
::
cd /d "%~dp0"

:: ── Check Python is installed ──────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    powershell -Command ^
      "Add-Type -AssemblyName PresentationCore,PresentationFramework; ^
       [System.Windows.MessageBox]::Show( ^
         'Python is not installed.`n`nInstall it from https://www.python.org/downloads/`nTick ''Add Python to PATH'' during setup.', ^
         'TransCrypts — Python Not Found','OK','Error')"
    exit /b 1
)

:: ── Find pythonw.exe — write path to a temp file to avoid quote issues ─────
python -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" > "%TEMP%\resumedb_pypath.txt" 2>nul
set /p PYTHONW=<"%TEMP%\resumedb_pypath.txt"
del "%TEMP%\resumedb_pypath.txt" 2>nul

:: ── Launch with no console window ─────────────────────────────────────────
if exist "%PYTHONW%" (
    start "" "%PYTHONW%" "%~dp0start_desktop.py"
) else (
    start /min "Resume Database" python "%~dp0start_desktop.py"
)
