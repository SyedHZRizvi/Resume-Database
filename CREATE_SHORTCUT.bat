@echo off
::
:: Creates (or replaces) the "Resume Database" desktop shortcut.
:: Run this once — then use the shortcut on your desktop to open the app.
::
cd /d "%~dp0"

powershell -ExecutionPolicy Bypass -Command ^
  "$ws  = New-Object -ComObject WScript.Shell;" ^
  "$lnk = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Resume Database.lnk');" ^
  "$lnk.TargetPath     = '%~dp0START_APP.bat';" ^
  "$lnk.WorkingDirectory = '%~dp0';" ^
  "$lnk.Description    = 'TransCrypts Resume Database';" ^
  "$lnk.WindowStyle    = 7;" ^
  "$lnk.Save()"

echo.
echo  Shortcut created on your Desktop.
echo  Double-click "Resume Database" to open the app.
echo.
pause
