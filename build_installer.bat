@echo off
setlocal
cd /d "%~dp0"

echo Staging proxy payload for 5.0.0...
python tools\stage_version_payload.py --version 5.0.0 --rebuild
if errorlevel 1 exit /b 1

echo Staging proxy payload for 4.2.0...
python tools\stage_version_payload.py --version 4.2.0
if errorlevel 1 exit /b 1

echo Building csp-password-patch.exe...
python -m PyInstaller deitzmx-patch.spec
if errorlevel 1 exit /b 1

echo Done: dist\csp-password-patch.exe
endlocal
