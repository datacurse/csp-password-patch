@echo off
chcp 65001
echo Installing dependencies...
E:\Develop\conda\envs\dsenv\python.exe -m pip install pyinstaller pywinauto psutil pillow pywin32

echo Cleaning old files...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "auto_password_simple.spec" del "auto_password_simple.spec"

echo Creating spec file...
E:\Develop\conda\envs\dsenv\python.exe -m PyInstaller --name=auto_password_simple --onefile --console --icon=icon.ico auto_password_simple.py

echo Modifying spec file...
(
echo # -*- mode: python ; coding: utf-8 -*-
echo.
echo block_cipher = None
echo.
echo a = Analysis(
echo     ['auto_password_simple.py'],
echo     pathex=[],
echo     binaries=[],
echo     datas=[],
echo     hiddenimports=['pywinauto', 'psutil', 'PIL', 'ctypes'],
echo     hookspath=[],
echo     hooksconfig={},
echo     runtime_hooks=[],
echo     excludes=[],
echo     win_no_prefer_redirects=False,
echo     win_private_assemblies=False,
echo     cipher=block_cipher,
echo     noarchive=False,
echo )
echo.
echo pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
echo.
echo exe = EXE(
echo     pyz,
echo     a.scripts,
echo     a.binaries,
echo     a.zipfiles,
echo     a.datas,
echo     [],
echo     name='auto_password_simple',
echo     debug=False,
echo     bootloader_ignore_signals=False,
echo     strip=False,
echo     upx=True,
echo     upx_exclude=[],
echo     runtime_tmpdir=None,
echo     console=True,
echo     disable_windowed_traceback=False,
echo     argv_emulation=False,
echo     target_arch=None,
echo     codesign_identity=None,
echo     entitlements_file=None,
echo     icon='icon.ico'
echo )
) > auto_password_simple.spec

echo Building executable...
E:\Develop\conda\envs\dsenv\python.exe -m PyInstaller --clean auto_password_simple.spec

echo Build complete!
echo Press any key to exit...
pause
