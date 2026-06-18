@echo off
chcp 65001
echo Installing dependencies...
E:\Develop\conda\envs\dsenv\python.exe -m pip install pyinstaller pywinauto psutil pillow pywin32

echo Cleaning old files...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist auto_password.spec del auto_password.spec

echo Building executable...
E:\Develop\conda\envs\dsenv\python.exe -m PyInstaller --name=auto_password --onefile --console --icon=icon.ico --hidden-import=pywinauto --hidden-import=psutil --hidden-import=PIL --hidden-import=ctypes --hidden-import=win32com.client --hidden-import=pythoncom auto_password.py

echo Build complete!
echo Press any key to exit...
pause