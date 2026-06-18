# CLIP Studio Paint Auto Password Tool

A tool that automatically enters the CLIP Studio Paint password. It can replace the original CLIPStudioPaint.exe launcher.

## Features

- Automatically enters the password with no manual input
- Supports launching via shortcuts
- Supports custom program icons
- Detects whether CLIP Studio Paint is already running
- Saves the install path so you only need to configure it once

## Usage

1. Place `CSP_auto_Psw.exe` in the CLIP Studio Paint install directory
2. Create a desktop shortcut (optional)
3. Double-click to run the program

## Custom Icon

To change the program icon, name your image `icon.jpg` or `icon.png` and place it in the same directory as `auto_password.exe`.

## Notes

- On first use, if the program is not in the install directory, you will need to enter the CLIP Studio Paint install path manually
- It is recommended to place the program in the CLIP Studio Paint install directory so it can detect the location automatically
- If you run into problems, save the error output as `error.txt` and report it

## How It Works

1. On startup, the program checks whether it is in the CLIP Studio Paint install directory
2. If not, it tries to read the install path from the config file
3. If no config file exists, it prompts you to enter the install path
4. It launches CLIP Studio Paint
5. If a password window is detected, it enters the password automatically
6. If no password window is detected, CLIP Studio Paint is already running and the tool exits
