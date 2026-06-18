from pywinauto.application import Application
import time
import traceback
import os
import json
import psutil
import sys
from PIL import Image
import ctypes
import win32com.client
from win32com.client import pythoncom

def set_console_title(title):
    """Set the console window title."""
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except:
        pass

def get_shortcut_target(shortcut_path):
    """Get the actual path a shortcut points to."""
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        return shortcut.Targetpath
    except Exception as e:
        return None

def get_real_path():
    """Get the actual runtime path of the program."""
    try:
        if getattr(sys, 'frozen', False):
            # Running as a packaged exe
            exe_path = sys.executable
            
            # Check if launched via a shortcut
            if exe_path.lower().endswith('.lnk'):
                real_path = get_shortcut_target(exe_path)
                if real_path:
                    return os.path.dirname(real_path)
            
            return os.path.dirname(exe_path)
        else:
            # Running as a Python script
            return os.path.dirname(os.path.abspath(__file__))
    except Exception as e:
        return None

def load_config():
    try:
        base_path = get_real_path()
        if not base_path:
            return None
            
        config_path = os.path.join(base_path, "config.json")
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                return None
        return None
    except Exception as e:
        return None

def save_config(install_path, icon_path=None):
    try:
        base_path = get_real_path()
        if not base_path:
            return
            
        config = {
            "install_path": install_path,
            "icon_path": icon_path
        }
        config_path = os.path.join(base_path, "config.json")
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
    except Exception as e:
        pass

def find_clip_exe_in_dir(directory):
    """Search for a CLIP STUDIO PAINT folder in subdirectories of the given directory."""
    try:
        # Check immediate subdirectories
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path) and item.upper() == "CLIP STUDIO PAINT":
                # Check whether CLIPStudioPaint.exe exists in that folder
                exe_path = os.path.join(item_path, "CLIPStudioPaint.exe")
                if os.path.exists(exe_path):
                    return item_path
        return None
    except Exception as e:
        return None

def find_clip_exe():
    """Find the location of CLIPStudioPaint.exe."""
    try:
        base_path = get_real_path()
        if not base_path:
            return None
        
        # Check the current directory
        current_path = os.path.join(base_path, "CLIPStudioPaint.exe")
        if os.path.exists(current_path):
            return base_path
        
        # Check the path stored in the config file
        config = load_config()
        if config and "install_path" in config:
            config_path = config["install_path"]
            if os.path.exists(config_path):
                exe_path = os.path.join(config_path, "CLIPStudioPaint.exe")
                if os.path.exists(exe_path):
                    return config_path
        
        return None
    except Exception as e:
        return None

def convert_to_ico(image_path, output_path):
    """Convert an image to ICO format."""
    try:
        # Open the image
        img = Image.open(image_path)
        # Ensure the image is in RGBA mode
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        # Resize to 256x256
        img = img.resize((256, 256), Image.Resampling.LANCZOS)
        # Save as ICO
        img.save(output_path, format='ICO', sizes=[(256, 256)])
        return True
    except Exception as e:
        return False

def update_icon():
    """Update the program icon."""
    try:
        # Get the directory containing the current exe
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        
        # Load config
        config = load_config()
        if not config or "icon_path" not in config or not config["icon_path"]:
            return False
        
        icon_path = config["icon_path"]
        if not os.path.exists(icon_path):
            return False
        
        # Check file type
        if not icon_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            return False
        
        # Convert and save the icon
        output_path = os.path.join(base_path, "icon.ico")
        if convert_to_ico(icon_path, output_path):
            return True
        return False
    except Exception as e:
        return False

def auto_input_password():
    try:
        # Set console title
        set_console_title("CLIP Auto Password")
        
        print("--------------------------------")
        print("To change the program icon, name your image icon.jpg or icon.png")
        print("and place it in the same directory as auto_password.exe.")
        print("--------------------------------")
        
        # Check and update icon
        base_path = get_real_path()
        if not base_path:
            print("Error: Unable to get program path")
            print("\nPress any key to exit...")
            os.system("pause")
            return
            
        # Check for icon.jpg or icon.png
        icon_path = None
        for ext in ['.jpg', '.png']:
            temp_path = os.path.join(base_path, f"icon{ext}")
            if os.path.exists(temp_path):
                icon_path = temp_path
                break
                
        if icon_path:
            config = load_config() or {}
            config["icon_path"] = icon_path
            save_config(config.get("install_path", ""), icon_path)
            convert_to_ico(icon_path, os.path.join(base_path, "icon.ico"))
        
        # Update icon if needed
        update_icon()
        
        # Try to find CLIPStudioPaint.exe first
        install_path = find_clip_exe()
        
        if install_path:
            print(f"Detected CLIP Studio Paint at: {install_path}")
            exe_path = os.path.join(install_path, "CLIPStudioPaint.exe")
        else:
            config = load_config()
            install_path = None
            
            if config and "install_path" in config:
                # Validate the saved path
                saved_path = config["install_path"]
                if os.path.exists(saved_path):
                    exe_path = os.path.join(saved_path, "CLIPStudioPaint.exe")
                    if os.path.exists(exe_path):
                        install_path = saved_path
                        print(f"Detected saved install path: {install_path}")
                        print("Use this path? (Y/N)")
                        if input().strip().upper() == 'Y':
                            pass
                        else:
                            install_path = None
            
            if not install_path:
                print("Place this file in the CLIP Studio install directory to auto-detect and launch the exe.")
                print("You can place a shortcut on the desktop to replace CLIPStudioPaint.exe.")
                print("--------------------------------")
                print("On first use, if not in the install directory, enter the CLIP Studio Paint install path.")
                print("(Example: E:\\Clip\\CLIP STUDIO 1.5\\CLIP STUDIO PAINT)")
                print("Note: Do not include \\CLIPStudioPaint.exe at the end.")
                print("Tip: Copy the path from the folder address bar and paste it.")
                print("For feature requests, contact 2932183420@qq.com")
                print("--------------------------------")
                
                # First input attempt
                install_path = input("Enter path: ").strip()
                install_path = install_path.strip('"')
                
                # Check whether the path exists
                if not os.path.exists(install_path):
                    print(f"Error: Path does not exist - {install_path}")
                    print("Please re-enter the path")
                    # Second input attempt
                    install_path = input("Re-enter path: ").strip()
                    install_path = install_path.strip('"')
                    if not os.path.exists(install_path):
                        print(f"Error: Path does not exist - {install_path}")
                        print("\nPress any key to exit...")
                        os.system("pause")
                        return
                
                # Check for CLIPStudioPaint.exe in the given path
                exe_path = os.path.join(install_path, "CLIPStudioPaint.exe")
                if not os.path.exists(exe_path):
                    # Try to find a CLIP STUDIO PAINT folder in a subdirectory
                    print("Searching for CLIP STUDIO PAINT folder...")
                    found_path = find_clip_exe_in_dir(install_path)
                    if found_path:
                        install_path = found_path
                        print(f"Found CLIP Studio Paint: {install_path}")
                        exe_path = os.path.join(install_path, "CLIPStudioPaint.exe")
                    else:
                        print("CLIP STUDIO PAINT folder not found")
                        print("Please re-enter the path")
                        # Second input attempt
                        install_path = input("Re-enter path: ").strip()
                        install_path = install_path.strip('"')
                        if not os.path.exists(install_path):
                            print(f"Error: Path does not exist - {install_path}")
                            print("\nPress any key to exit...")
                            os.system("pause")
                            return
                        
                        # Check the path again
                        exe_path = os.path.join(install_path, "CLIPStudioPaint.exe")
                        if not os.path.exists(exe_path):
                            found_path = find_clip_exe_in_dir(install_path)
                            if found_path:
                                install_path = found_path
                                print(f"Found CLIP Studio Paint: {install_path}")
                                exe_path = os.path.join(install_path, "CLIPStudioPaint.exe")
                            else:
                                print("Error: CLIP Studio Paint not found")
                                print("\nPress any key to exit...")
                                os.system("pause")
                                return
                
                # Save config only when the path is valid
                save_config(install_path)
            
            if not os.path.exists(install_path):
                print(f"Error: Path does not exist - {install_path}")
                print("\nPress any key to exit...")
                os.system("pause")
                return
                
            exe_path = os.path.join(install_path, "CLIPStudioPaint.exe")
            if not os.path.exists(exe_path):
                print(f"Error: CLIPStudioPaint.exe not found - {exe_path}")
                print("\nPress any key to exit...")
                os.system("pause")
                return
        
        # Launch the program
        app = Application().start(exe_path)
        print("Program started")
        print(f"Launch path: {exe_path}")
        
        # Wait for the password window
        max_attempts = 20
        password_window = None
        print(f"Waiting for password window, up to {max_attempts} attempts...")
        for i in range(max_attempts):
            try:
                print(f"Attempt {i+1} to find password window...")
                print("Looking for window titled 'Application requires password to start'...")
                print("All current windows:")
                for window in app.windows():
                    print(f"Window title: {window.window_text()}, Class name: {window.class_name()}")
                
                password_window = app.window(title="Application requires password to start")
                if password_window.exists():
                    print("Password window found")
                    print(f"Window handle: {password_window.handle}")
                    print(f"Window class name: {password_window.class_name()}")
                    print(f"Window title: {password_window.window_text()}")
                    break
                else:
                    print("Password window not found")
            except Exception as e:
                print(f"Error while finding password window: {str(e)}")
                print("Detailed error:")
                print(traceback.format_exc())
            time.sleep(0.5)
            
        if not password_window:
            print("Could not find password window within the allowed attempts")
            print("Error: CLIP Studio Paint failed to start")
            print("\nPress any key to exit...")
            os.system("pause")
            return
        
        # Find the password input field
        print("Looking for password input field...")
        try:
            print("Trying to find input field with class_name='Edit'...")
            password_edit = password_window.child_window(class_name="Edit")
            if password_edit.exists():
                print("Password input field found")
                print(f"Input field handle: {password_edit.handle}")
                print(f"Input field class name: {password_edit.class_name()}")
            else:
                print("Password input field not found")
                print("Trying alternate methods to find input field...")
                print("All child controls in current window:")
                for child in password_window.children():
                    print(f"Control type: {child.class_name()}, Control ID: {child.control_id()}, Control text: {child.window_text()}")
                
                print("Trying to find input field with control_type='Edit'...")
                password_edit = password_window.child_window(control_type="Edit")
                if password_edit.exists():
                    print("Found password input field via control_type")
                    print(f"Input field handle: {password_edit.handle}")
                    print(f"Input field class name: {password_edit.class_name()}")
                else:
                    print("Still could not find password input field")
                    print("All child controls in current window:")
                    for child in password_window.children():
                        print(f"Control type: {child.class_name()}, Control ID: {child.control_id()}, Control text: {child.window_text()}")
        except Exception as e:
            print(f"Error while finding password input field: {str(e)}")
            print("Detailed error:")
            print(traceback.format_exc())
        
        # Enter the password
        try:
            print("Entering password...")
            print("Trying to set password text...")
            password_edit.set_text("lai2 zi4 bbs.itzmx.com mian3 fei4 fen1 xiang3 fa1 xian4 fan4 mai4 tui4 kuan3 ju3 bao4 cha4 ping2 bbs.itzmx.com Always Free")
            print("Password entered")
            
            # Simulate pressing Enter
            print("Simulating Enter key...")
            password_edit.type_keys('{ENTER}')
            print("Enter key pressed")
            
            # Verify the password was entered
            print("Verifying password was entered...")
            current_text = password_edit.window_text()
            print(f"Current input field text: {current_text}")
        except Exception as e:
            print(f"Error while entering password: {str(e)}")
            print("Detailed error:")
            print(traceback.format_exc())
            
        print("Password entered, waiting for program to start...")
        print("\nPress any key to exit...")
        os.system("pause")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        print("\nDetailed error:")
        print(traceback.format_exc())
        print("\nSave the error as error.txt and report to 2932183420@qq.com")
        print("Press any key to exit...")
        os.system("pause")

if __name__ == "__main__":
    auto_input_password()
