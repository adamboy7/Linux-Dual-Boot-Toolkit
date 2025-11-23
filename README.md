# Bluetooth Dual-Boot Toolkit

This repository provides GUI helpers for exporting and importing Bluetooth pairing keys when dual-booting between Linux and Windows.

## Running the Windows GUI with Administrator rights

The Windows Bluetooth GUI must run with administrative privileges to read and write pairing keys in the registry.

1. Open the Start menu, search for **PowerShell** or **Command Prompt**.
2. Right-click the result and choose **Run as administrator**.
3. In the elevated terminal, navigate to the folder containing `Windows-Bluetooth-GUI.py`.
4. Run the script:
   ```powershell
   python .\Windows-Bluetooth-GUI.py
   ```
5. After importing keys, you may need to toggle Bluetooth or reboot Windows for the changes to take effect.

> Tip: If you installed Python from the Microsoft Store, use `python` as shown above; otherwise, use `py` if `python` is not on your PATH.
